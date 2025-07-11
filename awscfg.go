// Package awsconfigfile contains logic to template ~/.aws/config files
// based on Common Fate access rules.
package awsconfigfile

import (
	"bytes"
	"sort"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/ini.v1"
)

type SSOProfile interface {
	ToIni(profileName string, nocredentialProcessProfile bool) any
}

type SSOSession struct {
	SSOSessionName			    string
	SSOStartURL             string
	SSORegistrationScopes   string
	SSORegion               string
	GeneratedFrom string
}

type ssoSession struct {
	SSOStartURL             string `ini:"sso_start_url"`
	SSORegistrationScopes   string `ini:"sso_registration_scopes"`
	SSORegion               string `ini:"sso_region"`
	CommonFateGeneratedFrom string `ini:"common_fate_generated_from,omitempty"`
}

func (s *SSOSession) ToIni(profileName string, nocredentialProcessProfile bool) any {
	return &ssoSession{
		SSOStartURL:           s.SSOStartURL,
		SSORegistrationScopes: s.SSORegistrationScopes,
		SSORegion:             s.SSORegion,
		CommonFateGeneratedFrom: s.GeneratedFrom,
	}
}

type AccountProfile struct {
	AccountName    string
	SSOSessionName     string
	AccountID   string
	RoleName       string
	GeneratedFrom  string
	Region         string
	CommonFateURL  string
	// Legacy format used for credential process
	SSOStartURL string
	SSORegion   string
}

type credentialProcessProfile struct {
	SSOStartURL             string `ini:"granted_sso_start_url"`
	SSORegion               string `ini:"granted_sso_region,omitempty"`
	AccountID            string `ini:"granted_sso_account_id"`
	RoleName                string `ini:"granted_sso_role_name"`
	CommonFateGeneratedFrom string `ini:"common_fate_generated_from"`
	CredentialProcess       string `ini:"credential_process"`
	Region                  string `ini:"region,omitempty"`
}

type regularProfile struct {
	SSOSession              string `ini:"sso_session"`
	AccountID            string `ini:"sso_account_id"`
	CommonFateGeneratedFrom string `ini:"common_fate_generated_from"`
	RoleName                string `ini:"sso_role_name"`
	Region                  string `ini:"region,omitempty"`
}

func (a *AccountProfile) ToIni(profileName string, noCredentialProcess bool) any {
	if noCredentialProcess {
		return &regularProfile{
				SSOSession:              a.SSOSessionName,
				AccountID:            a.AccountID,
				RoleName:                a.RoleName,
				CommonFateGeneratedFrom: a.GeneratedFrom,
				Region:                  a.Region,
		}
	}
	credProcess := "granted credential-process --profile " + profileName
	if a.CommonFateURL != "" {
		credProcess += " --url " + a.CommonFateURL
	}
	
	return &credentialProcessProfile{
		SSOStartURL:             a.SSOStartURL,
		SSORegion:               a.SSORegion,
		AccountID:            a.AccountID,
		RoleName:                a.RoleName,
		CredentialProcess:       credProcess,
		CommonFateGeneratedFrom: a.GeneratedFrom,
		Region:                  a.Region,
	}
}

type MergeOpts struct {
	Config              *ini.File
	Prefix              string
	Profiles            []SSOProfile
	SectionNameTemplate string
	NoCredentialProcess bool
	// PruneStartURLs is a slice of AWS SSO start URLs which profiles are being generated for.
	// Existing profiles with these start URLs will be removed if they aren't found in the Profiles field.
	PruneStartURLs []string
}

func Merge(opts MergeOpts) error {
	if opts.SectionNameTemplate == "" {
		opts.SectionNameTemplate = "{{ .AccountName }}/{{ .RoleName }}"
	}
	
	// Separate SSOSession and AccountProfile types
	var ssoSessions []SSOSession
	var accountProfiles []*AccountProfile
	
	for _, profile := range opts.Profiles {
		switch p := profile.(type) {
		case *SSOSession:
			ssoSessions = append(ssoSessions, *p) // Store a copy of the session
		case *AccountProfile:
			accountProfiles = append(accountProfiles, p)
		default:
			return nil // Unsupported profile type, skip
		}
	}
		

	// Sort profiles by CombinedName (AccountName/RoleName)
	sort.SliceStable(accountProfiles, func(i, j int) bool {
		combinedNameI := accountProfiles[i].AccountName + "/" + accountProfiles[i].RoleName
		combinedNameJ := accountProfiles[j].AccountName + "/" + accountProfiles[j].RoleName
		return combinedNameI < combinedNameJ
	})

	funcMap := sprig.TxtFuncMap()
	sectionNameTempl, err := template.New("").Funcs(funcMap).Parse(opts.SectionNameTemplate)
	if err != nil {
		return err
	}

	// remove any config sections that have 'common_fate_generated_from' as a key
	for _, sec := range opts.Config.Sections() {
		var startURL string

		if sec.HasKey("granted_sso_start_url") {
			startURL = sec.Key("granted_sso_start_url").String()
		} else if sec.HasKey("sso_start_url") {
			startURL = sec.Key("sso_start_url").String()
		}

		for _, pruneURL := range opts.PruneStartURLs {
			isGenerated := sec.HasKey("common_fate_generated_from") // true if the profile was created automatically.

			if isGenerated && startURL == pruneURL {
				opts.Config.DeleteSection(sec.Name())
			}
		}
	}
	
	for _, ssoSession := range ssoSessions {
		ssoSession.SSOSessionName = normalizeAccountName(ssoSession.SSOSessionName)

		sectionName := "sso-session " + ssoSession.SSOSessionName
		
		opts.Config.DeleteSection(sectionName)
		section, err := opts.Config.NewSection(sectionName)
		if err != nil {
			return err
		}
		entry := ssoSession.ToIni(ssoSession.SSOSessionName, opts.NoCredentialProcess)
		err = section.ReflectFrom(entry)
		if err != nil {
			return err
		}
	}

	for _, accountProfile := range accountProfiles {
		accountProfile.AccountName = normalizeAccountName(accountProfile.AccountName)
		sectionNameBuffer := bytes.NewBufferString("")
		err := sectionNameTempl.Execute(sectionNameBuffer, accountProfile)
		if err != nil {
			return err
		}
		profileName := opts.Prefix + sectionNameBuffer.String()
		sectionName := "profile " + profileName

		opts.Config.DeleteSection(sectionName)
		section, err := opts.Config.NewSection(sectionName)
		if err != nil {
			return err
		}

		entry := accountProfile.ToIni(profileName, opts.NoCredentialProcess)
		err = section.ReflectFrom(entry)
		if err != nil {
			return err
		}

	}

	return nil
}


func normalizeAccountName(accountName string) string {
	return strings.ReplaceAll(accountName, " ", "-")
}
