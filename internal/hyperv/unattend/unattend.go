// Package unattend renders Windows answer files (unattend.xml /
// Autounattend.xml) and builds the PowerShell injection scripts. It has no MCP
// or gRPC dependencies so rendering and script construction are unit-testable.
//
// Security note: the rendered answer file necessarily contains the admin
// password (Windows requirement). Obfuscation (base64 of the password +
// "AdministratorPassword") is NOT encryption — it only avoids trivially
// grep-able plaintext. Callers must redact the password in ops/audit/results
// and rely on the baked-in first-boot scrub (Panther/UnattendGC/Winlogon) plus
// AutoLogonCount=1 to limit residual on-disk exposure.
package unattend

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"
	"text/template"
	"unicode/utf16"
)

//go:embed autounattend.xml.tmpl
var answerTemplate string

var tmpl = template.Must(template.New("unattend").Parse(answerTemplate))

// Params are the typed inputs to Render. The admin password is supplied at
// call time (ideally from the credentials store) and never persisted in the
// template file.
type Params struct {
	Hostname        string
	AdminPassword   string
	Locale          string // default en-US
	TimeZone        string
	ProductKey      string
	FirstBootScript string // inline PowerShell run once at first logon
	AutoLogon       bool
	Architecture    string // amd64 (default) | x86 | arm64
	Obfuscate       bool   // base64-obfuscate the password (NOT encryption)
}

// templateData is the escaped/derived view handed to the template.
type templateData struct {
	Hostname               string
	Locale                 string
	TimeZone               string
	ProductKey             string
	Architecture           string
	AutoLogon              bool
	HasFirstBootScript     bool
	AdminPasswordValue     string
	AdminPasswordPlainText string
}

// Render produces the answer-file XML for p. All caller-supplied values are
// XML-escaped; the password is either emitted as escaped plaintext or as the
// Windows base64 obfuscation when p.Obfuscate is set.
func Render(p Params) (string, error) {
	if strings.TrimSpace(p.Hostname) == "" {
		return "", fmt.Errorf("hostname is required")
	}
	arch := strings.TrimSpace(p.Architecture)
	if arch == "" {
		arch = "amd64"
	}
	locale := strings.TrimSpace(p.Locale)
	if locale == "" {
		locale = "en-US"
	}

	data := templateData{
		Hostname:           xmlEscape(p.Hostname),
		Locale:             xmlEscape(locale),
		TimeZone:           xmlEscape(strings.TrimSpace(p.TimeZone)),
		ProductKey:         xmlEscape(strings.TrimSpace(p.ProductKey)),
		Architecture:       xmlEscape(arch),
		AutoLogon:          p.AutoLogon,
		HasFirstBootScript: strings.TrimSpace(p.FirstBootScript) != "",
	}
	if p.Obfuscate {
		data.AdminPasswordValue = xmlEscape(obfuscatePassword(p.AdminPassword, "AdministratorPassword"))
		data.AdminPasswordPlainText = "false"
	} else {
		data.AdminPasswordValue = xmlEscape(p.AdminPassword)
		data.AdminPasswordPlainText = "true"
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// obfuscatePassword implements Windows' answer-file password obfuscation:
// base64(UTF-16LE(password + magic)). Magic is "AdministratorPassword" for the
// account password and "Password" for AutoLogon; we use the account form for
// both fields, which Windows accepts when PlainText=false.
func obfuscatePassword(password, magic string) string {
	combined := password + magic
	u := utf16.Encode([]rune(combined))
	buf := make([]byte, 0, len(u)*2)
	for _, c := range u {
		buf = append(buf, byte(c), byte(c>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// xmlEscape escapes the five XML special characters for use in element text.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
