package unattend

import (
	"strings"
	"testing"
)

func TestRender_BasicTemplating(t *testing.T) {
	xml, err := Render(Params{
		Hostname:      "win-test-01",
		AdminPassword: "P@ss<&>'\"word",
		Locale:        "en-US",
		TimeZone:      "Pacific Standard Time",
		AutoLogon:     true,
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(xml, "<ComputerName>win-test-01</ComputerName>") {
		t.Errorf("hostname not rendered")
	}
	if !strings.Contains(xml, "<TimeZone>Pacific Standard Time</TimeZone>") {
		t.Errorf("timezone not rendered")
	}
	oobe := xml[strings.Index(xml, `<settings pass="oobeSystem">`):]
	for _, want := range []string{
		"<InputLocale>en-US</InputLocale>",
		"<SkipMachineOOBE>true</SkipMachineOOBE>",
		"<SkipUserOOBE>true</SkipUserOOBE>",
	} {
		if !strings.Contains(oobe, want) {
			t.Errorf("oobeSystem missing %q", want)
		}
	}
	if got := strings.Count(xml, `settings pass="specialize"`); got != 1 {
		t.Fatalf("specialize pass count = %d, want 1", got)
	}
	specialize := xml[strings.Index(xml, `<settings pass="specialize">`):strings.Index(xml, `<settings pass="oobeSystem">`)]
	if got := strings.Count(specialize, `name="Microsoft-Windows-Shell-Setup"`); got != 1 {
		t.Fatalf("Shell-Setup component appears %d times in specialize; Windows rejects duplicates", got)
	}
	// XML-special chars in the password must be escaped.
	if strings.Contains(xml, "P@ss<&>") {
		t.Errorf("password XML special chars not escaped: %s", xml)
	}
	if !strings.Contains(xml, "&lt;") || !strings.Contains(xml, "&amp;") {
		t.Errorf("expected escaped entities in password value")
	}
	// AutoLogon must use a one-time count.
	if !strings.Contains(xml, "<LogonCount>1</LogonCount>") {
		t.Errorf("AutoLogon must set LogonCount=1")
	}
	// Scrub of Panther / AutoLogon registry must be baked in.
	for _, want := range []string{
		`del /f /q C:\Windows\Panther\unattend.xml`,
		`Panther\UnattendGC`,
		`AutoAdminLogon /f`,
		`DefaultPassword /f`,
	} {
		if !strings.Contains(xml, want) {
			t.Errorf("scrub command missing: %q", want)
		}
	}
}

func TestRender_PlainTextDefaultAndObfuscation(t *testing.T) {
	plain, _ := Render(Params{Hostname: "h", AdminPassword: "secret"})
	if !strings.Contains(plain, "<PlainText>true</PlainText>") {
		t.Errorf("default should be plaintext password")
	}
	if !strings.Contains(plain, "<Value>secret</Value>") {
		t.Errorf("plaintext password value expected")
	}

	obf, _ := Render(Params{Hostname: "h", AdminPassword: "secret", Obfuscate: true})
	if !strings.Contains(obf, "<PlainText>false</PlainText>") {
		t.Errorf("obfuscated should set PlainText=false")
	}
	if strings.Contains(obf, "<Value>secret</Value>") {
		t.Errorf("obfuscated value must not be cleartext")
	}
	adminEncoded := obfuscatePassword("secret", "AdministratorPassword")
	autoLogonEncoded := obfuscatePassword("secret", "Password")
	if !strings.Contains(obf, adminEncoded) || strings.Contains(obf, autoLogonEncoded) {
		// AutoLogon is disabled in this render, so only the administrator value
		// should be present.
		t.Errorf("unexpected obfuscated password values")
	}
	withAutoLogon, _ := Render(Params{Hostname: "h", AdminPassword: "secret", Obfuscate: true, AutoLogon: true})
	if !strings.Contains(withAutoLogon, adminEncoded) || !strings.Contains(withAutoLogon, autoLogonEncoded) {
		t.Errorf("AutoLogon must use the Windows 'Password' suffix while AdministratorPassword uses its own suffix")
	}
	if !strings.Contains(withAutoLogon, "<Domain>.</Domain>") {
		t.Errorf("AutoLogon for the local Administrator must specify the local-account domain")
	}
}

func TestRender_FirstBootScriptToggle(t *testing.T) {
	with, _ := Render(Params{Hostname: "h", AdminPassword: "x", FirstBootScript: "Write-Host hi"})
	if !strings.Contains(with, `C:\Windows\Setup\Scripts\FirstBoot.ps1`) {
		t.Errorf("first-boot command should reference FirstBoot.ps1")
	}
	without, _ := Render(Params{Hostname: "h", AdminPassword: "x"})
	if strings.Contains(without, "LabLink first-boot script") {
		t.Errorf("first-boot command should be absent when no script")
	}

	if _, err := Render(Params{AdminPassword: "x"}); err == nil {
		t.Errorf("expected error when hostname empty")
	}
}

func TestBuildMountInjectScript_MethodA(t *testing.T) {
	s, err := BuildMountInjectScript(MountInjectParams{
		VHDPath:        `D:\VMs\win01.vhdx`,
		BaseVHD:        `D:\base\golden.vhdx`,
		UnattendRemote: `C:\Windows\Temp\u.xml`,
	})
	if err != nil {
		t.Fatalf("BuildMountInjectScript: %v", err)
	}

	for _, want := range []string{
		"New-VHD -Path $vhdPath -ParentPath $baseVhd -Differencing", // never inject into base
		`Windows\System32\Config\SYSTEM`,                            // content-based volume detection
		"$mountedByUs",                                              // only dismount what we mounted
		"Mount-VHD -Path $vhdPath -PassThru",                        // valid Hyper-V parameter spelling
		"Add-PartitionAccessPath -AssignDriveLetter",                // temp letter assignment
		"Remove-Item $unattendSrc -Force",                           // scrub staged cleartext copy
		"finally {",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Method A script missing %q", want)
		}
		if strings.Contains(s, "-Passthrough") {
			t.Error("Method A script contains invalid Mount-VHD -Passthrough parameter")
		}
	}

	if _, err := BuildMountInjectScript(MountInjectParams{UnattendRemote: "x"}); err == nil {
		t.Errorf("expected error when vhd_path empty")
	}
}

func TestBuildMountInjectScript_EnrollmentPayload(t *testing.T) {
	s, err := BuildMountInjectScript(MountInjectParams{
		VHDPath:        `D:\VMs\win01.vhdx`,
		UnattendRemote: `C:\Windows\Temp\u.xml`,
		PayloadRemote:  `C:\Windows\Temp\lablink-enroll`,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`Windows\Setup\Scripts\LabLinkPayload`,
		`Copy-Item (Join-Path $payloadSrc '*') $payloadDst -Recurse -Force`,
		`Remove-Item $payloadSrc -Recurse -Force`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("enrollment script missing %q", want)
		}
	}
}

func TestBuildIsoInjectScript_Deferred(t *testing.T) {
	if _, err := BuildIsoInjectScript(MountInjectParams{}); err == nil ||
		!strings.Contains(err.Error(), "METHOD_B_DEFERRED") {
		t.Errorf("Method B must report deferred, got %v", err)
	}
}
