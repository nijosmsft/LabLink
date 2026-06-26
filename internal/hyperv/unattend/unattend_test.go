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
		"Add-PartitionAccessPath -AssignDriveLetter",                // temp letter assignment
		"Remove-Item $unattendSrc -Force",                           // scrub staged cleartext copy
		"finally {",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("Method A script missing %q", want)
		}
	}

	if _, err := BuildMountInjectScript(MountInjectParams{UnattendRemote: "x"}); err == nil {
		t.Errorf("expected error when vhd_path empty")
	}
}

func TestBuildIsoInjectScript_Deferred(t *testing.T) {
	if _, err := BuildIsoInjectScript(MountInjectParams{}); err == nil ||
		!strings.Contains(err.Error(), "METHOD_B_DEFERRED") {
		t.Errorf("Method B must report deferred, got %v", err)
	}
}
