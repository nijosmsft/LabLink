package hyperv

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nijosmsft/lablink/internal/linuximage"
)

func TestPublishedRestrictedImageRemovesInheritedVMWriteAccess(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "parent.vhdx")
	hash := strings.Repeat("a", 64)
	key, err := linuximage.CacheKey(hash, 64)
	if err != nil {
		t.Fatal(err)
	}
	script, err := BuildLinuxImagePublishScript(LinuxImagePublishParams{
		StagedVHDX: path, FinalVHDX: path, MetadataPath: filepath.Join(root, "metadata.json"),
		StatePath: filepath.Join(root, "state.json"),
		Metadata: linuximage.ImageMetadata{
			SchemaVersion: linuximage.TransformSchema, CacheKey: key, Source: linuximage.FixedSource(),
			ImageSHA256: hash, PreparedSHA256: strings.Repeat("b", 64), DiskSizeGB: 64,
			PreparedVHDX: path, BuilderProfile: "builder", BuilderProfileFingerprint: strings.Repeat("c", 64),
			Verification: linuximage.VerificationState{Status: linuximage.VerificationVerified, Signer: linuximage.UbuntuSigningKeyFingerprint},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(script, "if ($env:LABLINK_HYPERV_RESTRICTED -eq '1') {")
	end := strings.Index(script, "Set-ItemProperty -LiteralPath $finalVHDX")
	if start < 0 || end < start {
		t.Fatal("publication ACL block missing")
	}
	probe := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$env:LABLINK_HYPERV_RESTRICTED='1'
$root=%s;$finalVHDX=%s
& icacls.exe $root /grant:r '*S-1-5-83-0:(OI)(CI)F' | Out-Null
if($LASTEXITCODE -ne 0){throw 'fixture ACL failed'}
New-Item -ItemType File -Path $finalVHDX | Out-Null
%s
$readers=0
foreach($rule in (Get-Acl -LiteralPath $finalVHDX).GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
    if($rule.IdentityReference.Value.StartsWith('S-1-5-83-') -or $rule.IdentityReference.Value -eq $workerSID){
        if($rule.FileSystemRights -band ([Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership)){throw 'VM writer survived publication'}
        $readers++
    }
}
if($readers -ne 2){throw 'VM image readers missing'}
'publication ACL safe'
`, PSLit(root), PSLit(path), script[start:end])
	command := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", probe)
	command.Env = append(os.Environ(), "PSModulePath="+filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "Modules"))
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "publication ACL safe") {
		t.Fatalf("publication ACL: %v\n%s", err, output)
	}
}

func TestWSLDiskDiscoveryWaitsWithoutWeakeningIdentityChecks(t *testing.T) {
	script, err := BuildLinuxImageBuilderTransformScript(LinuxImageBuilderTransformParams{
		StatePath: `C:\builder.json`, ExpectedSizeBytes: 65 << 30, ExpectedTargetLocation: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(script, "    for ($discoveryAttempt=0;")
	end := strings.Index(script, "    $wslDisk = $newWSLDisks[0]")
	if start < 0 || end < start {
		t.Fatal("WSL disk discovery block missing")
	}
	for _, test := range []struct{ mode, want string }{
		{"delayed", "selected:/dev/sdb:probes=3"},
		{"absent", "found 0:probes=30"},
		{"ambiguous", "found 2:probes=1"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			probe := fmt.Sprintf(`
$ErrorActionPreference='Stop'
$mode='%s';$script:probes=0
$beforeDiskPaths=@{'/dev/sda'=$true}
function Start-Sleep {param($Seconds)}
function wsl.exe {
    $script:probes++;$global:LASTEXITCODE=0
    if($mode -eq 'absent' -or ($mode -eq 'delayed' -and $script:probes -lt 3)) {
        '{"blockdevices":[{"type":"disk","path":"/dev/sda"}]}'
    } elseif($mode -eq 'ambiguous') {
        '{"blockdevices":[{"type":"disk","path":"/dev/sdb"},{"type":"disk","path":"/dev/sdc"}]}'
    } else {
        '{"blockdevices":[{"type":"disk","path":"/dev/sda"},{"type":"disk","path":"/dev/sdb"}]}'
    }
}
try {
%s
    'selected:'+$newWSLDisks[0].path+':probes='+$script:probes
} catch { $_.Exception.Message+':probes='+$script:probes }
`, test.mode, script[start:end])
			output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", probe).CombinedOutput()
			if err != nil || !strings.Contains(string(output), test.want) {
				t.Fatalf("disk discovery: %v\n%s", err, output)
			}
		})
	}
}
