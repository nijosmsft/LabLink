package unattend

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWindowsVolumeContentCheckRemainsInsidePartitionLoop(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("validates Windows PowerShell AST")
	}
	script, err := BuildMountInjectScript(MountInjectParams{
		VHDPath: `E:\VM\child.vhdx`, UnattendRemote: `C:\Temp\unattend.xml`,
	})
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "inject.ps1")
	checker := filepath.Join(root, "check.ps1")
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	check := `param([string]$ScriptPath)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors | Out-String)}
$checks=@($ast.FindAll({param($n)
 $n -is [Management.Automation.Language.IfStatementAst] -and
 $n.Clauses[0].Item1.Extent.Text -like '*Test-Path*Windows\System32\Config\SYSTEM*'
},$true))
if($checks.Count -ne 1){throw 'Windows-volume content check is missing or ambiguous'}
$parent=$checks[0].Parent
while($parent -and -not ($parent -is [Management.Automation.Language.ForEachStatementAst])){$parent=$parent.Parent}
if(-not $parent -or $parent.Variable.VariablePath.UserPath -ne 'part'){
 throw 'Windows-volume content check escaped its partition loop'
}
`
	if err := os.WriteFile(checker, []byte(check), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
		"-File", checker, "-ScriptPath", path).CombinedOutput()
	if err != nil {
		t.Fatalf("Windows injection control flow is invalid: %v\n%s", err, out)
	}
}
