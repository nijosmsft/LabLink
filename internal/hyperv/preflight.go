package hyperv

// PreflightScript returns the shared Test-LabLinkHyperV preamble that every
// mutating Hyper-V tool runs first. It verifies the Hyper-V PowerShell module
// is present and the caller is elevated, emitting a tagged error otherwise.
//
// Enabling the Hyper-V role itself (Enable-WindowsOptionalFeature) requires a
// reboot and is out of scope for Phase 1 — we only detect-and-report.
func PreflightScript() string {
	return "" +
		"if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {\n" +
		"    throw 'HYPERV_NOT_AVAILABLE: Hyper-V PowerShell module/role not installed (Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All, then reboot)'\n" +
		"}\n" +
		"$__admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)\n" +
		"if (-not $__admin) { throw 'NOT_ELEVATED: Hyper-V operations require Administrator (the agent service usually runs as LocalSystem)' }\n"
}
