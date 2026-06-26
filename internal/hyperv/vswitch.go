package hyperv

import (
	"encoding/json"
	"fmt"
	"strings"
)

// VSwitch is a parsed Hyper-V virtual switch row.
type VSwitch struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	NetAdapter        string `json:"net_adapter"`
	AllowManagementOS bool   `json:"allow_management_os"`
}

// BuildListVSwitchesScript builds the discovery script for vSwitches.
func BuildListVSwitchesScript() string {
	body := `
$rows = foreach ($sw in @(Get-VMSwitch -ErrorAction SilentlyContinue)) {
    [pscustomobject]@{
        name                = $sw.Name
        type                = "$($sw.SwitchType)"
        net_adapter         = $sw.NetAdapterInterfaceDescription
        allow_management_os = [bool]$sw.AllowManagementOS
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 4
`
	return wrapTagged(body)
}

// ParseVSwitches parses the JSON emitted by BuildListVSwitchesScript.
func ParseVSwitches(jsonText string) ([]VSwitch, error) {
	jsonText = strings.TrimSpace(extractJSON(jsonText))
	if jsonText == "" {
		return nil, nil
	}
	if strings.HasPrefix(jsonText, "{") {
		var one VSwitch
		if err := json.Unmarshal([]byte(jsonText), &one); err != nil {
			return nil, err
		}
		return []VSwitch{one}, nil
	}
	var out []VSwitch
	if err := json.Unmarshal([]byte(jsonText), &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateVSwitchParams configures BuildCreateVSwitchScript.
type CreateVSwitchParams struct {
	Name              string
	Type              string // "external" | "internal" | "private"
	NetAdapter        string // required when Type == external
	AllowManagementOS bool   // default true (caller sets)
	IfExists          string // "reuse" (default) | "fail" | "replace"

	// IsRemote is true when the target is a registered node (not localhost).
	// On a remote target an external switch on the management NIC is BLOCKED
	// unless AllowMgmtDisruption is true (network reviewer finding #1).
	IsRemote bool
	// AllowMgmtDisruption overrides the management-NIC safeguard.
	AllowMgmtDisruption bool
	// MgmtIP is the target-side IP the server uses to reach this host; used to
	// identify the management NIC at runtime on the target.
	MgmtIP string
}

// BuildCreateVSwitchScript builds the create_vswitch mutation script with the
// management-NIC severance safeguard baked in. Returns an error for invalid
// param combinations that can be detected statically.
func BuildCreateVSwitchScript(p CreateVSwitchParams) (string, error) {
	swType := strings.ToLower(strings.TrimSpace(p.Type))
	switch swType {
	case "external", "internal", "private":
	default:
		return "", fmt.Errorf("invalid vswitch type %q (expected external|internal|private)", p.Type)
	}
	if swType == "external" && strings.TrimSpace(p.NetAdapter) == "" {
		return "", fmt.Errorf("net_adapter is required when type=external")
	}
	ifExists := strings.ToLower(strings.TrimSpace(p.IfExists))
	if ifExists == "" {
		ifExists = "reuse"
	}
	switch ifExists {
	case "reuse", "fail", "replace":
	default:
		return "", fmt.Errorf("invalid if_exists %q (expected reuse|fail|replace)", p.IfExists)
	}
	// Static safeguard: on a remote target, AllowManagementOS=false on an
	// external switch can cut host connectivity even on a non-mgmt NIC; require
	// the explicit override.
	if swType == "external" && p.IsRemote && !p.AllowManagementOS && !p.AllowMgmtDisruption {
		return "", fmt.Errorf("MGMT_OS_BLOCKED: allow_management_os=false on a remote external switch can sever connectivity; set allow_management_nic_disruption=true to override")
	}

	var b strings.Builder
	b.WriteString(PreflightScript())
	fmt.Fprintf(&b, "$name = %s\n", PSLit(p.Name))
	fmt.Fprintf(&b, "$swType = %s\n", PSLit(swType))
	fmt.Fprintf(&b, "$netAdapter = %s\n", PSLit(p.NetAdapter))
	fmt.Fprintf(&b, "$allowMgmtOS = %s\n", PSBool(p.AllowManagementOS))
	fmt.Fprintf(&b, "$ifExists = %s\n", PSLit(ifExists))
	fmt.Fprintf(&b, "$isRemote = %s\n", PSBool(p.IsRemote))
	fmt.Fprintf(&b, "$allowMgmtDisruption = %s\n", PSBool(p.AllowMgmtDisruption))
	fmt.Fprintf(&b, "$mgmtIP = %s\n", PSLit(strings.TrimSpace(p.MgmtIP)))

	b.WriteString(`
if ($swType -eq 'external') {
    $adapter = Get-NetAdapter -Name $netAdapter -ErrorAction SilentlyContinue
    if (-not $adapter) { throw "NIC_NOT_FOUND: physical NIC '$netAdapter' not found" }

    # Management-NIC severance safeguard: block binding the NIC that carries the
    # agent/host connectivity on a REMOTE target unless explicitly overridden.
    $mgmtIfIndex = $null
    if ($mgmtIP) {
        $ipcfg = Get-NetIPAddress -IPAddress $mgmtIP -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ipcfg) { $mgmtIfIndex = $ipcfg.InterfaceIndex }
    }
    if ($null -eq $mgmtIfIndex) {
        $defRoute = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
            Sort-Object RouteMetric | Select-Object -First 1
        if ($defRoute) { $mgmtIfIndex = $defRoute.InterfaceIndex }
    }
    if ($isRemote -and $null -ne $mgmtIfIndex -and $adapter.ifIndex -eq $mgmtIfIndex -and -not $allowMgmtDisruption) {
        throw "MGMT_NIC_BLOCKED: NIC '$netAdapter' carries the LabLink agent/host connectivity on this remote target. Binding an external vSwitch to it can sever the connection. Re-run with allow_management_nic_disruption=true (prefer an async/detached job + reconnect) to proceed."
    }
}

$existing = Get-VMSwitch -Name $name -ErrorAction SilentlyContinue
$action = 'created'
if ($existing) {
    if ($ifExists -eq 'fail') { throw "VSWITCH_EXISTS: vSwitch '$name' already exists" }
    if ($ifExists -eq 'reuse') {
        # Validate the existing switch matches the requested shape before reusing.
        $existType = "$($existing.SwitchType)"
        if ($existType.ToLower() -ne $swType) {
            throw "VSWITCH_MISMATCH: existing vSwitch '$name' is $existType, requested $swType"
        }
        if ($swType -eq 'external') {
            $reqDesc = (Get-NetAdapter -Name $netAdapter).InterfaceDescription
            if ($existing.NetAdapterInterfaceDescription -ne $reqDesc) {
                throw "VSWITCH_MISMATCH: existing vSwitch '$name' bound to '$($existing.NetAdapterInterfaceDescription)', requested '$reqDesc'"
            }
            if ([bool]$existing.AllowManagementOS -ne $allowMgmtOS) {
                throw "VSWITCH_MISMATCH: existing vSwitch '$name' AllowManagementOS=$($existing.AllowManagementOS), requested $allowMgmtOS"
            }
        }
        $action = 'reused'
    }
    if ($ifExists -eq 'replace') {
        Remove-VMSwitch -Name $name -Force
        $existing = $null
        $action = 'replaced'
    }
}

if (-not $existing) {
    if ($swType -eq 'external') {
        New-VMSwitch -Name $name -NetAdapterName $netAdapter -AllowManagementOS:$allowMgmtOS | Out-Null
    } elseif ($swType -eq 'internal') {
        New-VMSwitch -Name $name -SwitchType Internal | Out-Null
    } else {
        New-VMSwitch -Name $name -SwitchType Private | Out-Null
    }
}

$sw = Get-VMSwitch -Name $name
[pscustomobject]@{
    name                = $sw.Name
    type                = "$($sw.SwitchType)"
    net_adapter         = $sw.NetAdapterInterfaceDescription
    allow_management_os = [bool]$sw.AllowManagementOS
    action              = $action
} | ConvertTo-Json -Depth 4
`)
	return wrapTagged(b.String()), nil
}
