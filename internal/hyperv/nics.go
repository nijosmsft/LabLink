package hyperv

import (
	"encoding/json"
	"fmt"
	"strings"
)

// NIC is a parsed physical network adapter row from list_physical_nics.
type NIC struct {
	Name                 string `json:"name"`
	InterfaceDescription string `json:"interface_description"`
	MAC                  string `json:"mac"`
	Status               string `json:"status"`
	LinkSpeed            string `json:"link_speed"`
	BoundVSwitch         string `json:"bound_vswitch"`
	IsManagementNIC      bool   `json:"is_management_nic"`
	ManagementRisk       bool   `json:"management_risk"`
	RecommendedExternal  bool   `json:"recommended_for_external"`
}

// BuildListNicsScript builds the discovery script for physical NICs.
//
// mgmtIP is the target-side IP address that the LabLink server uses to reach
// this host (the host part of the registry node Address). The NIC that owns
// that IP — or, failing an exact match, the NIC carrying the active default
// route — is flagged is_management_nic / management_risk so callers and the
// create_vswitch safeguard can avoid severing the agent connection. For a
// localhost target mgmtIP is empty and only the default-route NIC is flagged
// (lower risk: you own your own host).
func BuildListNicsScript(includeVirtual bool, mgmtIP string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "$mgmtIP = %s\n", PSLit(strings.TrimSpace(mgmtIP)))
	fmt.Fprintf(&b, "$includeVirtual = %s\n", PSBool(includeVirtual))
	b.WriteString(`
# Resolve the management interface index: prefer the NIC that owns $mgmtIP,
# else fall back to the NIC carrying the default route (lowest RouteMetric).
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

$adapters = if ($includeVirtual) { Get-NetAdapter } else { Get-NetAdapter -Physical }
$vmswitches = @(Get-VMSwitch -ErrorAction SilentlyContinue)

$rows = foreach ($a in $adapters) {
    $bound = $null
    foreach ($sw in $vmswitches) {
        if ($sw.SwitchType -eq 'External' -and $sw.NetAdapterInterfaceDescription -eq $a.InterfaceDescription) {
            $bound = $sw.Name; break
        }
    }
    $isMgmt = ($null -ne $mgmtIfIndex -and $a.ifIndex -eq $mgmtIfIndex)
    # Recommended for an external switch only if Up, not already bound, and not
    # the management NIC (binding it could sever connectivity).
    $rec = ($a.Status -eq 'Up' -and -not $bound -and -not $isMgmt)
    [pscustomobject]@{
        name                     = $a.Name
        interface_description    = $a.InterfaceDescription
        mac                      = $a.MacAddress
        status                   = "$($a.Status)"
        link_speed               = "$($a.LinkSpeed)"
        bound_vswitch            = $bound
        is_management_nic        = [bool]$isMgmt
        management_risk          = [bool]$isMgmt
        recommended_for_external = [bool]$rec
    }
}
ConvertTo-Json -InputObject @($rows) -Depth 4
`)
	return wrapTagged(b.String())
}

// ParseNICs parses the JSON array emitted by BuildListNicsScript. PowerShell
// emits a bare object (not an array) for a single row; ParseNICs handles both.
func ParseNICs(jsonText string) ([]NIC, error) {
	jsonText = strings.TrimSpace(extractJSON(jsonText))
	if jsonText == "" {
		return nil, nil
	}
	if strings.HasPrefix(jsonText, "{") {
		var one NIC
		if err := json.Unmarshal([]byte(jsonText), &one); err != nil {
			return nil, err
		}
		return []NIC{one}, nil
	}
	var nics []NIC
	if err := json.Unmarshal([]byte(jsonText), &nics); err != nil {
		return nil, err
	}
	return nics, nil
}

// extractJSON returns the substring from the first '[' or '{' to the matching
// last ']' or '}', skipping any leading PowerShell/log noise.
func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	startArr := strings.Index(s, "[")
	startObj := strings.Index(s, "{")
	start := -1
	switch {
	case startArr == -1:
		start = startObj
	case startObj == -1:
		start = startArr
	default:
		if startArr < startObj {
			start = startArr
		} else {
			start = startObj
		}
	}
	if start == -1 {
		return s
	}
	endArr := strings.LastIndex(s, "]")
	endObj := strings.LastIndex(s, "}")
	end := endArr
	if endObj > end {
		end = endObj
	}
	if end <= start {
		return s
	}
	return s[start : end+1]
}
