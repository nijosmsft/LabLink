// Package hyperv contains pure PowerShell/XML builders and parsers for the
// LabLink VM-management tools. It deliberately has NO dependency on mcp-go,
// gRPC, or the rest of the server so the script/XML construction can be unit
// tested in isolation (Heimdall review §3 layering requirement).
//
// Every script emitted here is "argument safe": caller-supplied values are
// emitted as single-quoted PowerShell literals via PSLit / PSBool, never
// interpolated directly into a command line. This matches the existing
// escapePSString convention in internal/mcptools/deploy.go and the network
// reviewer's "argument-safe construction" requirement.
package hyperv

import (
	"fmt"
	"strings"
)

// EscapePS escapes a string for inclusion inside a PowerShell single-quoted
// literal by doubling embedded single quotes.
func EscapePS(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// PSLit renders s as a complete single-quoted PowerShell string literal,
// doubling any embedded single quotes (the standard PowerShell escape).
func PSLit(s string) string {
	return "'" + EscapePS(s) + "'"
}

// PSBool renders a Go bool as a PowerShell boolean literal.
func PSBool(b bool) string {
	if b {
		return "$true"
	}
	return "$false"
}

// scriptPreamble is prepended to every Hyper-V mutation/discovery script so a
// failure is a single tagged line on a nonzero exit and runPS can map it to a
// tool error.
const scriptPreamble = "$ErrorActionPreference = 'Stop'\n"

// wrapTagged wraps body in a try/catch that, on error, prints a single tagged
// line ("LABLINK_ERROR: <message>") and exits nonzero so the Go layer can
// detect failure deterministically (runPS treats nonzero exit as failure).
func wrapTagged(body string) string {
	var sb strings.Builder
	sb.WriteString(scriptPreamble)
	sb.WriteString("try {\n")
	sb.WriteString(body)
	sb.WriteString("\n} catch {\n")
	sb.WriteString("    Write-Output (\"LABLINK_ERROR: \" + $_.Exception.Message)\n")
	sb.WriteString("    exit 1\n")
	sb.WriteString("}\n")
	return sb.String()
}

// WrapTagged is the exported form of wrapTagged for sibling packages
// (e.g. internal/hyperv/unattend) that build their own script bodies but want
// the same single-tagged-line failure convention.
func WrapTagged(body string) string { return wrapTagged(body) }

// gbBytes returns a PowerShell numeric literal for n gigabytes as bytes.
func gbBytes(n float64) string { return fmt.Sprintf("%d", int64(n*1024*1024*1024)) }

// mbBytes returns a PowerShell numeric literal for n megabytes as bytes.
func mbBytes(n float64) string { return fmt.Sprintf("%d", int64(n*1024*1024)) }
