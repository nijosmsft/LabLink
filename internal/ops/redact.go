package ops

import "strings"

var sensitiveKeySubstrings = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"credential",
	"apikey",
	"api_key",
}

// Redact returns a shallow copy of args with values replaced by "***" for
// keys whose name suggests they hold a secret. Always safe with nil input.
func Redact(args map[string]string) map[string]string {
	if len(args) == 0 {
		return nil
	}
	out := make(map[string]string, len(args))
	for k, v := range args {
		if isSensitive(k) {
			out[k] = "***"
			continue
		}
		out[k] = truncate(v, 256)
	}
	return out
}

func isSensitive(key string) bool {
	lk := strings.ToLower(key)
	for _, s := range sensitiveKeySubstrings {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
