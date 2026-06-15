package leasing

import "testing"

// --- DescribeAgentID tests ---------------------------------------------------

func TestDescribeAgentID_SameUser(t *testing.T) {
	self := Identity{Cookie: "deadbeef", Hostname: "CPC-nijos-D1A4Z"}
	agentID := "deadbeef-CPC-nijos-D1A4Z-47628-4446"
	d := DescribeAgentID(agentID, self)
	if !d.Decoded {
		t.Fatalf("Decoded=false, want true; raw=%q", agentID)
	}
	if d.Cookie != "deadbeef" {
		t.Fatalf("Cookie=%q want deadbeef", d.Cookie)
	}
	if d.Hostname != "CPC-nijos-D1A4Z" {
		t.Fatalf("Hostname=%q want CPC-nijos-D1A4Z", d.Hostname)
	}
	if d.PID != 47628 {
		t.Fatalf("PID=%d want 47628", d.PID)
	}
	if d.Suffix != "4446" {
		t.Fatalf("Suffix=%q want 4446", d.Suffix)
	}
	if !d.SameHost {
		t.Fatalf("SameHost=false, want true")
	}
	if !d.SameUser {
		t.Fatalf("SameUser=false, want true")
	}
	if d.Raw != agentID {
		t.Fatalf("Raw=%q want %q", d.Raw, agentID)
	}
}

func TestDescribeAgentID_SameHostDifferentUser(t *testing.T) {
	// Cookie does not match self's cookie; hostname does.
	self := Identity{Cookie: "aabbccdd", Hostname: "CPC-nijos-D1A4Z"}
	agentID := "deadbeef-CPC-nijos-D1A4Z-47628-4446"
	d := DescribeAgentID(agentID, self)
	if !d.Decoded {
		t.Fatalf("Decoded=false, want true")
	}
	if !d.SameHost {
		t.Fatalf("SameHost=false, want true")
	}
	if d.SameUser {
		t.Fatalf("SameUser=true, want false (cookie differs)")
	}
}

func TestDescribeAgentID_DifferentHost(t *testing.T) {
	self := Identity{Cookie: "deadbeef", Hostname: "SOME-OTHER-BOX"}
	agentID := "deadbeef-CPC-nijos-D1A4Z-47628-4446"
	d := DescribeAgentID(agentID, self)
	if !d.Decoded {
		t.Fatalf("Decoded=false, want true")
	}
	if d.SameHost {
		t.Fatalf("SameHost=true, want false")
	}
	if d.SameUser {
		t.Fatalf("SameUser=true, want false")
	}
}

func TestDescribeAgentID_HostnameWithDashes(t *testing.T) {
	// Hostname contains multiple dashes; parsing must handle it correctly.
	self := Identity{Cookie: "11223344", Hostname: "CPC-nijos-D1A4Z"}
	agentID := "11223344-CPC-nijos-D1A4Z-99999-abcd"
	d := DescribeAgentID(agentID, self)
	if !d.Decoded {
		t.Fatalf("Decoded=false, want true for hostname-with-dashes")
	}
	if d.Hostname != "CPC-nijos-D1A4Z" {
		t.Fatalf("Hostname=%q want CPC-nijos-D1A4Z", d.Hostname)
	}
	if d.PID != 99999 {
		t.Fatalf("PID=%d want 99999", d.PID)
	}
	if d.Suffix != "abcd" {
		t.Fatalf("Suffix=%q want abcd", d.Suffix)
	}
	if !d.SameHost {
		t.Fatalf("SameHost=false, want true")
	}
	if !d.SameUser {
		t.Fatalf("SameUser=false, want true")
	}
}

func TestDescribeAgentID_CustomAgentID_NoDecode(t *testing.T) {
	// A value set via LABLINK_AGENT_ID — does not match the standard shape.
	self := Identity{Cookie: "deadbeef", Hostname: "myhost"}
	for _, agentID := range []string{
		"custom-value",
		"alice-test",
		"bob-other",
		"my-very-long-non-standard-agent-identifier",
	} {
		d := DescribeAgentID(agentID, self)
		if d.Decoded {
			t.Errorf("agentID=%q: Decoded=true, want false", agentID)
		}
		if d.Raw != agentID {
			t.Errorf("agentID=%q: Raw=%q, want input unchanged", agentID, d.Raw)
		}
		if d.SameHost || d.SameUser {
			t.Errorf("agentID=%q: SameHost=%v SameUser=%v, both want false", agentID, d.SameHost, d.SameUser)
		}
	}
}

func TestDescribeAgentID_BadCookie_NoDecode(t *testing.T) {
	self := Identity{Cookie: "deadbeef", Hostname: "myhost"}
	// Cookie is not 8 hex chars.
	d := DescribeAgentID("short-myhost-1234-ab12", self)
	if d.Decoded {
		t.Fatalf("Decoded=true, want false when cookie is not 8 hex chars")
	}
}

func TestDescribeAgentID_BadSuffix_NoDecode(t *testing.T) {
	self := Identity{Cookie: "deadbeef", Hostname: "myhost"}
	// Suffix has non-hex chars.
	d := DescribeAgentID("deadbeef-myhost-1234-ZZZZ", self)
	if d.Decoded {
		t.Fatalf("Decoded=true, want false when suffix has non-hex chars")
	}
}

func TestDescribeAgentID_NoPID_NoDecode(t *testing.T) {
	self := Identity{Cookie: "deadbeef", Hostname: "myhost"}
	// No numeric pid segment.
	d := DescribeAgentID("deadbeef-myhost-notapid-abcd", self)
	if d.Decoded {
		t.Fatalf("Decoded=true, want false when pid is non-numeric")
	}
}
