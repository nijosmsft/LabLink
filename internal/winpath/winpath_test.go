package winpath

import "testing"

func TestWindowsPathsAreHostIndependent(t *testing.T) {
	tests := []struct {
		root string
		want string
	}{
		{`E:\VM`, `E:\VM\guest\guest.vhdx`},
		{`\\host\share\VM`, `\\host\share\VM\guest\guest.vhdx`},
	}
	for _, test := range tests {
		got, err := Join(test.root, "guest", "guest.vhdx")
		if err != nil || got != test.want {
			t.Fatalf("Join(%q) = %q, %v; want %q", test.root, got, err, test.want)
		}
	}
}

func TestRejectsNonCleanWindowsPaths(t *testing.T) {
	for _, value := range []string{
		`E:\VM\..\bad`, `E:/VM`, `relative\VM`, `E:\VM\\guest`,
		`\\host`, `E:\VM\guest.`, `E:\VM\bad:name`, "E:\\VM\\bad\nname",
	} {
		if _, err := CleanAbsolute(value); err == nil {
			t.Errorf("CleanAbsolute(%q) unexpectedly succeeded", value)
		}
	}
}
