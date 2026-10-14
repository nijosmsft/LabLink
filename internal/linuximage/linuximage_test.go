package linuximage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

func TestFixedSourceValidation(t *testing.T) {
	source := FixedSource()
	if err := source.Validate(); err != nil {
		t.Fatal(err)
	}
	if source.ImageURL != "https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz" ||
		ImageFilename != "ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz" ||
		ExtractedVHDFilename != "livecd.ubuntu-cpc.azure.vhd" {
		t.Fatalf("unexpected fixed source: %+v", source)
	}
	source.ImageURL = "http://cloud-images.ubuntu.com/image"
	if err := source.Validate(); err == nil {
		t.Fatal("expected non-HTTPS source rejection")
	}
	source = FixedSource()
	source.ImageURL = "https://example.com/arbitrary.vhd.tar.gz"
	if err := source.Validate(); err == nil || !strings.Contains(err.Error(), "fixed") {
		t.Fatalf("expected arbitrary source rejection, got %v", err)
	}
	for _, raw := range []string{"http://example.com/x", "https:///x", "******example.com/x", "https://example.com/x#frag"} {
		if err := ValidateHTTPSURL(raw); err == nil {
			t.Errorf("ValidateHTTPSURL(%q) unexpectedly succeeded", raw)
		}
	}
}

func TestParseSHA256SUMSExactImage(t *testing.T) {
	hash := strings.Repeat("a", 64)
	data := []byte(strings.Join([]string{
		strings.Repeat("b", 64) + " *other.img",
		hash + "  " + ImageFilename,
	}, "\r\n"))
	got, err := ParseSHA256SUMS(data, ImageFilename)
	if err != nil || got != hash {
		t.Fatalf("checksum = %q, %v", got, err)
	}
}

func TestParseSHA256SUMSRejectsMissingDuplicateAndInvalid(t *testing.T) {
	hash := strings.Repeat("a", 64)
	cases := map[string]string{
		"missing":   hash + "  prefix-" + ImageFilename,
		"duplicate": hash + "  " + ImageFilename + "\n" + hash + " *" + ImageFilename,
		"invalid":   strings.Repeat("z", 64) + "  " + ImageFilename,
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSHA256SUMS([]byte(data), ImageFilename); err == nil {
				t.Fatal("expected parse error")
			}
		})
	}
}

func TestContentAddressedCachePaths(t *testing.T) {
	digest := strings.Repeat("1", 64)
	paths, err := NewCachePaths(`E:\LabLinkImages`, digest, 64)
	if err != nil {
		t.Fatal(err)
	}
	if paths.CacheKey == "" || !strings.Contains(paths.ImagePath, filepath.Join("sha256", digest)) {
		t.Fatalf("paths are not content-addressed: %+v", paths)
	}
	if !strings.HasSuffix(paths.PreparedVHDXPath, SourceID+".vhdx") ||
		!strings.HasSuffix(paths.MetadataPath, "metadata.json") ||
		!strings.HasSuffix(paths.StatePath, "state.json") {
		t.Fatalf("unexpected paths: %+v", paths)
	}
	if !strings.Contains(paths.StatePath, filepath.Join("variants", "disk-64")) {
		t.Fatalf("state path is not disk-size-specific: %s", paths.StatePath)
	}
	other, _ := CacheKey(strings.Repeat("2", 64), 64)
	if other == paths.CacheKey {
		t.Fatal("different image digests produced the same cache key")
	}
	otherSize, _ := CacheKey(digest, 128)
	if otherSize == paths.CacheKey {
		t.Fatal("different disk sizes produced the same cache key")
	}
	for _, oldSchema := range []string{"lablink-linux-old-v0", "lablink-linux-old-v1"} {
		oldSchemaKey := sha256Text(SourceID + "\n" + digest + "\n" + oldSchema + "\ndisk_size_gb=64")
		if oldSchemaKey == paths.CacheKey {
			t.Fatalf("old transform schema %q cache key was adopted", oldSchema)
		}
	}
}

func TestUbuntuManifestVerifierOfficialSignature(t *testing.T) {
	manifest, err := os.ReadFile(filepath.Join("testdata", "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(filepath.Join("testdata", "SHA256SUMS.gpg"))
	if err != nil {
		t.Fatal(err)
	}
	state, err := (UbuntuManifestVerifier{}).VerifyManifest(context.Background(), ManifestVerificationRequest{
		Source: FixedSource(), Manifest: manifest, Signature: signature,
	})
	if err != nil || state.Status != VerificationVerified ||
		state.Signer != UbuntuSigningKeyFingerprint || state.VerifiedAt == nil {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	if _, err := ParseSHA256SUMS(manifest, ImageFilename); err != nil {
		t.Fatalf("signed manifest does not contain exact Azure VHD archive: %v", err)
	}
}

func TestUbuntuManifestVerifierRejectsTamperAndWrongKey(t *testing.T) {
	manifest, _ := os.ReadFile(filepath.Join("testdata", "SHA256SUMS"))
	signature, _ := os.ReadFile(filepath.Join("testdata", "SHA256SUMS.gpg"))
	tampered := append([]byte(nil), manifest...)
	tampered[0] ^= 1
	wrongEntity, err := openpgp.NewEntity("Wrong", "", "wrong@example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	var wrongSignature bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&wrongSignature, wrongEntity, bytes.NewReader(manifest), nil); err != nil {
		t.Fatal(err)
	}
	for name, request := range map[string]ManifestVerificationRequest{
		"tampered manifest": {Source: FixedSource(), Manifest: tampered, Signature: signature},
		"wrong key signature": {
			Source: FixedSource(), Manifest: manifest, Signature: wrongSignature.Bytes(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			state, err := (UbuntuManifestVerifier{}).VerifyManifest(context.Background(), request)
			if err == nil || state.Status != VerificationFailed {
				t.Fatalf("state=%+v err=%v", state, err)
			}
		})
	}
}

func sha256Text(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
