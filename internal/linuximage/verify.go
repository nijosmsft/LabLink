package linuximage

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// Ubuntu's official documentation identifies this key as the UEC Image
// Automatic Signing Key used for cloud-image checksum manifests:
// https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/
//
//go:embed ubuntu-cloud-image-signing-key.asc
var ubuntuCloudImageSigningKey []byte

type ManifestVerificationRequest struct {
	Source    Source
	Manifest  []byte
	Signature []byte
}

// ManifestVerifier authenticates SHA256SUMS before its image digest may be
// trusted. Implementations must verify an approved Ubuntu signing identity.
type ManifestVerifier interface {
	VerifyManifest(context.Context, ManifestVerificationRequest) (VerificationState, error)
}

type VerificationError struct {
	State VerificationStatus
	Err   error
}

func (e *VerificationError) Error() string {
	return fmt.Sprintf("manifest verification %s: %v", e.State, e.Err)
}

func (e *VerificationError) Unwrap() error { return e.Err }

// UbuntuManifestVerifier verifies the detached SHA256SUMS signature using the
// embedded Canonical cloud-image key and pins the exact documented primary-key
// fingerprint. No system keyring or network key lookup participates.
type UbuntuManifestVerifier struct {
	Now func() time.Time
}

func (v UbuntuManifestVerifier) VerifyManifest(_ context.Context, req ManifestVerificationRequest) (VerificationState, error) {
	fail := func(err error) (VerificationState, error) {
		state := VerificationState{
			Status: VerificationFailed, Verifier: "openpgp-pinned-key",
			Signer: UbuntuSigningKeyFingerprint, Error: err.Error(),
		}
		return state, &VerificationError{State: VerificationFailed, Err: err}
	}
	if err := req.Source.Validate(); err != nil {
		return fail(fmt.Errorf("source: %w", err))
	}
	if len(req.Manifest) == 0 || len(req.Signature) == 0 {
		return fail(fmt.Errorf("manifest and detached signature are required"))
	}
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(ubuntuCloudImageSigningKey))
	if err != nil {
		return fail(fmt.Errorf("parse embedded Ubuntu signing key: %w", err))
	}
	if len(keyring) != 1 || keyring[0].PrimaryKey == nil {
		return fail(fmt.Errorf("embedded Ubuntu signing key must contain exactly one primary key"))
	}
	embeddedFingerprint := strings.ToUpper(hex.EncodeToString(keyring[0].PrimaryKey.Fingerprint))
	if embeddedFingerprint != UbuntuSigningKeyFingerprint {
		return fail(fmt.Errorf("embedded Ubuntu signing key fingerprint %s does not match pinned fingerprint %s", embeddedFingerprint, UbuntuSigningKeyFingerprint))
	}
	signer, err := openpgp.CheckArmoredDetachedSignature(
		keyring, bytes.NewReader(req.Manifest), bytes.NewReader(req.Signature), nil,
	)
	if err != nil {
		return fail(fmt.Errorf("verify SHA256SUMS.gpg: %w", err))
	}
	if signer == nil || signer.PrimaryKey == nil {
		return fail(fmt.Errorf("signature verifier returned no signer"))
	}
	signerFingerprint := strings.ToUpper(hex.EncodeToString(signer.PrimaryKey.Fingerprint))
	if signerFingerprint != UbuntuSigningKeyFingerprint {
		return fail(fmt.Errorf("signature signer fingerprint %s does not match pinned fingerprint %s", signerFingerprint, UbuntuSigningKeyFingerprint))
	}
	now := time.Now().UTC()
	if v.Now != nil {
		now = v.Now().UTC()
	}
	return VerificationState{
		Status: VerificationVerified, Verifier: "openpgp-pinned-key",
		Signer: signerFingerprint, VerifiedAt: &now,
	}, nil
}
