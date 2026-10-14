// Package linuximage defines the fixed Ubuntu Azure VHD source, validation,
// and content-addressed cache model used by LabLink.
package linuximage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/winpath"
)

const (
	SourceID                    = "ubuntu-24.04-amd64-generic"
	Distribution                = "ubuntu"
	Release                     = "24.04"
	Architecture                = "amd64"
	ImageFilename               = "ubuntu-24.04-server-cloudimg-amd64-azure.vhd.tar.gz"
	ExtractedVHDFilename        = "livecd.ubuntu-cpc.azure.vhd"
	ManifestFilename            = "SHA256SUMS"
	ManifestSigFilename         = "SHA256SUMS.gpg"
	TransformSchema             = "lablink-linux-nocloud-azure-vhd-wsl-builder-v1"
	SourceBaseURL               = "https://cloud-images.ubuntu.com/releases/noble/release"
	ImageURL                    = SourceBaseURL + "/" + ImageFilename
	SHA256SUMSURL               = SourceBaseURL + "/" + ManifestFilename
	SHA256SUMSSignatureURL      = SourceBaseURL + "/" + ManifestSigFilename
	UbuntuSigningKeyFingerprint = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81"
	WSLRuntimeVersion           = "3.0.3"
	WSLRuntimeProductVersion    = "3.0.3.0"
	WSLMSIFilename              = "wsl.3.0.3.0.x64.msi"
	WSLMSIURL                   = "https://github.com/microsoft/WSL/releases/download/3.0.3/" + WSLMSIFilename
	WSLMSISHA256                = "ae977286974255bd26bf925f00f40f5692c6b2084155cbc0563c09aea091f211"
	WSLMSIDisplayName           = "LabLink WSL 3.0.3 x64 MSI"
	WSLDistributionName         = "Ubuntu-24.04"
)

// Source is deliberately fixed. Validate rejects substitutions and
// caller-provided URLs.
type Source struct {
	ID                  string `json:"id"`
	Distribution        string `json:"distribution"`
	Release             string `json:"release"`
	Architecture        string `json:"architecture"`
	ImageFilename       string `json:"image_filename"`
	ManifestFilename    string `json:"manifest_filename"`
	SignatureFilename   string `json:"signature_filename"`
	ImageURL            string `json:"image_url"`
	SHA256SUMSURL       string `json:"sha256sums_url"`
	SHA256SUMSSignature string `json:"sha256sums_signature_url"`
}

func FixedSource() Source {
	return Source{
		ID: SourceID, Distribution: Distribution, Release: Release,
		Architecture: Architecture, ImageFilename: ImageFilename,
		ManifestFilename: ManifestFilename, SignatureFilename: ManifestSigFilename,
		ImageURL: ImageURL, SHA256SUMSURL: SHA256SUMSURL,
		SHA256SUMSSignature: SHA256SUMSSignatureURL,
	}
}

func ValidateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("URL must use HTTPS")
	}
	if u.Host == "" || u.User != nil {
		return fmt.Errorf("URL must have a host and no user information")
	}
	if u.Fragment != "" {
		return fmt.Errorf("URL fragments are not allowed")
	}
	return nil
}

func (s Source) Validate() error {
	for label, raw := range map[string]string{
		"image": s.ImageURL, "SHA256SUMS": s.SHA256SUMSURL,
		"SHA256SUMS signature": s.SHA256SUMSSignature,
	} {
		if err := ValidateHTTPSURL(raw); err != nil {
			return fmt.Errorf("%s URL: %w", label, err)
		}
	}
	want := FixedSource()
	gotJSON, _ := json.Marshal(s)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		return fmt.Errorf("unsupported Linux image source metadata; source is fixed to %s", SourceID)
	}
	return nil
}

type VerificationStatus string

const (
	VerificationPending     VerificationStatus = "pending"
	VerificationVerified    VerificationStatus = "verified"
	VerificationFailed      VerificationStatus = "failed"
	VerificationUnavailable VerificationStatus = "unavailable"
)

type VerificationState struct {
	Status     VerificationStatus `json:"status"`
	Verifier   string             `json:"verifier,omitempty"`
	Signer     string             `json:"signer,omitempty"`
	VerifiedAt *time.Time         `json:"verified_at,omitempty"`
	Error      string             `json:"error,omitempty"`
}

type Phase string

const (
	PhasePlanned              Phase = "planned"
	PhasePrerequisites        Phase = "prerequisites"
	PhaseDownloading          Phase = "downloading"
	PhaseVerificationRequired Phase = "signature_verification_required"
	PhaseImageValidated       Phase = "image_validated"
	PhaseConverted            Phase = "converted"
	PhaseBuilderReady         Phase = "builder_ready"
	PhaseDiskAttached         Phase = "disk_attached"
	PhaseFilesystemUpdated    Phase = "filesystem_updated"
	PhaseDiagnosticRetained   Phase = "diagnostic_retained"
	PhaseReady                Phase = "ready"
	PhaseFailed               Phase = "failed"
)

type BITSJobState struct {
	Kind             string `json:"kind"`
	ID               string `json:"id,omitempty"`
	DisplayName      string `json:"display_name,omitempty"`
	State            string `json:"state,omitempty"`
	BytesTransferred int64  `json:"bytes_transferred,omitempty"`
	BytesTotal       int64  `json:"bytes_total,omitempty"`
	Error            string `json:"error,omitempty"`
}

type PreparationState struct {
	SchemaVersion    string            `json:"schema_version"`
	Source           Source            `json:"source"`
	Phase            Phase             `json:"phase"`
	StagingID        string            `json:"staging_id"`
	CacheRoot        string            `json:"cache_root"`
	ImageSHA256      string            `json:"image_sha256,omitempty"`
	CacheKey         string            `json:"cache_key,omitempty"`
	DiskSizeGB       int               `json:"disk_size_gb"`
	ImagePath        string            `json:"image_path,omitempty"`
	StagedVHDX       string            `json:"staged_vhdx,omitempty"`
	PreparedVHDX     string            `json:"prepared_vhdx,omitempty"`
	PreparedSHA256   string            `json:"prepared_sha256,omitempty"`
	MetadataPath     string            `json:"metadata_path,omitempty"`
	BuilderProfile   string            `json:"image_builder_profile,omitempty"`
	BuilderVMName    string            `json:"builder_vm_name,omitempty"`
	BuilderNodeName  string            `json:"builder_node_name,omitempty"`
	AttachedDiskPath string            `json:"attached_disk_path,omitempty"`
	DiagnosticState  string            `json:"diagnostic_state,omitempty"`
	Jobs             []BITSJobState    `json:"jobs,omitempty"`
	Verification     VerificationState `json:"verification"`
	UpdatedAt        time.Time         `json:"updated_at"`
	Error            string            `json:"error,omitempty"`
}

type ImageMetadata struct {
	SchemaVersion             string            `json:"schema_version"`
	CacheKey                  string            `json:"cache_key"`
	Source                    Source            `json:"source"`
	ImageSHA256               string            `json:"image_sha256"`
	PreparedSHA256            string            `json:"prepared_sha256"`
	DiskSizeGB                int               `json:"disk_size_gb"`
	PreparedVHDX              string            `json:"prepared_vhdx"`
	BuilderProfile            string            `json:"image_builder_profile"`
	BuilderProfileFingerprint string            `json:"builder_profile_fingerprint"`
	Verification              VerificationState `json:"verification"`
	PublishedAt               time.Time         `json:"published_at"`
}

type CachePaths struct {
	Root             string `json:"root"`
	CacheKey         string `json:"cache_key"`
	ImageSHA256      string `json:"image_sha256"`
	SourceStateDir   string `json:"source_state_dir"`
	StatePath        string `json:"state_path"`
	DownloadDir      string `json:"download_dir"`
	ImagePath        string `json:"image_path"`
	ManifestPath     string `json:"manifest_path"`
	SignaturePath    string `json:"signature_path"`
	ContentDir       string `json:"content_dir"`
	PreparedVHDXPath string `json:"prepared_vhdx_path"`
	MetadataPath     string `json:"metadata_path"`
	StagingRoot      string `json:"staging_root"`
}

func CacheKey(imageSHA256 string, diskSizeGB int) (string, error) {
	digest, err := normalizeSHA256(imageSHA256)
	if err != nil {
		return "", err
	}
	if err := ValidateDiskSizeGB(diskSizeGB); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf(
		"%s\n%s\n%s\ndisk_size_gb=%d",
		SourceID, digest, TransformSchema, diskSizeGB,
	)))
	return hex.EncodeToString(sum[:]), nil
}

func NewCachePaths(root, imageSHA256 string, diskSizeGB int) (CachePaths, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return CachePaths{}, fmt.Errorf("image cache root is required")
	}
	digest, err := normalizeSHA256(imageSHA256)
	if err != nil {
		return CachePaths{}, err
	}
	key, err := CacheKey(digest, diskSizeGB)
	if err != nil {
		return CachePaths{}, err
	}
	sourceRoot, err := winpath.Join(root, "sources", SourceID)
	if err != nil {
		return CachePaths{}, fmt.Errorf("image cache root: %w", err)
	}
	sourceStateDir, _ := winpath.Join(sourceRoot, "variants", fmt.Sprintf("disk-%d", diskSizeGB))
	downloadDir, _ := winpath.Join(sourceRoot, "downloads")
	imageBlobDir, _ := winpath.Join(root, "blobs", "sha256", digest)
	contentDir, _ := winpath.Join(root, "prepared", key)
	statePath, _ := winpath.Join(sourceStateDir, "state.json")
	imagePath, _ := winpath.Join(imageBlobDir, ImageFilename)
	manifestPath, _ := winpath.Join(downloadDir, ManifestFilename)
	signaturePath, _ := winpath.Join(downloadDir, ManifestSigFilename)
	preparedVHDX, _ := winpath.Join(contentDir, SourceID+".vhdx")
	metadataPath, _ := winpath.Join(contentDir, "metadata.json")
	stagingRoot, _ := winpath.Join(root, "staging")
	return CachePaths{
		Root: root, CacheKey: key, ImageSHA256: digest,
		SourceStateDir: sourceStateDir, StatePath: statePath,
		DownloadDir: downloadDir, ImagePath: imagePath,
		ManifestPath: manifestPath, SignaturePath: signaturePath,
		ContentDir:       contentDir,
		PreparedVHDXPath: preparedVHDX, MetadataPath: metadataPath,
		StagingRoot: stagingRoot,
	}, nil
}

func SourceStatePaths(root string, diskSizeGB int) (stateDir, statePath, downloadDir string, err error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return "", "", "", fmt.Errorf("image cache root is required")
	}
	if err := ValidateDiskSizeGB(diskSizeGB); err != nil {
		return "", "", "", err
	}
	sourceRoot, err := winpath.Join(root, "sources", SourceID)
	if err != nil {
		return "", "", "", fmt.Errorf("image cache root: %w", err)
	}
	stateDir, _ = winpath.Join(sourceRoot, "variants", fmt.Sprintf("disk-%d", diskSizeGB))
	statePath, _ = winpath.Join(stateDir, "state.json")
	downloadDir, _ = winpath.Join(sourceRoot, "downloads")
	return stateDir, statePath, downloadDir, nil
}

func ValidateDiskSizeGB(value int) error {
	if value < 32 || value > 2048 {
		return fmt.Errorf("disk_size_gb must be an integer between 32 and 2048")
	}
	return nil
}

func normalizeSHA256(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("SHA256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", fmt.Errorf("invalid SHA256: %w", err)
	}
	return value, nil
}
