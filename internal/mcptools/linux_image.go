package mcptools

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/nijosmsft/lablink/internal/agentclient"
	"github.com/nijosmsft/lablink/internal/audit"
	"github.com/nijosmsft/lablink/internal/credentials"
	"github.com/nijosmsft/lablink/internal/hyperv"
	"github.com/nijosmsft/lablink/internal/linuximage"
	"github.com/nijosmsft/lablink/internal/registry"
	"github.com/nijosmsft/lablink/internal/vmconfig"
	"github.com/nijosmsft/lablink/internal/winpath"
	pb "github.com/nijosmsft/lablink/proto/agent"
)

const linuxImageBuilderStatePath = `C:\ProgramData\LabLink\linux-image-builder-state.json`
const linuxImageBuilderUserTaskTimeoutSec = 540

type linuxImagePlan struct {
	Profile                   string            `json:"profile,omitempty"`
	Target                    string            `json:"target"`
	ImageCacheRoot            string            `json:"image_cache_root"`
	DiskSizeGB                int               `json:"disk_size_gb"`
	Source                    linuximage.Source `json:"source"`
	TransformSchema           string            `json:"transform_schema"`
	StatePath                 string            `json:"state_path"`
	DownloadDir               string            `json:"download_dir"`
	StagingID                 string            `json:"staging_id"`
	Verification              string            `json:"verification"`
	Ready                     bool              `json:"ready"`
	ImageBuilderProfile       string            `json:"image_builder_profile"`
	BuilderProfileFingerprint string            `json:"builder_profile_fingerprint"`
	BuilderVMName             string            `json:"builder_vm_name"`
	BuilderNodeName           string            `json:"builder_node_name"`
	DeleteBuilderAfterPrepare bool              `json:"delete_builder_after_prepare"`
	Builder                   windowsVMPlan     `json:"builder"`
}

type linuxImageBuilderDiskCleanup struct {
	retain bool
	reason string
}

func newLinuxImageBuilderDiskCleanup() linuxImageBuilderDiskCleanup {
	return linuxImageBuilderDiskCleanup{
		retain: true,
		reason: "operation interrupted after staging disk attachment",
	}
}

func (c *linuxImageBuilderDiskCleanup) acceptVerifiedTransform(status string, safeToDetach bool, transformError string) bool {
	if strings.TrimSpace(transformError) != "" {
		c.reason = transformError
	}
	if status != "filesystem_updated" || !safeToDetach {
		return false
	}
	c.retain = false
	c.reason = ""
	return true
}

func (c *linuxImageBuilderDiskCleanup) retainForFailure(reason string) {
	c.retain = true
	if strings.TrimSpace(reason) != "" {
		c.reason = reason
	}
}

type linuxImageBuilderLock struct {
	params hyperv.LinuxImageBuilderLockParams
}

func acquireLinuxImageBuilderLock(
	ctx context.Context,
	plan linuxImagePlan,
	target Target,
	reg *registry.Registry,
	pool *agentclient.Pool,
) (linuxImageBuilderLock, error) {
	owner, err := newRemoteStageID()
	if err != nil {
		return linuxImageBuilderLock{}, err
	}
	lock := linuxImageBuilderLock{params: hyperv.LinuxImageBuilderLockParams{
		Key: builderIdentityLockKey(plan.Target, plan.BuilderVMName), Owner: owner,
	}}
	script, err := hyperv.BuildLinuxImageBuilderAcquireLockScript(lock.params)
	if err != nil {
		return linuxImageBuilderLock{}, err
	}
	out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
	if err != nil {
		return linuxImageBuilderLock{}, fmt.Errorf("acquire Linux image builder identity lock: %w", err)
	}
	var result struct {
		Acquired bool `json:"acquired"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(out)), &result); err != nil {
		return linuxImageBuilderLock{}, fmt.Errorf("parse Linux image builder identity lock result: %w", err)
	}
	if !result.Acquired {
		return linuxImageBuilderLock{}, fmt.Errorf("Linux image builder %q on %s is active in another preparation", plan.BuilderVMName, plan.Target)
	}
	return lock, nil
}

func (l linuxImageBuilderLock) release(reg *registry.Registry, pool *agentclient.Pool, target Target) {
	script, err := hyperv.BuildLinuxImageBuilderReleaseLockScript(l.params)
	if err != nil {
		return
	}
	_, _, _ = runPS(context.Background(), reg, pool, target, script, vmDefaultTimeoutSec)
}

func registerLinuxImageTools(
	s *server.MCPServer,
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
) {
	s.AddTool(
		mcp.NewTool("prepare_linux_image",
			mcp.WithDescription("Prepare the fixed stable Ubuntu 24.04 amd64 Canonical Azure VHD archive through a required, reusable nested-virtualization Windows builder VM. The host verifies Canonical signatures and converts VHD to VHDX; only the builder installs WSL2 and edits the ext4 filesystem."),
			mcp.WithString("target", mcp.Description("localhost or a registered Windows Hyper-V host; may come from a Linux VM profile")),
			mcp.WithString("profile", mcp.Description("Linux VM profile; empty uses linux_target_defaults/default_linux_profile")),
			mcp.WithString("image_cache_root", mcp.Description("Host path for downloads, state, and content-addressed prepared images")),
			mcp.WithNumber("disk_size_gb", mcp.Description("Prepared OS disk virtual size GB (32-2048; default/profile 64)")),
			mcp.WithString("image_builder_profile", mcp.Description("Required Windows VM profile used to create/reuse the nested builder")),
			mcp.WithString("builder_vm_name", mcp.Description("Reusable builder VM name; defaults to LabLink-LinuxImageBuilder-<target>")),
			mcp.WithBoolean("delete_builder_after_prepare", mcp.Description("Delete only the operation-owned builder VM and child storage after success (default false; otherwise retained stopped)")),
			mcp.WithBoolean("dry_run", mcp.Description("Resolve and return the preparation plan without downloading, creating a VM, enabling WSL, or changing the host")),
		),
		prepareLinuxImageHandler(reg, pool, defaults, creds, auditLog, enrollment, leaseCfg),
	)
	s.AddTool(
		mcp.NewTool("get_linux_image_status",
			mcp.WithDescription("Return resumable state and BITS progress for the fixed Ubuntu Hyper-V image preparation."),
			mcp.WithString("target", mcp.Description("localhost or a registered Windows Hyper-V host; may come from a Linux VM profile")),
			mcp.WithString("profile", mcp.Description("Linux VM profile; empty uses linux_target_defaults/default_linux_profile")),
			mcp.WithString("image_cache_root", mcp.Description("Host image cache root; may come from the Linux VM profile")),
			mcp.WithNumber("disk_size_gb", mcp.Description("Prepared OS disk virtual size GB; must match the requested variant")),
			mcp.WithString("image_builder_profile", mcp.Description("Required Windows builder profile, used for validation before status access")),
		),
		getLinuxImageStatusHandler(reg, pool, defaults, creds),
	)
}

func prepareLinuxImageHandler(
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
	leaseCfg LeaseGateConfig,
) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		plan, target, err := resolveLinuxImagePlan(req, reg, defaults, creds)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		if req.GetBool("dry_run", false) {
			return vmResult("**Resolved Linux image preparation plan** (dry run; no changes made)", marshalPlan(plan)), nil
		}

		gatedReq := req
		args := cloneArguments(req.GetArguments())
		args["target"] = plan.Target
		gatedReq.Params.Arguments = args
		gatedReq.Params.Name = "prepare_linux_image"

		execute := func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ctx, op := beginOp(ctx, "prepare_linux_image", target.Name, "prepare fixed Ubuntu Azure VHD through nested builder", map[string]string{
				"target": target.Name, "image_cache_root": plan.ImageCacheRoot,
				"image_builder_profile": plan.ImageBuilderProfile, "builder_vm_name": plan.BuilderVMName,
			})
			var opErr error
			defer func() { op.Done(opErr) }()
			start := time.Now()
			stopHB := StartMCPHeartbeat(ctx, req, defaultHeartbeatInterval, func() (int64, int64) {
				return int64(time.Since(start).Seconds()), 45 * 60
			})
			defer stopHB()

			builderSourcePreflight, _ := hyperv.BuildLinuxImageBuilderSourcePreflightScript(
				plan.Builder.BaseVHD, plan.Builder.VMRoot, plan.Builder.VSwitch,
			)
			if _, _, err := runPS(ctx, reg, pool, target, builderSourcePreflight, vmDefaultTimeoutSec); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("Linux image builder source preconditions: %v", err)), nil
			}
			probe, _ := hyperv.BuildLinuxImagePrerequisiteProbeScript()
			if _, _, err := runPS(ctx, reg, pool, target, probe, vmDefaultTimeoutSec); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("Linux image host prerequisites: %v", err)), nil
			}

			download, err := hyperv.BuildLinuxImageDownloadScript(hyperv.LinuxImageDownloadParams{
				CacheRoot: plan.ImageCacheRoot, StagingID: plan.StagingID, DiskSizeGB: plan.DiskSizeGB,
			})
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			out, _, err := runPS(ctx, reg, pool, target, download, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("Linux image downloads: %v", err)), nil
			}
			var progress struct {
				Status      string `json:"status"`
				AllComplete bool   `json:"all_complete"`
				Ready       bool   `json:"ready"`
				State       struct {
					StagingID string `json:"staging_id"`
				} `json:"state"`
			}
			body := jsonExtract(out)
			if err := json.Unmarshal([]byte(body), &progress); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse Linux image download status: %v\nraw:\n%s", err, out)), nil
			}
			if !progress.AllComplete {
				if progress.Status == "download_failed" {
					return vmResult("**Linux image preparation download failed** — inspect the BITS job error and retry.", body), nil
				}
				return vmResult("**Linux image preparation started/resumed** — BITS is active; call `get_linux_image_status` for progress.", body), nil
			}
			if progress.Ready {
				statusScript, _ := hyperv.BuildLinuxImageStatusScript(plan.ImageCacheRoot, plan.DiskSizeGB)
				statusOut, _, statusErr := runPS(ctx, reg, pool, target, statusScript, vmDefaultTimeoutSec)
				if statusErr != nil {
					opErr = statusErr
					return mcp.NewToolResultError(fmt.Sprintf("validate ready Linux image metadata: %v", statusErr)), nil
				}
				return vmResult("**Linux image is ready** — the verified content-addressed base can be reused.", jsonExtract(statusOut)), nil
			}

			manifestPath, _ := winpath.Join(plan.DownloadDir, linuximage.ManifestFilename)
			signaturePath, _ := winpath.Join(plan.DownloadDir, linuximage.ManifestSigFilename)
			manifest, err := readTargetFile(ctx, pool, target, manifestPath, 2*1024*1024)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("pull SHA256SUMS from %s: %v", target.Name, err)), nil
			}
			signature, err := readTargetFile(ctx, pool, target, signaturePath, 64*1024)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("pull SHA256SUMS.gpg from %s: %v", target.Name, err)), nil
			}
			verification, err := (linuximage.UbuntuManifestVerifier{}).VerifyManifest(ctx, linuximage.ManifestVerificationRequest{
				Source: linuximage.FixedSource(), Manifest: manifest, Signature: signature,
			})
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("verify Ubuntu SHA256SUMS.gpg with pinned signer %s: %v", linuximage.UbuntuSigningKeyFingerprint, err)), nil
			}
			imageHash, err := linuximage.ParseSHA256SUMS(manifest, linuximage.ImageFilename)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse authenticated SHA256SUMS: %v", err)), nil
			}
			paths, err := linuximage.NewCachePaths(plan.ImageCacheRoot, imageHash, plan.DiskSizeGB)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			lockParams := hyperv.LinuxImageLockParams{CacheRoot: plan.ImageCacheRoot, CacheKey: paths.CacheKey, Owner: plan.StagingID}
			acquire, _ := hyperv.BuildLinuxImageAcquireLockScript(lockParams)
			lockOut, _, err := runPS(ctx, reg, pool, target, acquire, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("acquire Linux image preparation lock: %v", err)), nil
			}
			var lockResult struct {
				Acquired bool `json:"acquired"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(lockOut)), &lockResult); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse Linux image lock result: %v", err)), nil
			}
			if !lockResult.Acquired {
				return vmResult("**Linux image preparation is active in another caller** — retry after the same-image transform finishes.", jsonExtract(lockOut)), nil
			}
			release, _ := hyperv.BuildLinuxImageReleaseLockScript(lockParams)
			defer func() { _, _, _ = runPS(context.Background(), reg, pool, target, release, vmDefaultTimeoutSec) }()

			verifyDownloads, _ := hyperv.BuildLinuxImageVerifyScript(hyperv.LinuxImageVerifyParams{
				CacheRoot: plan.ImageCacheRoot, ExpectedImageHash: imageHash,
				CacheKey: paths.CacheKey, DiskSizeGB: plan.DiskSizeGB, Verification: verification,
			})
			if _, _, err = runPS(ctx, reg, pool, target, verifyDownloads, vmDefaultTimeoutSec); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("verify downloaded Canonical Azure VHD archive: %v", err)), nil
			}

			transformStagingID := progress.State.StagingID
			if transformStagingID == "" {
				transformStagingID = plan.StagingID
			}
			stageDir, _ := winpath.Join(paths.StagingRoot, transformStagingID)
			stagedVHDX, _ := winpath.Join(stageDir, linuximage.SourceID+".vhdx")
			convert, _ := hyperv.BuildLinuxImageConvertScript(hyperv.LinuxImageConvertParams{
				SourceArchive: paths.ImagePath, DestinationVHDX: stagedVHDX,
				StatePath: paths.StatePath, StageDir: stageDir, DiskSizeGB: plan.DiskSizeGB,
			})
			convertOut, _, err := runPS(ctx, reg, pool, target, convert, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("extract and Convert-VHD Canonical Azure image: %v", err)), nil
			}
			var converted struct {
				DiskIdentifier string `json:"disk_identifier"`
				VirtualSize    int64  `json:"virtual_size"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(convertOut)), &converted); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse converted VHDX identity: %v", err)), nil
			}

			builderLock, err := acquireLinuxImageBuilderLock(ctx, plan, target, reg, pool)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			defer builderLock.release(reg, pool, target)

			builderTarget, err := ensureLinuxImageBuilder(ctx, plan, target, reg, pool, creds, auditLog, enrollment)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			setupPayload, _ := hyperv.BuildLinuxImageBuilderSetupScript(linuxImageBuilderStatePath)
			setupScript, _ := hyperv.BuildLinuxImageBuilderUserTaskScript(setupPayload, linuxImageBuilderUserTaskTimeoutSec)
			setupOut, _, err := runLinuxImageBuilderUserScript(
				ctx, plan, reg, pool, builderTarget, creds, setupScript, vmDefaultTimeoutSec,
			)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("configure WSL2 inside builder %s: %v", plan.BuilderNodeName, err)), nil
			}
			var setupResult struct {
				Status string `json:"status"`
				Phase  string `json:"phase"`
			}
			const maxBuilderSetupReboots = 4
			for rebootCount := 0; ; {
				setupBody := jsonExtract(setupOut)
				if err := json.Unmarshal([]byte(setupBody), &setupResult); err != nil {
					opErr = err
					return mcp.NewToolResultError(fmt.Sprintf("parse builder setup state: %v", err)), nil
				}
				if setupResult.Status == "builder_ready" {
					break
				}
				if setupResult.Status == "setup_pending" {
					return vmResult("**Linux image builder setup started/resumed** — the pinned WSL MSI BITS transfer is active; rerun `prepare_linux_image` to resume.", setupBody), nil
				}
				if setupResult.Status != "reboot_required" {
					opErr = fmt.Errorf("unexpected builder setup status %q in phase %q", setupResult.Status, setupResult.Phase)
					return mcp.NewToolResultError(opErr.Error()), nil
				}
				if rebootCount >= maxBuilderSetupReboots {
					opErr = fmt.Errorf("builder setup exceeded %d required reboots; last phase %q", maxBuilderSetupReboots, setupResult.Phase)
					return mcp.NewToolResultError(opErr.Error()), nil
				}
				if err := rebootLinuxImageBuilder(ctx, builderTarget, pool); err != nil {
					opErr = err
					return mcp.NewToolResultError(err.Error()), nil
				}
				builderTarget, err = startAndVerifyLinuxImageBuilder(ctx, plan, target, reg, pool)
				if err != nil {
					opErr = err
					return mcp.NewToolResultError(fmt.Sprintf("rediscover builder after reboot: %v", err)), nil
				}
				setupOut, _, err = runLinuxImageBuilderUserScript(
					ctx, plan, reg, pool, builderTarget, creds, setupScript, vmDefaultTimeoutSec,
				)
				if err != nil {
					opErr = err
					return mcp.NewToolResultError(fmt.Sprintf("resume WSL2 setup after builder reboot: %v", err)), nil
				}
				rebootCount++
			}
			recordBuilder, _ := hyperv.BuildLinuxImageRecordBuilderScript(
				paths.StatePath, plan.ImageBuilderProfile, plan.BuilderVMName, plan.BuilderNodeName,
			)
			if _, _, err := runPS(ctx, reg, pool, target, recordBuilder, vmDefaultTimeoutSec); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("persist ready builder identity: %v", err)), nil
			}

			inspectScript, _ := hyperv.BuildInspectLinuxImageBuilderScript(plan.BuilderVMName, builderMetadata(plan))
			inspectOut, _, err := runPS(ctx, reg, pool, target, inspectScript, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("inspect builder disk ownership: %v", err)), nil
			}
			var builderInfo struct {
				DiskPaths []string `json:"disk_paths"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(inspectOut)), &builderInfo); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse builder disk inventory: %v", err)), nil
			}
			alreadyAttached := builderContainsWindowsPath(builderInfo.DiskPaths, stagedVHDX)
			if !alreadyAttached {
				inventoryScript, _ := hyperv.BuildLinuxImageBuilderInventoryScript(linuxImageBuilderStatePath)
				if _, _, err := runPS(ctx, reg, pool, builderTarget, inventoryScript, vmDefaultTimeoutSec); err != nil {
					opErr = err
					return mcp.NewToolResultError(fmt.Sprintf("persist builder pre-attach disk inventory: %v", err)), nil
				}
			}

			attachScript, _ := hyperv.BuildLinuxImageBuilderAttachScript(hyperv.LinuxImageBuilderAttachParams{
				VMName: plan.BuilderVMName, VHDXPath: stagedVHDX, StatePath: paths.StatePath, DiskSizeGB: plan.DiskSizeGB,
			})
			cleanupAttachedDisk := true
			diskCleanup := newLinuxImageBuilderDiskCleanup()
			defer func() {
				if !cleanupAttachedDisk {
					return
				}
				if diskCleanup.retain {
					ensureAttached, attachErr := hyperv.BuildLinuxImageBuilderAttachScript(hyperv.LinuxImageBuilderAttachParams{
						VMName: plan.BuilderVMName, VHDXPath: stagedVHDX,
						StatePath: paths.StatePath, DiskSizeGB: plan.DiskSizeGB,
					})
					if attachErr == nil {
						_, _, _ = runPS(context.Background(), reg, pool, target, ensureAttached, vmDefaultTimeoutSec)
					}
				}
				cleanupScript, cleanupErr := hyperv.BuildLinuxImageBuilderDetachScript(hyperv.LinuxImageBuilderDetachParams{
					VMName: plan.BuilderVMName, VHDXPath: stagedVHDX, StatePath: paths.StatePath,
					Retain: diskCleanup.retain, Reason: diskCleanup.reason,
				})
				if cleanupErr == nil {
					_, _, _ = runPS(context.Background(), reg, pool, target, cleanupScript, vmDefaultTimeoutSec)
				}
			}()
			attachOut, _, err := runPS(ctx, reg, pool, target, attachScript, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("attach exact operation-owned VHDX to builder: %v", err)), nil
			}
			var attached struct {
				ControllerLocation int `json:"controller_location"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(attachOut)), &attached); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse builder disk attachment identity: %v", err)), nil
			}
			builderTarget, err = startAndVerifyLinuxImageBuilder(ctx, plan, target, reg, pool)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			transformPayload, _ := hyperv.BuildLinuxImageBuilderTransformScript(hyperv.LinuxImageBuilderTransformParams{
				StatePath: linuxImageBuilderStatePath, ExpectedSizeBytes: converted.VirtualSize,
				ExpectedTargetLocation: attached.ControllerLocation,
			})
			transformScript, _ := hyperv.BuildLinuxImageBuilderUserTaskScript(transformPayload, linuxImageBuilderUserTaskTimeoutSec)
			transformOut, _, err := runLinuxImageBuilderUserScript(
				ctx, plan, reg, pool, builderTarget, creds, transformScript, vmDefaultTimeoutSec,
			)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("run WSL2 filesystem transform inside builder: %v", err)), nil
			}
			var transformed struct {
				Status       string `json:"status"`
				SafeToDetach bool   `json:"safe_to_detach"`
				Error        string `json:"error"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(transformOut)), &transformed); err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("parse builder transform result: %v", err)), nil
			}
			detachAllowed := diskCleanup.acceptVerifiedTransform(
				transformed.Status, transformed.SafeToDetach, transformed.Error,
			)
			detachScript, _ := hyperv.BuildLinuxImageBuilderDetachScript(hyperv.LinuxImageBuilderDetachParams{
				VMName: plan.BuilderVMName, VHDXPath: stagedVHDX, StatePath: paths.StatePath,
				Retain: !detachAllowed, Reason: diskCleanup.reason,
			})
			detachOut, _, detachErr := runPS(ctx, reg, pool, target, detachScript, vmDefaultTimeoutSec)
			if detachErr != nil {
				diskCleanup.retainForFailure(fmt.Sprintf("disk detach transport or agent failure: %v", detachErr))
				opErr = detachErr
				return mcp.NewToolResultError(fmt.Sprintf("stop builder and reconcile exact staging disk: %v", detachErr)), nil
			}
			cleanupAttachedDisk = false
			if !detachAllowed {
				opErr = fmt.Errorf("builder filesystem transform retained diagnostic state: %s", transformed.Error)
				return mcp.NewToolResultError(fmt.Sprintf(
					"Linux image preparation requires diagnosis; the builder is stopped and exact operation-disk state is explicit: %s\n%s",
					transformed.Error, jsonExtract(detachOut),
				)), nil
			}

			hashScript, _ := hyperv.BuildLinuxImageHashScript(stagedVHDX)
			hashOut, _, err := runPS(ctx, reg, pool, target, hashScript, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("hash transformed VHDX: %v", err)), nil
			}
			var hashed struct {
				SHA256 string `json:"sha256"`
			}
			if err := json.Unmarshal([]byte(jsonExtract(hashOut)), &hashed); err != nil || len(hashed.SHA256) != 64 {
				opErr = fmt.Errorf("parse transformed VHDX SHA256: %v", err)
				return mcp.NewToolResultError(opErr.Error()), nil
			}
			metadata := linuximage.ImageMetadata{
				SchemaVersion: linuximage.TransformSchema, CacheKey: paths.CacheKey,
				Source: linuximage.FixedSource(), ImageSHA256: imageHash, PreparedSHA256: hashed.SHA256,
				DiskSizeGB: plan.DiskSizeGB, PreparedVHDX: paths.PreparedVHDXPath,
				BuilderProfile: plan.ImageBuilderProfile, BuilderProfileFingerprint: plan.BuilderProfileFingerprint,
				Verification: verification, PublishedAt: time.Now().UTC(),
			}
			publish, err := hyperv.BuildLinuxImagePublishScript(hyperv.LinuxImagePublishParams{
				StagedVHDX: stagedVHDX, FinalVHDX: paths.PreparedVHDXPath,
				MetadataPath: paths.MetadataPath, StatePath: paths.StatePath, Metadata: metadata,
			})
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(err.Error()), nil
			}
			out, _, err = runPS(ctx, reg, pool, target, publish, vmDefaultTimeoutSec)
			if err != nil {
				opErr = err
				return mcp.NewToolResultError(fmt.Sprintf("publish prepared Linux image: %v", err)), nil
			}
			if plan.DeleteBuilderAfterPrepare {
				if err := deleteLinuxImageBuilder(ctx, plan, reg, pool, defaults, auditLog, enrollment); err != nil {
					opErr = err
					return mcp.NewToolResultError(fmt.Sprintf("image published, but builder cleanup failed: %v", err)), nil
				}
			}
			return vmResult("**Linux image preparation complete** — Canonical's signed Azure VHD was host-converted, edited only inside the nested WSL2 builder, detached, hashed, and published read-only.", jsonExtract(out)), nil
		}
		return LeaseGate(leaseCfg, extractTarget("target"), execute)(ctx, gatedReq)
	}
}

func getLinuxImageStatusHandler(reg *registry.Registry, pool *agentclient.Pool, defaults *vmconfig.Store, creds *credentials.Store) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		plan, target, err := resolveLinuxImagePlan(req, reg, defaults, creds)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		script, err := hyperv.BuildLinuxImageStatusScript(plan.ImageCacheRoot, plan.DiskSizeGB)
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		out, _, err := runPS(ctx, reg, pool, target, script, vmDefaultTimeoutSec)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("get Linux image status: %v", err)), nil
		}
		return vmResult("**Linux image preparation status**", jsonExtract(out)), nil
	}
}

func resolveLinuxImagePlan(req mcp.CallToolRequest, reg *registry.Registry, defaults *vmconfig.Store, creds *credentials.Store) (linuxImagePlan, Target, error) {
	requestedTarget := strings.TrimSpace(req.GetString("target", ""))
	profile, profileName, err := defaults.ResolveLinuxForTarget(req.GetString("profile", ""), requestedTarget)
	if err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	targetName := requestedTarget
	if targetName == "" {
		targetName = strings.TrimSpace(profile.Target)
	}
	if targetName == "" {
		targetName = "localhost"
	}
	cacheRoot := strings.TrimSpace(req.GetString("image_cache_root", ""))
	if cacheRoot == "" {
		cacheRoot = strings.TrimSpace(profile.ImageCacheRoot)
	}
	if cacheRoot == "" {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_cache_root is required explicitly or in a Linux VM profile")
	}
	cleanRoot, err := winpath.CleanAbsolute(cacheRoot)
	if err != nil || cleanRoot != cacheRoot {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_cache_root must be a clean absolute Windows host path")
	}
	diskSizeValue := profile.DiskSizeGB
	if value, ok := numericArgument(req.GetArguments()["disk_size_gb"]); ok {
		diskSizeValue = value
	}
	if diskSizeValue <= 0 {
		diskSizeValue = 64
	}
	if math.Trunc(diskSizeValue) != diskSizeValue {
		return linuxImagePlan{}, Target{}, fmt.Errorf("disk_size_gb must be an integer")
	}
	diskSizeGB := int(diskSizeValue)
	if err := linuximage.ValidateDiskSizeGB(diskSizeGB); err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	if err := validateFixedLinuxProfile(profile); err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	builderProfileName := strings.TrimSpace(req.GetString("image_builder_profile", ""))
	if builderProfileName == "" {
		builderProfileName = strings.TrimSpace(profile.ImageBuilderProfile)
	}
	if builderProfileName == "" {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile is required in the request or Linux VM profile before any download or host mutation")
	}
	builderProfile, resolvedBuilderName, err := defaults.ResolveWindows(builderProfileName)
	if err != nil {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q: %w", builderProfileName, err)
	}
	if resolvedBuilderName == "" {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q was not found", builderProfileName)
	}
	if guestOS, guestErr := builderProfile.EffectiveGuestOS(); guestErr != nil || guestOS != vmconfig.GuestOSWindows {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q must reference a Windows profile", builderProfileName)
	}
	if builderProfile.Target != "" && !strings.EqualFold(builderProfile.Target, targetName) {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q targets %q, not Linux image host %q", builderProfileName, builderProfile.Target, targetName)
	}
	for field, value := range map[string]string{
		"base_vhd": builderProfile.BaseVHD, "vm_root": builderProfile.VMRoot,
		"vswitch": builderProfile.VSwitch, "admin_password_credential": builderProfile.AdminCredential,
	} {
		if strings.TrimSpace(value) == "" {
			return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q is incomplete: missing %s", builderProfileName, field)
		}
	}
	if builderProfile.ExposeVirtualizationExtensions == nil || !*builderProfile.ExposeVirtualizationExtensions {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q must set expose_virtualization_extensions=true", builderProfileName)
	}
	if builderProfile.DynamicMemory {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q must set dynamic_memory=false", builderProfileName)
	}
	if builderProfile.VirtualizationBasedSecurityOptOut == nil || !*builderProfile.VirtualizationBasedSecurityOptOut {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q must set virtualization_based_security_opt_out=true", builderProfileName)
	}
	if creds == nil {
		return linuxImagePlan{}, Target{}, fmt.Errorf("credential store unavailable while validating image_builder_profile")
	}
	builderCredential, err := creds.Get(builderProfile.AdminCredential)
	if err != nil {
		return linuxImagePlan{}, Target{}, fmt.Errorf("image_builder_profile %q credential %q is unavailable: %w", builderProfileName, builderProfile.AdminCredential, err)
	}
	if strings.TrimSpace(builderCredential.Username) == "" || builderCredential.Password == "" {
		return linuxImagePlan{}, Target{}, fmt.Errorf(
			"image_builder_profile %q credential %q must contain username and password",
			builderProfileName, builderProfile.AdminCredential,
		)
	}
	builderVMName := strings.TrimSpace(req.GetString("builder_vm_name", ""))
	if builderVMName == "" {
		builderVMName = strings.TrimSpace(profile.BuilderVMName)
	}
	if builderVMName == "" {
		builderVMName = defaultLinuxImageBuilderName(targetName)
	}
	if err := validateVMPathName(builderVMName); err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	deleteBuilder := boolValue(profile.DeleteBuilderAfterPrepare, false)
	if value, ok := req.GetArguments()["delete_builder_after_prepare"].(bool); ok {
		deleteBuilder = value
	}
	source := linuximage.FixedSource()
	if err := source.Validate(); err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	_, statePath, downloadDir, err := linuximage.SourceStatePaths(cacheRoot, diskSizeGB)
	if err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	stagingID, err := randomStagingID()
	if err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	target, err := resolvePlanTarget(targetName, reg)
	if err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	builder := planFromProfile(builderProfile, resolvedBuilderName)
	builder.Target = target.Name
	builder.Name = builderVMName
	builder.Hostname = windowsHostname(builderVMName)
	builder.RegisterWithLabLink = true
	builder.LabLinkNodeName = linuxImageBuilderNodeName(target.Name, builderVMName)
	builder.LabLinkRole = "linux-image-builder"
	if builder.LabLinkPort <= 0 {
		builder.LabLinkPort = 9091
	}
	derivePlanPaths(&builder)
	metadata, err := hyperv.LinuxImageBuilderManagedMetadata(hyperv.LinuxImageBuilderMetadata{
		SchemaVersion: 1, Target: target.Name, Profile: resolvedBuilderName,
		ProfileFingerprint: builderProfileFingerprint(builderProfile),
		VMName:             builderVMName, NodeName: builder.LabLinkNodeName,
	})
	if err != nil {
		return linuxImagePlan{}, Target{}, err
	}
	builder.ManagedMetadata = metadata
	return linuxImagePlan{
		Profile: profileName, Target: target.Name, ImageCacheRoot: cacheRoot,
		Source: source, DiskSizeGB: diskSizeGB, TransformSchema: linuximage.TransformSchema,
		StatePath: statePath, DownloadDir: downloadDir, StagingID: stagingID,
		Verification: string(linuximage.VerificationPending), ImageBuilderProfile: resolvedBuilderName,
		BuilderProfileFingerprint: builderProfileFingerprint(builderProfile),
		BuilderVMName:             builderVMName, BuilderNodeName: builder.LabLinkNodeName,
		DeleteBuilderAfterPrepare: deleteBuilder, Builder: builder,
	}, target, nil
}

func builderMetadata(plan linuxImagePlan) hyperv.LinuxImageBuilderMetadata {
	return hyperv.LinuxImageBuilderMetadata{
		SchemaVersion: 1, Target: plan.Target, Profile: plan.ImageBuilderProfile,
		ProfileFingerprint: plan.BuilderProfileFingerprint,
		VMName:             plan.BuilderVMName, NodeName: plan.BuilderNodeName,
	}
}

func ensureLinuxImageBuilder(
	ctx context.Context,
	plan linuxImagePlan,
	host Target,
	reg *registry.Registry,
	pool *agentclient.Pool,
	creds *credentials.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
) (Target, error) {
	inspectScript, _ := hyperv.BuildInspectLinuxImageBuilderScript(plan.BuilderVMName, builderMetadata(plan))
	out, _, err := runPS(ctx, reg, pool, host, inspectScript, vmDefaultTimeoutSec)
	if err != nil {
		return Target{}, fmt.Errorf("inspect reusable Linux image builder: %w", err)
	}
	var inspected struct {
		Exists                            bool `json:"exists"`
		ExposeVirtualizationExtensions    bool `json:"expose_virtualization_extensions"`
		DynamicMemory                     bool `json:"dynamic_memory"`
		VirtualizationBasedSecurityOptOut bool `json:"virtualization_based_security_opt_out"`
	}
	if err := json.Unmarshal([]byte(jsonExtract(out)), &inspected); err != nil {
		return Target{}, fmt.Errorf("parse builder inspection: %w", err)
	}
	if !inspected.Exists {
		result, err := executeWindowsVMPlan(ctx, plan.Builder, reg, pool, creds, auditLog, enrollment)
		if err != nil {
			return Target{}, err
		}
		if result == nil || result.IsError {
			return Target{}, fmt.Errorf("create Windows image builder failed: %s", toolResultText(result))
		}
	} else if !inspected.ExposeVirtualizationExtensions {
		return Target{}, fmt.Errorf("existing operation-owned builder %q does not expose virtualization extensions", plan.BuilderVMName)
	} else if inspected.DynamicMemory {
		return Target{}, fmt.Errorf("existing operation-owned builder %q uses dynamic memory", plan.BuilderVMName)
	} else if !inspected.VirtualizationBasedSecurityOptOut {
		return Target{}, fmt.Errorf("existing operation-owned builder %q is not opted out of virtualization-based security", plan.BuilderVMName)
	}
	return startAndVerifyLinuxImageBuilder(ctx, plan, host, reg, pool)
}

func startAndVerifyLinuxImageBuilder(ctx context.Context, plan linuxImagePlan, host Target, reg *registry.Registry, pool *agentclient.Pool) (Target, error) {
	startScript, _ := hyperv.BuildLinuxImageBuilderStartScript(plan.BuilderVMName)
	out, _, err := runPS(ctx, reg, pool, host, startScript, 1000)
	if err != nil {
		return Target{}, fmt.Errorf("start reusable Linux image builder: %w", err)
	}
	var info startedVMInfo
	if err := json.Unmarshal([]byte(jsonExtract(out)), &info); err != nil {
		return Target{}, fmt.Errorf("parse builder address: %w", err)
	}
	if err := verifyEnrolledVM(ctx, plan.Builder, info, reg, pool, true); err != nil {
		return Target{}, fmt.Errorf("verify Linux image builder enrollment: %w", err)
	}
	return resolvePlanTarget(plan.BuilderNodeName, reg)
}

func runLinuxImageBuilderUserScript(
	ctx context.Context,
	plan linuxImagePlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
	builder Target,
	creds *credentials.Store,
	script string,
	timeoutSec int,
) (string, int, error) {
	if creds == nil {
		return "", -1, fmt.Errorf("credential store unavailable for Linux image builder user task")
	}
	profileName := strings.TrimSpace(plan.Builder.AdminPasswordCredential)
	credential, err := creds.Get(profileName)
	if err != nil {
		return "", -1, fmt.Errorf("resolve Linux image builder credential %q: %w", profileName, err)
	}
	username := strings.TrimSpace(credential.Username)
	if username == "" || credential.Password == "" {
		return "", -1, fmt.Errorf("Linux image builder credential %q must contain username and password", profileName)
	}
	env := map[string]string{
		"LABLINK_BUILDER_USERNAME": username,
		"LABLINK_BUILDER_PASSWORD": credential.Password,
	}
	secretValues := []string{credential.Password}
	defer func() {
		env["LABLINK_BUILDER_USERNAME"] = ""
		env["LABLINK_BUILDER_PASSWORD"] = ""
		secretValues[0] = ""
	}()
	return runPSWithEnv(ctx, reg, pool, builder, script, timeoutSec, env, secretValues)
}

func rebootLinuxImageBuilder(ctx context.Context, builder Target, pool *agentclient.Pool) error {
	if builder.IsLocal || builder.Node == nil {
		return fmt.Errorf("Linux image builder must be an enrolled remote Windows VM")
	}
	node := builder.Node
	client, err := pool.GetClient(node.Address, node.TLSServerName)
	if err != nil {
		return fmt.Errorf("connect to builder for reboot: %w", err)
	}
	rebootCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.Execute(rebootCtx, &pb.ExecuteRequest{
		Command: "shutdown /r /t 2 /f", Shell: "cmd", TimeoutSeconds: 5,
	})
	if err == nil {
		_, _, _, _, _ = collectStreamOutput(stream)
	}
	pool.ResetConnection(node.Address)
	deadline := time.Now().Add(2 * time.Minute)
	consecutiveFailures := 0
	const builderRebootPollInterval = time.Second
	for time.Now().Before(deadline) {
		conn, dialErr := rebootNodesDial(node.Address, rebootNodesConnectTimeout)
		if dialErr != nil {
			consecutiveFailures++
			if consecutiveFailures >= rebootNodesDownConfirmations {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(10 * time.Second):
					return nil
				}
			}
		} else {
			consecutiveFailures = 0
			_ = conn.Close()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(builderRebootPollInterval):
		}
	}
	return fmt.Errorf("builder reboot was requested but the enrolled agent never went offline")
}

func deleteLinuxImageBuilder(
	ctx context.Context,
	plan linuxImagePlan,
	reg *registry.Registry,
	pool *agentclient.Pool,
	defaults *vmconfig.Store,
	auditLog *audit.Log,
	enrollment VMEnrollmentConfig,
) error {
	req := mcp.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"target": plan.Target, "name": plan.BuilderVMName, "managed_root": plan.Builder.VMRoot,
		"dry_run": false, "force_stop": true, "delete_storage": true,
		"unregister_node": true, "lablink_node_name": plan.BuilderNodeName, "delete_identity": true,
	}
	result, err := deleteVMHandler(reg, pool, defaults, auditLog, enrollment)(ctx, req)
	if err != nil {
		return err
	}
	if result == nil || result.IsError {
		return fmt.Errorf("%s", toolResultText(result))
	}
	return nil
}

func builderContainsWindowsPath(paths []string, wanted string) bool {
	for _, path := range paths {
		if sameWindowsPath(path, wanted) {
			return true
		}
	}
	return false
}

func defaultLinuxImageBuilderName(target string) string {
	suffix := windowsHostname(strings.ReplaceAll(target, "localhost", "local"))
	if suffix == "" {
		suffix = "LOCAL"
	}
	name := "LL-LNXBLD-" + suffix
	if len(name) > 64 {
		name = name[:64]
	}
	return strings.TrimRight(name, "-")
}

func linuxImageBuilderNodeName(target, vmName string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(target)) + "\x00" + strings.ToLower(strings.TrimSpace(vmName))))
	return "LLB-" + hex.EncodeToString(sum[:5])
}

func builderProfileFingerprint(profile vmconfig.Profile) string {
	data, _ := json.Marshal(profile)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func builderIdentityLockKey(target, vmName string) string {
	sum := sha256.Sum256([]byte(
		strings.ToLower(strings.TrimSpace(target)) + "\x00" +
			strings.ToLower(strings.TrimSpace(vmName)),
	))
	return hex.EncodeToString(sum[:])
}

func validateFixedLinuxProfile(profile vmconfig.Profile) error {
	checks := []struct {
		name string
		got  string
		want string
	}{
		{"distribution", profile.Distribution, linuximage.Distribution},
		{"release", profile.Release, linuximage.Release},
		{"architecture", profile.Architecture, linuximage.Architecture},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.got) != "" && !strings.EqualFold(strings.TrimSpace(check.got), check.want) {
			return fmt.Errorf("Linux profile %s %q is unsupported; MVP requires %q", check.name, check.got, check.want)
		}
	}
	return nil
}

func randomStagingID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", fmt.Errorf("create staging ID: %w", err)
	}
	return hex.EncodeToString(value[:]), nil
}
