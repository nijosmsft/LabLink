# Releasing LabLink

The canonical release path is the GitHub Actions workflow at
`.github/workflows/release.yml` — push a `vX.Y.Z` tag and CI builds the
release zip, computes `SHA256SUMS.txt`, and publishes a GitHub Release.

To build the same release zip locally (handy when iterating on the
packaging step or for an air-gapped build):

```powershell
.\scripts\build-release.ps1 -Version v0.3.0
```

Artifacts land under `.\release\`. The script is what the GitHub Actions
release workflow runs.
