# Local Backup and Restore

Use a local Git bundle when no remote has been approved. Do not commit bundles into this
repository and do not push without owner approval.

## Create Bundle

```powershell
$backupRoot = Join-Path (Split-Path -Parent (Get-Location).Path) "aethelgard_backups"
New-Item -ItemType Directory -Force -Path $backupRoot
git bundle create (Join-Path $backupRoot "aethelgard-main-YYYYMMDD-HHMM.bundle") --all
```

## Verify Bundle

```powershell
$backupRoot = Join-Path (Split-Path -Parent (Get-Location).Path) "aethelgard_backups"
git bundle verify (Join-Path $backupRoot "aethelgard-main-YYYYMMDD-HHMM.bundle")
```

## Clone From Bundle

```powershell
$backupRoot = Join-Path (Split-Path -Parent (Get-Location).Path) "aethelgard_backups"
git clone (Join-Path $backupRoot "aethelgard-main-YYYYMMDD-HHMM.bundle") `
    (Join-Path (Split-Path -Parent (Get-Location).Path) "aethelgard_restore_test")
```

## Restore Notes

- A bundle contains committed refs, not untracked files or ignored reports.
- Create the bundle after green validation and after the commit that should be backed up.
- Keep customer reports, sample inputs, and bundles outside the repository unless explicitly approved.
