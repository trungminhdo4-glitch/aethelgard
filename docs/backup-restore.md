# Local Backup and Restore

Use a local Git bundle when no remote has been approved. Do not commit bundles into this
repository and do not push without owner approval.

## Create Bundle

```powershell
mkdir D:\projects\aethelgard_backups -Force
git bundle create D:\projects\aethelgard_backups\aethelgard-main-YYYYMMDD-HHMM.bundle --all
```

## Verify Bundle

```powershell
git bundle verify D:\projects\aethelgard_backups\aethelgard-main-YYYYMMDD-HHMM.bundle
```

## Clone From Bundle

```powershell
git clone D:\projects\aethelgard_backups\aethelgard-main-YYYYMMDD-HHMM.bundle D:\projects\aethelgard_restore_test
```

## Restore Notes

- A bundle contains committed refs, not untracked files or ignored reports.
- Create the bundle after green validation and after the commit that should be backed up.
- Keep customer reports, sample inputs, and bundles outside the repository unless explicitly approved.
