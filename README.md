# SCCM Application Automation Pipeline

A metadata-driven, low-touch application factory for Microsoft Endpoint Configuration Manager (MECM / SCCM).

Automate the complete application lifecycle: download from winget, create SCCM apps, deploy to collections - all from a simple JSON config.

## Features

- **One-command deployment** - Stage, create, and deploy apps with a single script
- **Metadata-driven** - All automation driven by auto-generated `app.json`
- **Smart detection** - MSI ProductCode, registry DisplayName, or file-based fallback
- **Automatic supersedence** - New versions automatically supersede old with uninstall
- **User-scope warnings** - Detects per-user installers and warns about potential issues
- **Robust fallbacks** - Multiple detection methods, URL fallback for winget failures
- **Bulk processing** - Process dozens of apps from a JSON config file
- **Idempotent** - Safe to re-run without duplicating resources

## Quick Start

### Option 1: Interactive Setup (Recommended)

Run the setup wizard to configure for your environment:

```powershell
.\Initialize-AppPipeline.ps1
```

This will:
- Validate your SCCM connection
- Configure your content share and distribution point
- Help you add applications interactively
- Generate your `apps-config.json`

### Option 2: Manual Configuration

1. Copy `apps-config.example.json` to `apps-config.json`
2. Edit settings for your environment
3. Add your applications

### Run the Pipeline

```powershell
# Process all applications
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json

# Preview without making changes
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -WhatIf

# Process a single app
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -AppFilter "VLC"
```

## Scripts

| Script | Purpose |
|--------|---------|
| `Initialize-AppPipeline.ps1` | Interactive setup wizard for new environments |
| `Invoke-AppPipeline.ps1` | Main orchestrator - process apps from JSON config |
| `Stage-WingetToSCCM.ps1` | Download installer via winget, generate metadata |
| `New-CMAppFromTemplate.ps1` | Create SCCM Application from metadata |
| `Deploy-Application.ps1` | Distribute content and deploy to collection |

## Configuration

### apps-config.json

```json
{
  "Settings": {
    "SiteCode": "ABC",
    "ContentRoot": "\\\\FileServer\\SCCM-Source\\Applications",
    "DPName": "sccm-dp.contoso.com",
    "LimitingCollection": "All Systems",
    "DefaultPurpose": "Available"
  },
  "Applications": [
    {
      "WingetId": "VideoLAN.VLC",
      "AppName": "VLC",
      "Collection": "SCCM Software VLC"
    },
    {
      "WingetId": "7zip.7zip",
      "AppName": "7-Zip",
      "Collection": "SCCM Software 7-Zip"
    },
    {
      "WingetId": "Git.Git",
      "AppName": "Git",
      "Version": "2.47.0",
      "Collection": "Developer PCs",
      "Purpose": "Required"
    }
  ]
}
```

### Application Options

| Property | Required | Description |
|----------|----------|-------------|
| `WingetId` | Yes | Winget package ID (e.g., `VideoLAN.VLC`) |
| `AppName` | No | Display name (defaults to last part of WingetId) |
| `Version` | No | Pin to specific version (defaults to latest) |
| `Collection` | No | Target collection name |
| `Purpose` | No | `Available` or `Required` |
| `ExeSilentArgs` | No | Custom silent install arguments |

## How It Works

### Pipeline Flow

```
1. STAGE          2. CREATE           3. DEPLOY
   │                  │                   │
   ▼                  ▼                   ▼
┌─────────┐      ┌──────────┐       ┌──────────┐
│ winget  │      │  SCCM    │       │  SCCM    │
│download │ ──▶  │  App +   │  ──▶  │  Deploy  │
│ + meta  │      │   DT     │       │  to DP   │
└─────────┘      └──────────┘       └──────────┘
     │                │
     ▼                ▼
  app.json      Supersedence
               (auto-configured)
```

### Detection Methods

The pipeline automatically selects the best detection method:

| Installer | Detection | How It Works |
|-----------|-----------|--------------|
| MSI | ProductCode | Checks for MSI GUID in registry (most reliable) |
| EXE | Flexible | Registry DisplayName + version with fallbacks |

**Flexible Detection** (for EXE installers):
1. Checks HKLM and HKCU registry for DisplayName
2. Uses loose matching (`-like '*AppName*'`)
3. Graceful version comparison (handles weird formats)
4. Falls back to file-based detection if registry fails

### User-Scope Detection

The pipeline detects per-user installers (apps that install to `%AppData%`) and warns you:

```
[WARN] USER-SCOPED APP DETECTED: Discord
[WARN]   This app installs to the user profile (e.g., %AppData%)
[WARN]   SCCM runs as SYSTEM, so detection may fail
```

## Folder Structure

```
\\FileServer\SCCM-Source\
├── Applications\
│   ├── 7-Zip\
│   │   └── 24.09\
│   │       ├── 7z2409-x64.msi
│   │       └── app.json
│   ├── VLC\
│   │   └── 3.0.21\
│   │       ├── vlc-3.0.21-win64.exe
│   │       └── app.json
│   └── ...
└── Scripts\
    ├── Initialize-AppPipeline.ps1
    ├── Invoke-AppPipeline.ps1
    ├── Stage-WingetToSCCM.ps1
    ├── New-CMAppFromTemplate.ps1
    ├── Deploy-Application.ps1
    └── apps-config.json
```

## Individual Script Usage

### Stage an Application

```powershell
.\Stage-WingetToSCCM.ps1 `
    -PackageId "VideoLAN.VLC" `
    -AppName "VLC" `
    -Version "3.0.21" `
    -SccmContentRoot "\\FileServer\SCCM-Source\Applications"
```

### Create SCCM Application

```powershell
.\New-CMAppFromTemplate.ps1 `
    -SiteCode "ABC" `
    -NewAppName "VLC" `
    -NewVersion "3.0.21" `
    -AppContentRoot "\\FileServer\SCCM-Source\Applications"
```

### Deploy to Collection

```powershell
.\Deploy-Application.ps1 `
    -SiteCode "ABC" `
    -AppName "VLC - 3.0.21" `
    -CollectionName "SCCM Software VLC" `
    -DPName "sccm-dp.contoso.com" `
    -AutoCreateCollection
```

## Pipeline Options

```powershell
# Stage only (download installers, don't create SCCM apps)
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -StageOnly

# Create only (assumes already staged)
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -CreateOnly

# Deploy only (assumes apps already created)
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -DeployOnly

# Filter to specific apps
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -AppFilter "VLC*"
.\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -AppFilter "*Office*"
```

## Supersedence

When you create a new version of an application, the pipeline automatically:

1. Finds previous versions by name pattern (`AppName - *`)
2. Creates supersedence relationship
3. Configures uninstall of old version

### Override Supersedence

```powershell
# Don't uninstall old version
.\New-CMAppFromTemplate.ps1 ... -NoUninstall

# Disable supersedence entirely
.\New-CMAppFromTemplate.ps1 ... -NoSupersedence
```

## Requirements

- Windows PowerShell 5.1+
- SCCM Console installed (provides ConfigurationManager module)
- [winget CLI](https://github.com/microsoft/winget-cli) for downloading packages
- Network access to SCCM content share
- Appropriate SCCM permissions (Application Administrator or similar)

## Troubleshooting

### Common Issues

**"Could not determine version from winget"**
- The winget ID may be incorrect. Run `winget search <appname>` to find the correct ID.
- Some apps have versioned IDs (e.g., `GIMP.GIMP.3` instead of `GIMP.GIMP`)

**"winget download failed"**
- The pipeline will automatically try URL fallback from the winget manifest
- Check winget logs: `%LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir`

**App installs but shows "Not Detected" (0x87D00324)**
- Check if it's a per-user installer (installs to %AppData%)
- Verify the DisplayName in registry matches what detection is looking for
- Try switching to DisplayName-only detection in app.json

**Object Lock Errors**
- Use the lock utility: `.\Tools\Clear-CMObjectLock.ps1 -SiteCode ABC -ListOnly`

### Logs

The pipeline creates detailed logs:
```
\\FileServer\SCCM-Source\Scripts\pipeline-20240115-143052.log
```

## Tools

Additional utilities in the `Tools` folder:

| Tool | Purpose |
|------|---------|
| `Clear-CMObjectLock.ps1` | Clear orphaned SCCM object locks |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

MIT License - Use freely in your environment.
