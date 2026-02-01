<#
New-CMAppFromTemplate.ps1
Script 2 â€“ Create MECM Application + Script DT from metadata (app.json)

GOAL
- Script 1 stages content + writes app.json
- Script 2 consumes app.json and creates:
    - NEW Application: <App> - <Version>
    - Script Installer DT
    - Detection based on metadata (or marker fallback)
- Script 3 distributes + deploys

FEATURES
- Metadata-first (app.json)
- Installer types: EXE / MSI
- Detection modes:
    - Marker
    - MsiProductCode
    - UninstallDisplayNameVersion
- IMPORTANT FIX:
    If installer is EXE and detection is Marker, install is wrapped:
      - Run EXE
      - If exit code 0 => write marker
      - Return installer exit code
    This prevents 0x87D00324 "installed but not detected".
- Idempotent (if app+DT exists, exits cleanly)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SiteCode,

    [Parameter(Mandatory)]
    [string]$NewAppName,

    [Parameter(Mandatory)]
    [string]$NewVersion,

    [string]$Publisher = "IT Department",

    # Production content root - UPDATE THIS TO YOUR SCCM CONTENT SHARE
    [Parameter(Mandatory)]
    [string]$AppContentRoot,

    # Optional: console folder path (must already exist)
    [string]$DestinationConsoleFolderPath,

    # Optional overrides (rare; normally driven by app.json)
    [string]$InstallCommandLine,
    [string]$UninstallCommandLine,

    # Phase 2 override: disable supersedence even if enabled by default/app.json
    [switch]$NoSupersedence,

    # Phase 2 override: keep old version installed (default is to uninstall superseded apps)
    [switch]$NoUninstall
)

# Import shared helpers
$helperModule = Join-Path $PSScriptRoot "SCCMPipelineHelpers.psm1"
if (Test-Path $helperModule) {
    Import-Module $helperModule -Force
}

# Default timeout for installer execution (2 hours)
$script:InstallerTimeout = 7200

# Validate inputs early
try {
    if (Get-Command Assert-SafeAppName -ErrorAction SilentlyContinue) {
        Assert-SafeAppName -Name $NewAppName | Out-Null
    }
    if (Get-Command Assert-SafeVersion -ErrorAction SilentlyContinue) {
        Assert-SafeVersion -Version $NewVersion | Out-Null
    }
} catch {
    throw "Input validation failed: $($_.Exception.Message)"
}

#region Logging / CM Connection

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet("INFO","WARN","ERROR","OK")]
        [string]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO"  { Write-Host "[$ts] [INFO ] $Message" }
        "WARN"  { Write-Host "[$ts] [WARN ] $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[$ts] [ERROR] $Message" -ForegroundColor Red }
        "OK"    { Write-Host "[$ts] [ OK  ] $Message" -ForegroundColor Green }
    }
}

function Connect-CMSite {
    param([Parameter(Mandatory)][string]$SiteCode)

    $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
    if (-not (Test-Path $modulePath)) {
        throw "ConfigurationManager.psd1 not found. Run on a machine with MECM console installed."
    }

    Import-Module $modulePath -Force

    if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteCode | Out-Null
    }

    Set-Location "$SiteCode`:"
}

#endregion

#region Detection script builders

function New-DetectScript_Marker {
    param([Parameter(Mandatory)][string]$MarkerPath)
    @"
if (Test-Path -LiteralPath '$MarkerPath') { 'Installed' }
"@
}

function New-DetectScript_MsiProductCode {
    param([Parameter(Mandatory)][string]$ProductCode)

    # Robust: checks uninstall hives where MSI product codes commonly appear as key names (PSChildName)
    @"
`$keys = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
`$hit = Get-ItemProperty `$keys -ErrorAction SilentlyContinue |
  Where-Object { `$_.PSChildName -eq '$ProductCode' } |
  Select-Object -First 1
if (`$hit) { 'Installed' }
"@
}

function New-DetectScript_UninstallDisplayNameVersion {
    param(
        [Parameter(Mandatory)][string]$DisplayName,
        [Parameter(Mandatory)][string]$MinVersion
    )

    # SCCM script detection: output any text = detected, no output = not detected
    @"
`$keys = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
`$app = Get-ItemProperty `$keys -ErrorAction SilentlyContinue |
 Where-Object { `$_.DisplayName -eq '$DisplayName' } |
 Select-Object -First 1

if (`$app -and `$app.DisplayVersion) {
  try {
    `$cur = [version]`$app.DisplayVersion
    `$min = [version]'$MinVersion'
    if (`$cur -ge `$min) { 'Installed' }
  } catch {
    # Fallback to string compare (best-effort for non-standard versions)
    if (`$app.DisplayVersion -ge '$MinVersion') { 'Installed' }
  }
}
"@
}

function New-DetectScript_UninstallDisplayName {
    <#
    .SYNOPSIS
        Detects app by DisplayName only (no version check).
        Use when version checking isn't reliable or needed.
    #>
    param(
        [Parameter(Mandatory)][string]$DisplayName
    )

    @"
`$keys = @(
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
`$app = Get-ItemProperty `$keys -ErrorAction SilentlyContinue |
 Where-Object { `$_.DisplayName -eq '$DisplayName' } |
 Select-Object -First 1

if (`$app) { 'Installed' }
"@
}

function New-DetectScript_FileBased {
    <#
    .SYNOPSIS
        Detects app by checking if a specific file exists.
        Useful as fallback when registry detection fails.
    #>
    param(
        [Parameter(Mandatory)][string]$FilePath
    )

    @"
if (Test-Path '$FilePath') { 'Installed' }
"@
}

function New-DetectScript_Flexible {
    <#
    .SYNOPSIS
        Creates a robust detection script with multiple fallback methods.
        Designed to work with ANY application, not just specific ones.

        Detection strategy (in order):
        1. File-based detection (most reliable if path known)
        2. Registry search using KEY WORDS from DisplayName (handles naming variations)
        3. Loose registry match on any part of the name

        Includes retry logic for apps that need time to finalize (e.g., Adobe).
        Returns 'Installed' if ANY method succeeds.
    #>
    param(
        [string]$DisplayName,
        [string]$MinVersion,
        [string]$FilePath
    )

    # Extract key words from DisplayName for flexible matching
    # "Adobe Acrobat Reader (64-bit)" -> @("Adobe", "Acrobat", "Reader")
    # This handles cases where registry name differs from winget name
    $keyWords = @()
    if ($DisplayName) {
        $keyWords = $DisplayName -replace '\(.*?\)', '' -replace '[^a-zA-Z0-9\s]', '' -split '\s+' |
            Where-Object { $_.Length -gt 2 } |  # Skip tiny words
            Select-Object -First 3  # Use first 3 significant words
    }
    $keyWordsString = ($keyWords | ForEach-Object { "'$_'" }) -join ', '

    $script = @"
# Flexible detection - works with any application
# Uses multiple methods to handle naming variations between winget and registry

function Test-AppInstalled {
  `$keys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )

"@

    # Method 1: File-based detection (most reliable)
    if ($FilePath) {
        $script += @"
  # Method 1: File-based detection (most reliable)
  if (Test-Path '$FilePath') { return `$true }

"@
    }

    # Method 2: Key word matching (handles naming variations)
    if ($keyWords.Count -gt 0) {
        $script += @"
  # Method 2: Key word matching (handles naming variations)
  # Looking for apps containing these key words: $keyWordsString
  `$keyWords = @($keyWordsString)

  `$allApps = Get-ItemProperty `$keys -ErrorAction SilentlyContinue | Where-Object { `$_.DisplayName }

  foreach (`$app in `$allApps) {
    `$name = `$app.DisplayName
    `$matchCount = 0

    foreach (`$word in `$keyWords) {
      if (`$name -like "*`$word*") { `$matchCount++ }
    }

    # If at least 2 key words match (or all if fewer than 2), consider it a match
    `$requiredMatches = [Math]::Min(2, `$keyWords.Count)
    if (`$matchCount -ge `$requiredMatches) {
"@
        if ($MinVersion) {
            $script += @"

      # Version check (flexible - don't fail on weird formats)
      try {
        if (`$app.DisplayVersion) {
          `$verString = `$app.DisplayVersion -replace '[^\d.].*', '' -replace '\.+', '.'
          if (`$verString -and `$verString -match '^\d') {
            `$cur = [version]`$verString
            `$min = [version]'$MinVersion'
            if (`$cur -ge `$min) { return `$true }
          } else {
            return `$true  # Can't parse version, but app exists
          }
        } else {
          return `$true  # No version in registry, but app found
        }
      } catch {
        return `$true  # Version comparison failed, but app exists
      }
"@
        } else {
            $script += @"

      return `$true
"@
        }
        $script += @"

    }
  }
"@
    }

    $script += @"

  return `$false
}

# Try detection with retry (helps with multi-stage installers like Adobe)
`$maxRetries = 3
`$retryDelay = 5

for (`$i = 1; `$i -le `$maxRetries; `$i++) {
  if (Test-AppInstalled) {
    'Installed'
    exit
  }
  if (`$i -lt `$maxRetries) {
    Start-Sleep -Seconds `$retryDelay
  }
}
"@

    return $script
}

function Convert-ToSortableVersion {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Version)

    # 1) Try .NET Version parsing first (handles 1.2, 1.2.3, 1.2.3.4)
    $verObj = $null
    if ([version]::TryParse($Version, [ref]$verObj)) {
        return @{ Kind = "DotNetVersion"; Value = $verObj }
    }

    # 2) Fallback: extract numeric parts so "24.07" or "1.2.8-test3" can still sort.
    #    Non-numeric becomes separators; we compare numeric arrays, then original string as tie-break.
    $nums = [regex]::Matches($Version, '\d+') | ForEach-Object { [int]$_.Value }
    if (-not $nums -or $nums.Count -eq 0) {
        $nums = @(0)
    }
    return @{ Kind = "NumericArray"; Value = $nums; Raw = $Version }
}

function Compare-Version {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$A,
        [Parameter(Mandatory)][string]$B
    )

    $va = Convert-ToSortableVersion -Version $A
    $vb = Convert-ToSortableVersion -Version $B

    if ($va.Kind -eq "DotNetVersion" -and $vb.Kind -eq "DotNetVersion") {
        return $va.Value.CompareTo($vb.Value)
    }

    # Convert DotNetVersion to numeric array for mixed comparisons
    if ($va.Kind -eq "DotNetVersion") {
        $v = $va.Value
        $arrA = @($v.Major, $v.Minor, $v.Build, $v.Revision) | Where-Object { $_ -ge 0 }
    } else {
        $arrA = @($va.Value)
    }

    if ($vb.Kind -eq "DotNetVersion") {
        $v = $vb.Value
        $arrB = @($v.Major, $v.Minor, $v.Build, $v.Revision) | Where-Object { $_ -ge 0 }
    } else {
        $arrB = @($vb.Value)
    }

    $max = [Math]::Max($arrA.Count, $arrB.Count)
    for ($i=0; $i -lt $max; $i++) {
        $x = if ($i -lt $arrA.Count) { $arrA[$i] } else { 0 }
        $y = if ($i -lt $arrB.Count) { $arrB[$i] } else { 0 }
        if ($x -lt $y) { return -1 }
        if ($x -gt $y) { return 1 }
    }

    # Tie-break by raw string
    return ($A).CompareTo($B)
}

function Get-PreviousAppForSupersedence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaseName,
        [Parameter(Mandatory)][string]$CurrentVersion,
        [string]$NamePrefix
    )

    if (-not $NamePrefix) { $NamePrefix = "$BaseName - " }

    # Find all apps that match the prefix
    $apps = Get-CMApplication -Fast -Name "$NamePrefix*" -ErrorAction SilentlyContinue
    if (-not $apps) { return $null }

    # Extract version suffix from the name (everything after the prefix)
    $candidates = foreach ($a in $apps) {
        if ($a.LocalizedDisplayName -eq "$BaseName - $CurrentVersion") { continue }
        if (-not ($a.LocalizedDisplayName -like "$NamePrefix*")) { continue }

        $suffix = $a.LocalizedDisplayName.Substring($NamePrefix.Length).Trim()
        if (-not $suffix) { continue }

        # Only consider versions lower than the current version
        if ((Compare-Version -A $suffix -B $CurrentVersion) -lt 0) {
            [pscustomobject]@{
                App      = $a
                Version  = $suffix
                Name     = $a.LocalizedDisplayName
            }
        }
    }

    if (-not $candidates) { return $null }

    # Return the highest version below current (manual compare to stay compatible with Windows PowerShell 5.1)
    $best = $null
    foreach ($c in $candidates) {
        if (-not $best) {
            $best = $c
            continue
        }
        if ((Compare-Version -A $c.Version -B $best.Version) -gt 0) {
            $best = $c
        }
    }

    return $best
}

function Ensure-CMSupersedence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$NewAppName,
        [Parameter(Mandatory)][string]$NewDtName,
        [Parameter(Mandatory)][string]$OldAppName,
        [Parameter(Mandatory)][string]$OldDtName,
        [bool]$UninstallOld = $true
    )

    $newApp = Get-CMApplication -Name $NewAppName -ErrorAction Stop
    $oldApp = Get-CMApplication -Name $OldAppName -ErrorAction Stop

    $newDt  = Get-CMDeploymentType -ApplicationName $NewAppName -ErrorAction Stop |
        Where-Object { $_.LocalizedDisplayName -ieq $NewDtName } | Select-Object -First 1

    # Try case-insensitive match for old DT (handles naming inconsistencies)
    $oldDt  = Get-CMDeploymentType -ApplicationName $OldAppName -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalizedDisplayName -ieq $OldDtName } | Select-Object -First 1

    # If exact match fails, try finding any DT for the old app
    if (-not $oldDt) {
        $oldDt = Get-CMDeploymentType -ApplicationName $OldAppName -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($oldDt) {
            Write-Log "Using DT '$($oldDt.LocalizedDisplayName)' for supersedence (expected '$OldDtName')" "WARN"
        }
    }

    if (-not $newDt -or -not $oldDt) {
        Write-Log "Could not resolve deployment types for supersedence. NewDT='$NewDtName' OldDT='$OldDtName'" "WARN"
        Write-Log "Supersedence skipped - app created successfully but not linked to previous version" "WARN"
        return
    }

    # Idempotency check (best-effort). If cmdlet not available, we still set supersedence and let SCCM handle duplicates.
    $already = $false
    if (Get-Command Get-CMDeploymentTypeSupersedence -ErrorAction SilentlyContinue) {
        try {
            $rels = Get-CMDeploymentTypeSupersedence -DeploymentTypeId $newDt.CI_ID -ErrorAction Stop
            if ($rels) {
                $already = $rels | Where-Object {
                    $_.SupersededDeploymentTypeID -eq $oldDt.CI_ID
                } | ForEach-Object { $true } | Select-Object -First 1
            }
        } catch { }
    }

    if ($already) {
        Write-Log "Supersedence already exists: '$NewAppName' DT -> '$OldAppName' DT" "OK"
        return
    }

    Write-Log "Setting supersedence: '$NewAppName' supersedes '$OldAppName' (UninstallOld=$UninstallOld)" "INFO"
    # Build args so we only pass a valid parameter set (Force OR IsUninstall)
    $ssArgs = @{
        Id                      = $newApp.CI_ID
        CurrentDeploymentTypeId  = $newDT.CI_ID
        SupersededApplicationId  = $oldApp.CI_ID
        OldDeploymentTypeId      = $oldDT.CI_ID
    }

    if ($UninstallOld) {
        # When uninstalling, DO NOT pass -Force (different parameter set)
        $ssArgs["IsUninstall"] = $true
    }
    else {
        # When not uninstalling, DO NOT pass -IsUninstall (different parameter set)
        $ssArgs["Force"] = $true
    }

    Set-CMApplicationSupersedence @ssArgs | Out-Null
    Write-Log "Supersedence configured." "OK"
}


#endregion

try {
    # Names + content paths
    $FinalAppName = "$NewAppName - $NewVersion"
    $dtName       = "$FinalAppName - Script"

    # FIXED Join-Path usage (Join-Path only supports 2 parts unless nested)
    $contentPath  = Join-Path (Join-Path $AppContentRoot $NewAppName) $NewVersion
    $metaPath     = Join-Path $contentPath "app.json"

    Write-Log "New App Name : $FinalAppName"
    Write-Log "Content Root : $AppContentRoot"
    Write-Log "Content Path : $contentPath"

    # Use FileSystem provider explicitly (required when running from CM drive like HLL:)
    $fsContentPath = if ($contentPath -match '^\\\\') { "Microsoft.PowerShell.Core\FileSystem::$contentPath" } else { $contentPath }
    $fsMetaPath = if ($metaPath -match '^\\\\') { "Microsoft.PowerShell.Core\FileSystem::$metaPath" } else { $metaPath }

    if (-not (Test-Path -LiteralPath $fsContentPath)) {
        throw "Content folder not found: $contentPath (did Script 1 stage it?)"
    }
    if (-not (Test-Path -LiteralPath $fsMetaPath)) {
        throw "Metadata file not found: $metaPath (expected app.json)"
    }

    # Load metadata
    $meta = Get-Content -LiteralPath $fsMetaPath -Raw | ConvertFrom-Json
    Write-Log "Loaded metadata: $metaPath" "OK"

    # Verify installer integrity if hash is present
    if ($meta.InstallerHash -and $meta.InstallerFile) {
        $installerPath = Join-Path $contentPath $meta.InstallerFile
        $fsInstallerPath = if ($installerPath -match '^\\\\') { "Microsoft.PowerShell.Core\FileSystem::$installerPath" } else { $installerPath }

        if (Test-Path -LiteralPath $fsInstallerPath) {
            Write-Log "Verifying installer integrity (SHA256)..." "INFO"
            $currentHash = (Get-FileHash -LiteralPath $fsInstallerPath -Algorithm SHA256).Hash

            if ($currentHash -ne $meta.InstallerHash) {
                throw "SECURITY: Installer integrity check failed! Expected hash: $($meta.InstallerHash), Got: $currentHash. The installer file may have been tampered with."
            }
            Write-Log "Installer integrity verified (SHA256 match)" "OK"
        } else {
            Write-Log "Installer file not found for hash verification: $installerPath" "WARN"
        }
    }

    $installerType = ($meta.Type | ForEach-Object { "$_".ToUpperInvariant() })
    $installerFile = $meta.InstallerFile
    $silentArgs    = $meta.SilentArgs
    $detMode       = $meta.Detection.Mode
    $installScope  = if ($meta.InstallScope) { $meta.InstallScope } else { "Machine" }

    # Enhanced metadata (Phase 6)
    $metaPublisher   = if ($meta.Publisher) { $meta.Publisher } else { $Publisher }
    $metaDescription = $meta.Description
    $metaReleaseDate = $meta.ReleaseDate
    $metaIconFile    = $meta.IconFile
    $metaUninstallCmd = $meta.UninstallCmd

    # Phase 7 metadata
    $metaIsPortable = if ($meta.IsPortable) { $meta.IsPortable } else { $false }
    $metaEstimatedTime = if ($meta.EstimatedInstallTime) { [int]$meta.EstimatedInstallTime } else { 5 }

    Write-Log "Metadata installer type: $installerType"
    Write-Log "Metadata installer file: $installerFile"
    if ($metaPublisher -ne $Publisher) {
        Write-Log "Publisher from metadata: $metaPublisher" "OK"
    }

    # Handle portable apps
    if ($metaIsPortable) {
        Write-Log "PORTABLE APP: Will copy EXE to Program Files instead of running installer" "WARN"
    }

    # Warn about user-scoped installers
    if ($installScope -eq "User") {
        Write-Log "WARNING: This is a per-USER installer. Detection may fail if installed as SYSTEM." "WARN"
        Write-Log "Consider deploying as 'Available' to user collections instead." "WARN"
    }

    # Marker standard (always unique per app+version)
    $markerPath = "C:\ProgramData\SCCM-Templates\$NewAppName\$NewVersion\installed.txt"

    # Get file path for fallback detection (if available)
    $filePath = $meta.Detection.FilePath

    # Build detection script
    $detectScript = $null

    switch ($detMode) {
        "MsiProductCode" {
            $pc = $meta.Detection.ProductCode
            if (-not $pc) { throw "Detection.Mode is MsiProductCode but ProductCode is missing in app.json" }
            $detectScript = New-DetectScript_MsiProductCode -ProductCode $pc
            Write-Log "Detection: MSI ProductCode ($pc)" "OK"
        }

        "UninstallDisplayNameVersion" {
            $dn  = $meta.Detection.DisplayName
            $min = $meta.Detection.MinVersion
            if (-not $dn -or -not $min) { throw "Detection.Mode is UninstallDisplayNameVersion but DisplayName/MinVersion missing in app.json" }
            # Use flexible detection with fallbacks for better reliability
            $detectScript = New-DetectScript_Flexible -DisplayName $dn -MinVersion $min -FilePath $filePath
            Write-Log "Detection: Flexible (DisplayName='$dn', MinVersion='$min', FilePath fallback)" "OK"
        }

        "UninstallDisplayName" {
            $dn = $meta.Detection.DisplayName
            if (-not $dn) { throw "Detection.Mode is UninstallDisplayName but DisplayName is missing in app.json" }
            # Use flexible detection for looser matching
            $detectScript = New-DetectScript_Flexible -DisplayName $dn -FilePath $filePath
            Write-Log "Detection: Flexible (DisplayName='$dn', no version check, FilePath fallback)" "OK"
        }

        "Flexible" {
            $dn  = $meta.Detection.DisplayName
            $min = $meta.Detection.MinVersion
            $detectScript = New-DetectScript_Flexible -DisplayName $dn -MinVersion $min -FilePath $filePath
            Write-Log "Detection: Flexible (DisplayName='$dn', MinVersion='$min', FilePath='$filePath')" "OK"
        }

        "FileBased" {
            # File-based detection (for portable apps)
            if (-not $filePath) { throw "Detection.Mode is FileBased but FilePath is missing in app.json" }
            $detectScript = New-DetectScript_FileBased -FilePath $filePath
            Write-Log "Detection: File-based ($filePath)" "OK"
        }

        default {
            # Marker fallback (safe baseline)
            $detMode = "Marker"
            $detectScript = New-DetectScript_Marker -MarkerPath $markerPath
            Write-Log "Detection: Marker fallback ($markerPath)" "WARN"
        }
    }

    # Build install/uninstall (metadata-first; overrides supported)
    # Timeout for installer execution (2 hours max)
    $installerTimeoutSeconds = 7200

    if (-not $InstallCommandLine) {

        # Handle portable apps specially - copy EXE to Program Files
        if ($metaIsPortable) {
            if (-not $installerFile) { throw "Metadata missing InstallerFile for portable app." }

            # Portable install: copy EXE to Program Files\<AppName>
            $portableDestFolder = "C:\Program Files\$NewAppName"
            $portableDestPath = "$portableDestFolder\$installerFile"

            # Escape single quotes for embedding in PowerShell strings
            $escapedPortableDestFolder = $portableDestFolder -replace "'", "''"
            $escapedPortableDestPath = $portableDestPath -replace "'", "''"
            $escapedInstallerFile = $installerFile -replace "'", "''"

            $InstallCommandLine = @"
powershell.exe -NoProfile -Command "& {
  `$destFolder = '$escapedPortableDestFolder'
  `$destPath = '$escapedPortableDestPath'
  `$srcFile = '.\$escapedInstallerFile'

  # Create destination folder
  if (-not (Test-Path `$destFolder)) {
    New-Item -Path `$destFolder -ItemType Directory -Force | Out-Null
  }

  # Copy the portable EXE
  Copy-Item -Path `$srcFile -Destination `$destPath -Force

  # Create Start Menu shortcut
  `$shell = New-Object -ComObject WScript.Shell
  `$shortcut = `$shell.CreateShortcut(`"`$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$NewAppName.lnk`")
  `$shortcut.TargetPath = `$destPath
  `$shortcut.Save()

  if (Test-Path `$destPath) { exit 0 } else { exit 1 }
}"
"@
            Write-Log "Portable install: Will copy to $portableDestPath" "OK"
        }
        elseif ($installerType -eq "EXE") {

            if (-not $installerFile) { throw "Metadata missing InstallerFile for EXE." }

            # Escape single quotes for paths
            $escapedInstallerFile = $installerFile -replace "'", "''"
            $escapedSilentArgs = $silentArgs -replace "'", "''"
            $escapedMarkerPath = $markerPath -replace "'", "''"

            # If marker detection, WRAP exe so marker gets written on success (fixes 0x87D00324)
            if ($detMode -eq "Marker") {

                if (-not $silentArgs) {
                    Write-Log "SilentArgs empty for EXE. Install will still run but may prompt. Consider setting InstallerTech/SilentArgs in Script 1." "WARN"
                    $silentArgs = ""
                    $escapedSilentArgs = ""
                }

                # Wrapper writes marker on success (0) or reboot-required (3010, 1641)
                # Includes timeout protection
                $InstallCommandLine = @"
powershell.exe -NoProfile -Command "& {
  `$exe = '.\${escapedInstallerFile}'
  `$argStr = '${escapedSilentArgs}'
  `$timeout = ${installerTimeoutSeconds}

  `$p = Start-Process -FilePath `$exe -ArgumentList `$argStr -PassThru
  `$waited = 0
  while (-not `$p.HasExited -and `$waited -lt `$timeout) {
    Start-Sleep -Seconds 5
    `$waited += 5
  }
  if (-not `$p.HasExited) {
    `$p.Kill()
    exit 1460  # ERROR_TIMEOUT
  }
  `$code = `$p.ExitCode

  # Treat 0, 3010 (reboot required), 1641 (reboot initiated) as success
  `$successCodes = @(0, 3010, 1641)
  if (`$code -in `$successCodes) {
    New-Item -Path (Split-Path -Parent '${escapedMarkerPath}') -ItemType Directory -Force | Out-Null
    Set-Content -Path '${escapedMarkerPath}' -Value 'Installed' -Force
    if (`$code -eq 0) { exit 0 } else { exit 3010 }
  }
  exit `$code
}"
"@
            }
            else {
                # Real detection mode: wrap installer to handle reboot exit codes
                # This prevents false failures when app installs but returns 3010
                # Includes timeout protection
                if (-not $silentArgs) {
                    $silentArgs = ""
                    $escapedSilentArgs = ""
                }

                $InstallCommandLine = @"
powershell.exe -NoProfile -Command "& {
  `$exe = '.\${escapedInstallerFile}'
  `$argStr = '${escapedSilentArgs}'
  `$timeout = ${installerTimeoutSeconds}

  `$p = Start-Process -FilePath `$exe -ArgumentList `$argStr -PassThru
  `$waited = 0
  while (-not `$p.HasExited -and `$waited -lt `$timeout) {
    Start-Sleep -Seconds 5
    `$waited += 5
  }
  if (-not `$p.HasExited) {
    `$p.Kill()
    exit 1460  # ERROR_TIMEOUT
  }
  `$code = `$p.ExitCode

  # Treat 0, 3010 (reboot required), 1641 (reboot initiated) as success
  `$successCodes = @(0, 3010, 1641)
  if (`$code -in `$successCodes) {
    if (`$code -eq 0) { exit 0 } else { exit 3010 }
  }
  exit `$code
}"
"@
            }
        }
        elseif ($installerType -eq "MSI") {

            if (-not $installerFile) { throw "Metadata missing InstallerFile for MSI." }
            # Use msiexec with local content file
            $InstallCommandLine = "msiexec /i `"$installerFile`" /qn /norestart"
        }
        else {
            throw "Unsupported installer type in metadata: $installerType"
        }
    }

    if (-not $UninstallCommandLine) {
        # Priority for uninstall command:
        # 1. Portable apps - delete the copied files
        # 2. UninstallCmd from winget metadata (best - from the actual package manifest)
        # 3. MSI ProductCode-based uninstall
        # 4. Marker cleanup (if marker detection)
        # 5. Placeholder

        if ($metaIsPortable) {
            # Portable uninstall: delete the EXE and shortcut
            $portableDestFolder = "C:\Program Files\$NewAppName"
            $UninstallCommandLine = @"
powershell.exe -NoProfile -Command "& {
  Remove-Item -Path '$portableDestFolder' -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item -Path `"`$env:ProgramData\Microsoft\Windows\Start Menu\Programs\$NewAppName.lnk`" -Force -ErrorAction SilentlyContinue
  exit 0
}"
"@
            Write-Log "Portable uninstall: Will delete $portableDestFolder" "OK"
        }
        elseif ($metaUninstallCmd) {
            # Use uninstall command from winget metadata
            $UninstallCommandLine = $metaUninstallCmd
            Write-Log "Using uninstall command from metadata" "OK"
        }
        elseif ($installerType -eq "MSI" -and $meta.Detection -and $meta.Detection.ProductCode) {
            # MSI: use ProductCode for reliable uninstall
            $pc = $meta.Detection.ProductCode
            $UninstallCommandLine = "msiexec /x $pc /qn /norestart"
        }
        elseif ($detMode -eq "Marker") {
            # Marker detection: clean up marker file
            $UninstallCommandLine = "powershell.exe -NoProfile -Command `"Remove-Item -LiteralPath '$markerPath' -Force -ErrorAction SilentlyContinue`""
        }
        elseif ($meta.Detection -and $meta.Detection.DisplayName) {
            # Try to build an uninstall command based on registry lookup
            $dn = $meta.Detection.DisplayName
            $UninstallCommandLine = @"
powershell.exe -NoProfile -Command "& {
  `$keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  `$app = Get-ItemProperty `$keys -EA SilentlyContinue | Where-Object { `$_.DisplayName -like '*$dn*' } | Select-Object -First 1
  if (`$app.UninstallString) {
    `$cmd = `$app.UninstallString
    if (`$cmd -match 'msiexec') { `$cmd = `$cmd + ' /qn /norestart' }
    elseif (`$cmd -match '\.exe') { `$cmd = `$cmd + ' /S' }
    Start-Process cmd.exe -ArgumentList '/c', `$cmd -Wait
  }
}"
"@
            Write-Log "Generated registry-based uninstall command" "OK"
        }
        else {
            # Placeholder (override later per app if needed)
            $UninstallCommandLine = "cmd.exe /c exit 0"
            Write-Log "No uninstall command available - using placeholder" "WARN"
        }
    }

    Write-Log "InstallCmd : $InstallCommandLine"
    Write-Log "Uninstall  : $UninstallCommandLine"

    # Connect to site
    Connect-CMSite -SiteCode $SiteCode

    # Create app if missing
    $app = Get-CMApplication -Name $FinalAppName -ErrorAction SilentlyContinue
    if (-not $app) {
        Write-Log "Creating application..." "INFO"

        # Build New-CMApplication parameters
        $appParams = @{
            Name = $FinalAppName
            Publisher = $metaPublisher
            SoftwareVersion = $NewVersion
            AutoInstall = $false
        }

        # Add optional parameters if available in metadata
        if ($metaDescription) {
            $appParams.Description = $metaDescription
        }

        # Parse and set release date if available
        if ($metaReleaseDate) {
            try {
                $releaseDate = [datetime]::Parse($metaReleaseDate)
                $appParams.ReleaseDate = $releaseDate
                Write-Log "Release date from metadata: $metaReleaseDate" "OK"
            } catch {
                Write-Log "Could not parse release date '$metaReleaseDate'" "WARN"
            }
        }

        $app = New-CMApplication @appParams
        Write-Log "Application created: $FinalAppName (Publisher: $metaPublisher)" "OK"

        # Set icon if available
        if ($metaIconFile) {
            $iconPath = Join-Path $contentPath $metaIconFile
            $fsIconPath = if ($iconPath -match '^\\\\') { "Microsoft.PowerShell.Core\FileSystem::$iconPath" } else { $iconPath }

            if (Test-Path -LiteralPath $fsIconPath) {
                try {
                    Set-CMApplication -Name $FinalAppName -IconLocationFile $iconPath
                    Write-Log "Icon set from: $metaIconFile" "OK"
                } catch {
                    Write-Log "Could not set icon: $($_.Exception.Message)" "WARN"
                }
            } else {
                Write-Log "Icon file not found: $iconPath" "WARN"
            }
        }
    } else {
        Write-Log "Application already exists: $FinalAppName (CI_ID: $($app.CI_ID))" "WARN"
    }

    # Idempotency: skip if DT already exists
    $existingDt = Get-CMDeploymentType -ApplicationName $FinalAppName -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalizedDisplayName -eq $dtName }

    if ($existingDt) {
        Write-Log "Deployment Type already exists: $dtName" "OK"
        Write-Log "Skipping DT creation, continuing to supersedence." "INFO"
    }
    else {
        # Create script DT
        Write-Log "Creating Script Installer deployment type: $dtName" "INFO"

        Add-CMScriptDeploymentType `
            -ApplicationName $FinalAppName `
            -DeploymentTypeName $dtName `
            -ContentLocation $contentPath `
            -InstallCommand $InstallCommandLine `
            -UninstallCommand $UninstallCommandLine `
            -InstallationBehaviorType InstallForSystem `
            -LogonRequirementType WhetherOrNotUserLoggedOn `
            -UserInteractionMode Hidden `
            -MaximumRuntimeMins 120 `
            -EstimatedRuntimeMins $metaEstimatedTime `
            -ScriptLanguage PowerShell `
            -ScriptText $detectScript `
            -Force | Out-Null

        Write-Log "Estimated install time: $metaEstimatedTime minutes" "OK"

        Write-Log "Deployment Type created: $dtName" "OK"
    }

    # Phase 2: Supersedence (default ON, safe auto-skip, metadata-driven with opt-out)
    $sup = $meta.Supersedence

    # Default behaviour: attempt supersedence for every run (will auto-skip if no previous app exists)
    # Opt-out mechanisms:
    #   1) -NoSupersedence switch (run-level)
    #   2) app.json: "Supersedence": { "Enabled": false } (app/version-level)
    $supEnabled = $true
    if ($NoSupersedence) { $supEnabled = $false }
    if ($sup -and ($sup.PSObject.Properties.Name -contains "Enabled") -and ($sup.Enabled -eq $false)) { $supEnabled = $false }

    if ($supEnabled) {
        $mode = "ImmediatePrevious"
        $uninstallOld = $true  # Default: uninstall superseded apps
        $prefix = "$NewAppName - "

        if ($sup) {
            if ($sup.Mode) { $mode = "$($sup.Mode)" }
            if ($sup.PSObject.Properties.Name -contains "UninstallOld") { $uninstallOld = [bool]$sup.UninstallOld }
            if ($sup.Match -and $sup.Match.NamePrefix) { $prefix = "$($sup.Match.NamePrefix)" }
        }

        # Command-line switch overrides metadata and default
        if ($NoUninstall) { $uninstallOld = $false }

        if ($mode -ne "ImmediatePrevious") {
            Write-Log "Supersedence mode '$mode' not implemented yet. Using ImmediatePrevious." "WARN"
            $mode = "ImmediatePrevious"
        }

        $prev = Get-PreviousAppForSupersedence -BaseName $NewAppName -CurrentVersion $NewVersion -NamePrefix $prefix
        if ($prev) {
            $oldAppName = $prev.Name
            $oldDtName  = "$oldAppName - Script"

            # Ensure uninstall is actually usable if requested
            if ($uninstallOld -and $installerType -ne "MSI") {
                Write-Log "UninstallOld=true requested but installer type is '$installerType'. This will only work if the OLD DT has a valid uninstall command." "WARN"
            }

            Ensure-CMSupersedence -NewAppName $FinalAppName -NewDtName $dtName -OldAppName $oldAppName -OldDtName $oldDtName -UninstallOld:$uninstallOld
        } else {
            Write-Log "Supersedence: no previous version found for '$NewAppName' below '$NewVersion' (prefix='$prefix'). Skipping." "INFO"
        }
    } else {
        Write-Log "Supersedence disabled for this run (NoSupersedence switch or app.json override)." "INFO"
    }

    # Optional move in console
    if ($DestinationConsoleFolderPath) {
        Write-Log "Moving to console folder: $DestinationConsoleFolderPath" "INFO"
        Move-CMObject -FolderPath $DestinationConsoleFolderPath -InputObject $app -ErrorAction Stop
        Write-Log "Moved to console folder." "OK"
    }

    Write-Host ""
    Write-Host "=== COMPLETE (NEW APP + SCRIPT DT) ==="
    Write-Host "Application : $FinalAppName"
    Write-Host "Content     : $contentPath"
    Write-Host "DT Name     : $dtName"
    Write-Host "Detect      : PowerShell (metadata-first, mode=$detMode)"
    Write-Host ""
    Write-Host "Next:"
    Write-Host " - Distribute content (Script 3)"
    Write-Host " - Deploy to Pilot/UAT (Script 3)"

    # Audit logging
    if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
        Write-AuditLog -Action "Create" -Target $FinalAppName -Result "Success" -Details "Created SCCM app with $detMode detection"
    }
}
catch {
    Write-Log $_.Exception.Message "ERROR"
    # Audit logging for failures
    if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
        Write-AuditLog -Action "Create" -Target "$NewAppName - $NewVersion" -Result "Failed" -Details $_.Exception.Message
    }
    throw
}
