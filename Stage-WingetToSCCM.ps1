<#
Stage-WingetToSCCM.ps1 (v5.0 - Portable App Support)
- Adds -WingetVersion (so SCCM version labels can differ, e.g. 1.2.8-test1)
- Adds -InstallerTech (NSIS/Inno/Portable/Unknown) to avoid silent-arg guessing when fallback URLs change filenames
- Phase 3: Auto-detects DisplayName from winget for EXE registry detection
- Phase 5: Auto-detects InstallScope (User vs Machine) from installer filename
- Phase 5: Adds expected install path for file-based detection fallback
- Phase 6: Retry logic for downloads (configurable retries)
- Phase 6: Extracts Publisher, ReleaseDate, Description from winget
- Phase 6: Extracts uninstall command from winget manifest
- Phase 6: Extracts icon from installer (if possible)
- Phase 7: Detects portable apps from winget and sets file-based detection
- Phase 7: Falls back to staging date if ReleaseDate not available
- Phase 7: Calculates EstimatedInstallTime based on installer size
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string[]]$PackageId,

    [string]$AppName,

    # SCCM label version (folder + app version label)
    [Parameter(Mandatory)]
    [string]$Version,

    # Optional: actual winget version (must match real winget version).
    # If omitted, script will NOT pass --version to winget.
    [string]$WingetVersion = "",

    [string]$LocalStageRoot = "C:\Winget-Staging",

    # UPDATE TO YOUR SCCM CONTENT SHARE (e.g. \\YOURSERVER\SCCM-Source\Applications)
    [Parameter(Mandatory)]
    [string]$SccmContentRoot,
    [string]$MetadataFileName = "app.json",

    # Optional override for EXE silent args (highest priority)
    [string]$ExeSilentArgs = "",

    # Optional hint for installer tech to set silent args deterministically
    [ValidateSet("","NSIS","Inno","Portable","Unknown")]
    [string]$InstallerTech = "",

    [ValidateSet("x64","x86","arm64","neutral")]
    [string]$Architecture = "x64",

    # Number of retry attempts for downloads
    [int]$MaxRetries = 3,

    # Delay between retries in seconds
    [int]$RetryDelaySeconds = 5
)

function Write-Log {
    param([string]$Message, [ValidateSet("INFO","WARN","ERROR","OK")]$Level="INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "INFO"  { Write-Host "[$ts] [INFO ] $Message" }
        "WARN"  { Write-Host "[$ts] [WARN ] $Message" -ForegroundColor Yellow }
        "ERROR" { Write-Host "[$ts] [ERROR] $Message" -ForegroundColor Red }
        "OK"    { Write-Host "[$ts] [ OK  ] $Message" -ForegroundColor Green }
    }
}

function Get-FSPath {
    param([Parameter(Mandatory)][string]$UncPath)
    if ($UncPath -notmatch '^\\\\') { throw "Path must be UNC: $UncPath" }
    "Microsoft.PowerShell.Core\FileSystem::$UncPath"
}

function Assert-UNC {
    param([Parameter(Mandatory)][string]$Path)
    $fsPath = Get-FSPath -UncPath $Path
    if (-not (Test-Path -LiteralPath $fsPath)) { throw "UNC path not accessible: $Path" }
}

function Test-WingetDownloadSupport {
    try {
        $help = & winget --help 2>$null | Out-String
        return ($help -match '(?im)^\s*download\s')
    } catch { return $false }
}

function Get-MsiProductCode {
    param([Parameter(Mandatory)][string]$MsiPath)

    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember("OpenDatabase","InvokeMethod",$null,$installer,@($MsiPath,0))
    $view = $db.GetType().InvokeMember("OpenView","InvokeMethod",$null,$db,@("SELECT Value FROM Property WHERE Property='ProductCode'"))
    $view.GetType().InvokeMember("Execute","InvokeMethod",$null,$view,$null) | Out-Null
    $rec = $view.GetType().InvokeMember("Fetch","InvokeMethod",$null,$view,$null)
    $rec.GetType().InvokeMember("StringData","GetProperty",$null,$rec,1)
}

function BestEffortGetSilentArgsFromWingetShow {
    param([Parameter(Mandatory)][string]$Id)

    try {
        $out = & winget show --id $Id --accept-source-agreements 2>$null | Out-String
        if ($out -match '(?im)Silent\s*:\s*(.+)$') { return $Matches[1].Trim() }
        if ($out -match '(?im)SilentWithProgress\s*:\s*(.+)$') { return $Matches[1].Trim() }
        return ""
    } catch { return "" }
}

function Get-InstallScope {
    <#
    .SYNOPSIS
        Detects if installer is User or Machine scope based on filename and winget info.
    #>
    param(
        [Parameter(Mandatory)][string]$InstallerFileName,
        [string]$WingetId = ""
    )

    # Check filename for User/Machine indicators
    $name = $InstallerFileName.ToLowerInvariant()
    if ($name -match '_user_|\.user\.|peruser|user_x64|user_x86') {
        return "User"
    }
    if ($name -match '_machine_|\.machine\.|permachine|machine_x64|machine_x86') {
        return "Machine"
    }

    # Default to Machine (most common for enterprise deployment)
    return "Machine"
}

function Get-ExpectedInstallPath {
    <#
    .SYNOPSIS
        Attempts to determine the expected install path for file-based detection fallback.
    #>
    param(
        [Parameter(Mandatory)][string]$AppName,
        [Parameter(Mandatory)][string]$WingetId,
        [string]$Scope = "Machine"
    )

    # Common install path patterns
    $programFiles = $env:ProgramFiles
    $programFilesX86 = ${env:ProgramFiles(x86)}
    $localAppData = $env:LocalAppData

    # Try to construct likely paths based on app name
    $appNameClean = $AppName -replace '[^\w\s-]', ''

    $possiblePaths = @()

    if ($Scope -eq "Machine") {
        $possiblePaths += "$programFiles\$appNameClean"
        $possiblePaths += "$programFiles\$($WingetId.Split('.')[-1])"
        $possiblePaths += "$programFilesX86\$appNameClean"
    } else {
        $possiblePaths += "$localAppData\$appNameClean"
        $possiblePaths += "$localAppData\Programs\$appNameClean"
    }

    # Return first path as suggestion (actual verification happens at detection time)
    return $possiblePaths[0]
}

function Get-WingetAppDisplayName {
    <#
    .SYNOPSIS
        Extracts the display name from winget metadata for registry-based detection.
    .DESCRIPTION
        Queries 'winget show' and parses the output to find the app's display name.
        This name typically matches what appears in Add/Remove Programs (registry).
    #>
    param([Parameter(Mandatory)][string]$Id)

    try {
        $out = & winget show --id $Id --accept-source-agreements 2>$null | Out-String

        # Look for "Found <DisplayName> [PackageId]" pattern
        if ($out -match 'Found\s+(.+?)\s+\[') {
            $name = $Matches[1].Trim()
            Write-Log "Detected DisplayName from winget: $name" "OK"
            return $name
        }

        # Fallback: look for explicit Name field
        if ($out -match '(?im)^Name\s*:\s*(.+)$') {
            $name = $Matches[1].Trim()
            Write-Log "Detected DisplayName from winget (Name field): $name" "OK"
            return $name
        }

        Write-Log "Could not extract DisplayName from winget metadata" "WARN"
        return $null
    } catch {
        Write-Log "Error querying winget for DisplayName: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Get-WingetAppMetadata {
    <#
    .SYNOPSIS
        Extracts comprehensive metadata from winget (Publisher, Description, ReleaseDate, etc.)
    #>
    param([Parameter(Mandatory)][string]$Id)

    $metadata = @{
        Publisher = $null
        Description = $null
        ReleaseDate = $null
        Homepage = $null
        License = $null
        UninstallCommand = $null
        InstallerType = $null
    }

    try {
        $out = & winget show --id $Id --accept-source-agreements 2>$null | Out-String

        # Publisher
        if ($out -match '(?im)^Publisher\s*:\s*(.+)$') {
            $metadata.Publisher = $Matches[1].Trim()
        }

        # Description (may be multi-line, get first line)
        if ($out -match '(?im)^Description\s*:\s*(.+)$') {
            $metadata.Description = $Matches[1].Trim()
        }

        # Release Date
        if ($out -match '(?im)^Release\s*Date\s*:\s*(.+)$') {
            $metadata.ReleaseDate = $Matches[1].Trim()
        }

        # Homepage URL
        if ($out -match '(?im)^(?:Homepage|Publisher\s+Url)\s*:\s*(https?://\S+)') {
            $metadata.Homepage = $Matches[1].Trim()
        }

        # License
        if ($out -match '(?im)^License\s*:\s*(.+)$') {
            $metadata.License = $Matches[1].Trim()
        }

        # Try to find uninstall command from manifest
        if ($out -match '(?im)^Uninstall\s*:\s*(.+)$') {
            $metadata.UninstallCommand = $Matches[1].Trim()
        }

        # Installer Type (portable, exe, msi, etc.)
        if ($out -match '(?im)^\s*Installer\s+Type\s*:\s*(.+)$') {
            $metadata.InstallerType = $Matches[1].Trim().ToLowerInvariant()
        }

        return $metadata
    } catch {
        Write-Log "Error extracting metadata from winget: $($_.Exception.Message)" "WARN"
        return $metadata
    }
}

function Get-EstimatedInstallTime {
    <#
    .SYNOPSIS
        Calculates estimated install time in minutes based on installer size.
    #>
    param([Parameter(Mandatory)][double]$SizeMB)

    # Rough estimates:
    # < 10 MB = 5 minutes (quick install)
    # 10-50 MB = 10 minutes (medium install)
    # 50-200 MB = 15 minutes (larger install)
    # > 200 MB = 20 minutes (large install)

    if ($SizeMB -lt 10) { return 5 }
    if ($SizeMB -lt 50) { return 10 }
    if ($SizeMB -lt 200) { return 15 }
    return 20
}

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with retry logic.
    #>
    param(
        [Parameter(Mandatory)][ScriptBlock]$ScriptBlock,
        [int]$MaxRetries = 3,
        [int]$DelaySeconds = 5,
        [string]$OperationName = "Operation"
    )

    $attempt = 0
    $lastError = $null

    while ($attempt -lt $MaxRetries) {
        $attempt++
        try {
            $result = & $ScriptBlock
            return $result
        }
        catch {
            $lastError = $_
            if ($attempt -lt $MaxRetries) {
                Write-Log "$OperationName failed (attempt $attempt/$MaxRetries). Retrying in $DelaySeconds seconds..." "WARN"
                Start-Sleep -Seconds $DelaySeconds
            }
        }
    }

    Write-Log "$OperationName failed after $MaxRetries attempts." "ERROR"
    throw $lastError
}

function Get-InstallerIcon {
    <#
    .SYNOPSIS
        Extracts icon from an EXE or MSI installer and saves as .ico file.
    .DESCRIPTION
        Uses Shell32 to extract the icon from the installer file.
        Returns the path to the saved icon file, or $null if extraction failed.
    #>
    param(
        [Parameter(Mandatory)][string]$InstallerPath,
        [Parameter(Mandatory)][string]$OutputFolder
    )

    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop

        $iconPath = Join-Path $OutputFolder "app-icon.ico"

        # Try to extract icon using Shell32
        $shell = New-Object -ComObject Shell.Application
        $folder = $shell.Namespace((Split-Path $InstallerPath -Parent))
        $file = $folder.ParseName((Split-Path $InstallerPath -Leaf))

        # Get the icon - this gets the associated icon
        $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($InstallerPath)

        if ($icon) {
            # Save the icon
            $fileStream = [System.IO.File]::Create($iconPath)
            $icon.Save($fileStream)
            $fileStream.Close()
            $icon.Dispose()

            Write-Log "Extracted icon to: $iconPath" "OK"
            return $iconPath
        }

        Write-Log "Could not extract icon from installer" "WARN"
        return $null
    }
    catch {
        Write-Log "Icon extraction failed: $($_.Exception.Message)" "WARN"
        return $null
    }
}

function Get-WingetInstallerUrls {
    param([Parameter(Mandatory)][string]$Id)

    $out = & winget show --id $Id --accept-source-agreements 2>$null | Out-String
    $urls = New-Object System.Collections.Generic.List[string]

    foreach ($pattern in @(
        '(?im)^\s*Installer\s+Url\s*:\s*(https?://\S+)\s*$',
        '(?im)^\s*Installer\s+URL\s*:\s*(https?://\S+)\s*$',
        '(?im)^\s*Installer\s+URL\s*\(.*\)\s*:\s*(https?://\S+)\s*$'
    )) {
        $matches = [regex]::Matches($out, $pattern)
        foreach ($m in $matches) { $urls.Add($m.Groups[1].Value) }
    }

    $urls | Select-Object -Unique
}

function Download-File {
    param(
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestinationPath
    )

    Write-Log "Direct URL fallback download: $Url" "WARN"
    try {
        Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop
        return $true
    } catch {
        Write-Log "Direct download failed: $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Find-InstallerInFolder {
    param([Parameter(Mandatory)][string]$Folder)

    Get-ChildItem -Path $Folder -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension.ToLowerInvariant() -in @(
                ".msi",".exe",".msix",".appx",
                ".msixbundle",".appxbundle",
                ".msp",".zip"
            )
        } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Get-SilentArgsFromTechOrSignature {
    param(
        [Parameter(Mandatory)][string]$InstallerFileName,
        [string]$WingetSilentArgs = "",
        [string]$TechHint = ""
    )

    if ($WingetSilentArgs) { return $WingetSilentArgs }

    switch ($TechHint) {
        "NSIS" { return "/S" }
        "Inno" { return "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" }
    }

    $n = $InstallerFileName.ToLowerInvariant()
    if ($n -match 'nullsoft|nsis') { return "/S" }
    if ($n -match 'inno') { return "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" }

    return ""
}

# Import shared helpers
$helperModule = Join-Path $PSScriptRoot "SCCMPipelineHelpers.psm1"
if (Test-Path $helperModule) {
    Import-Module $helperModule -Force
}

try {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw "winget not found on this machine." }
    if (-not (Test-WingetDownloadSupport)) { throw "Your winget does not appear to support 'winget download'. Update winget (App Installer) and try again." }

    Assert-UNC -Path $SccmContentRoot
    New-Item -ItemType Directory -Path $LocalStageRoot -Force | Out-Null

    foreach ($id in $PackageId) {

        $resolvedAppName = if ($AppName) { $AppName } else { ($id.Split('.') | Select-Object -Last 1) }

        # Validate inputs
        try {
            if (Get-Command Assert-SafeAppName -ErrorAction SilentlyContinue) {
                Assert-SafeAppName -Name $resolvedAppName | Out-Null
            }
            if (Get-Command Assert-SafeVersion -ErrorAction SilentlyContinue) {
                Assert-SafeVersion -Version $Version | Out-Null
            }
        } catch {
            throw "Input validation failed for '$resolvedAppName': $($_.Exception.Message)"
        }
        $localPkgStage = Join-Path $LocalStageRoot ($resolvedAppName + "_" + $Version)
        New-Item -ItemType Directory -Path $localPkgStage -Force | Out-Null

        Write-Log "Downloading via winget: $id -> $localPkgStage (arch=$Architecture, wingetVersion=$WingetVersion)" "INFO"

        # Build winget args (only pass --version if WingetVersion is supplied)
        $downloadArgs = @("download","--id",$id,"--architecture",$Architecture,"--download-directory",$localPkgStage,"--accept-source-agreements","--accept-package-agreements")
        if ($WingetVersion) { $downloadArgs += @("--version",$WingetVersion) }

        # Download with retry logic
        $downloadSuccess = $false
        $attempt = 0

        while (-not $downloadSuccess -and $attempt -lt $MaxRetries) {
            $attempt++
            if ($attempt -gt 1) {
                Write-Log "Retry attempt $attempt/$MaxRetries for winget download..." "WARN"
                Start-Sleep -Seconds $RetryDelaySeconds
            }

            $wingetOut = & winget @downloadArgs 2>&1 | Out-String
            $code = $LASTEXITCODE

            if ($code -eq 0) {
                $downloadSuccess = $true
            } elseif ($attempt -eq $MaxRetries) {
                Write-Log "winget download failed after $MaxRetries attempts (exit=$code). Output below:" "ERROR"
                Write-Host $wingetOut
            }
        }

        # Fallback to direct URL download if winget failed
        if (-not $downloadSuccess) {
            Write-Log "Attempting manifest URL fallback via 'winget show'..." "WARN"
            $urls = Get-WingetInstallerUrls -Id $id

            if (-not $urls -or $urls.Count -eq 0) {
                throw "winget download failed for $id (exit=$code) and no Installer Url found for fallback."
            }

            $downloaded = $false
            foreach ($u in $urls) {
                # Retry each URL
                for ($urlAttempt = 1; $urlAttempt -le $MaxRetries; $urlAttempt++) {
                    try {
                        $fileName = [IO.Path]::GetFileName(([Uri]$u).AbsolutePath)
                        if (-not $fileName) { $fileName = "$($id.Replace('.','_'))-$Version.bin" }
                        $dest = Join-Path $localPkgStage $fileName

                        if ($urlAttempt -gt 1) {
                            Write-Log "URL download retry $urlAttempt/$MaxRetries..." "WARN"
                            Start-Sleep -Seconds $RetryDelaySeconds
                        }

                        if (Download-File -Url $u -DestinationPath $dest) {
                            $downloaded = $true
                            break
                        }
                    } catch {
                        Write-Log "Skipping URL due to parse error: $u" "WARN"
                    }
                }
                if ($downloaded) { break }
            }

            if (-not $downloaded) {
                throw "winget download failed for $id (exit=$code) and fallback URL download(s) failed after retries."
            }
        }

        $installer = Find-InstallerInFolder -Folder $localPkgStage
        if (-not $installer) {
            Write-Log "No installer file detected after download/fallback." "ERROR"
            Write-Log "Directory listing for ${localPkgStage}:" "WARN"
            Get-ChildItem -Path $localPkgStage -Recurse -Force |
                Select-Object FullName, Length, LastWriteTime |
                Sort-Object LastWriteTime -Descending |
                Format-Table -AutoSize
            throw "No installer file found after winget download/fallback for $id in $localPkgStage"
        }

        $type = switch ($installer.Extension.ToLowerInvariant()) {
            ".msi"  { "MSI" }
            ".exe"  { "EXE" }
            default { "EXE" }
        }

        # Create SCCM folder \\Root\<App>\<Version>\
        $uncAppFolder = Join-Path $SccmContentRoot $resolvedAppName
        $uncVerFolder = Join-Path $uncAppFolder   $Version
        $fsVerFolder  = Get-FSPath -UncPath $uncVerFolder

        Write-Log "Ensuring SCCM content folder exists: $uncVerFolder" "INFO"
        New-Item -ItemType Directory -Path $fsVerFolder -Force | Out-Null

        # Copy installer into SCCM content folder
        $destInstaller = Join-Path $uncVerFolder $installer.Name
        $fsDestInstaller = Get-FSPath -UncPath $destInstaller

        Write-Log "Copying installer: $($installer.FullName) -> $destInstaller" "INFO"
        Copy-Item -LiteralPath $installer.FullName -Destination $fsDestInstaller -Force

        # Calculate SHA256 hash for integrity verification
        Write-Log "Calculating SHA256 hash for integrity verification..." "INFO"
        $installerHash = (Get-FileHash -LiteralPath $fsDestInstaller -Algorithm SHA256).Hash
        Write-Log "Installer hash (SHA256): $installerHash" "OK"

        # Determine silent args for EXE
        $silent = ""
        if ($type -eq "EXE") {
            if ($ExeSilentArgs) {
                $silent = $ExeSilentArgs
            } else {
                $fromWinget = BestEffortGetSilentArgsFromWingetShow -Id $id
                $silent = Get-SilentArgsFromTechOrSignature -InstallerFileName $installer.Name -WingetSilentArgs $fromWinget -TechHint $InstallerTech
            }
        }

        # Detect install scope (User vs Machine)
        $installScope = Get-InstallScope -InstallerFileName $installer.Name -WingetId $id
        if ($installScope -eq "User") {
            Write-Log "WARNING: This appears to be a per-USER installer. May require user-context deployment." "WARN"
        }

        # Get expected install path for file-based detection fallback
        $expectedPath = Get-ExpectedInstallPath -AppName $resolvedAppName -WingetId $id -Scope $installScope

        # Extract enhanced metadata from winget
        Write-Log "Extracting metadata from winget..." "INFO"
        $wingetMeta = Get-WingetAppMetadata -Id $id

        # Detect portable apps from winget metadata or filename
        $isPortable = $false
        if ($wingetMeta.InstallerType -eq "portable") {
            $isPortable = $true
            Write-Log "PORTABLE APP DETECTED from winget metadata" "WARN"
        } elseif ($installer.Name -match 'portable|_p_|\.portable\.' -and $type -eq "EXE") {
            $isPortable = $true
            Write-Log "PORTABLE APP DETECTED from filename pattern" "WARN"
        }

        # Override InstallerTech if portable detected
        if ($isPortable -and -not $InstallerTech) {
            $InstallerTech = "Portable"
        }

        # Get installer file size
        $installerSize = [math]::Round($installer.Length / 1MB, 2)

        # Calculate estimated install time based on size
        $estimatedTime = Get-EstimatedInstallTime -SizeMB $installerSize

        # Fall back to current date if ReleaseDate not available from winget
        $releaseDate = $wingetMeta.ReleaseDate
        if (-not $releaseDate) {
            $releaseDate = (Get-Date -Format "yyyy-MM-dd")
            Write-Log "ReleaseDate not in winget, using staging date: $releaseDate" "INFO"
        }

        # Try to extract icon
        $iconFile = $null
        try {
            $iconPath = Get-InstallerIcon -InstallerPath $installer.FullName -OutputFolder $localPkgStage
            if ($iconPath -and (Test-Path $iconPath)) {
                # Copy icon to SCCM folder
                $destIconPath = Join-Path $uncVerFolder "app-icon.ico"
                $fsDestIcon = Get-FSPath -UncPath $destIconPath
                Copy-Item -LiteralPath $iconPath -Destination $fsDestIcon -Force
                $iconFile = "app-icon.ico"
            }
        } catch {
            Write-Log "Icon extraction skipped: $($_.Exception.Message)" "WARN"
        }

        $meta = [ordered]@{
            AppName              = $resolvedAppName
            Version              = $Version
            WingetId             = $id
            WingetVersion        = $WingetVersion
            InstallerFile        = $installer.Name
            InstallerHash        = $installerHash
            InstallerSize        = "$installerSize MB"
            Type                 = $type
            InstallerTech        = if ($InstallerTech) { $InstallerTech } else { "Unknown" }
            IsPortable           = $isPortable
            SilentArgs           = $silent
            InstallScope         = $installScope
            Publisher            = $wingetMeta.Publisher
            Description          = $wingetMeta.Description
            ReleaseDate          = $releaseDate
            EstimatedInstallTime = $estimatedTime
            Homepage             = $wingetMeta.Homepage
            License              = $wingetMeta.License
            IconFile             = $iconFile
            UninstallCmd         = $wingetMeta.UninstallCommand
            Detection            = [ordered]@{
                Mode        = "Marker"
                ProductCode = $null
                DisplayName = $null
                MinVersion  = $null
                FilePath    = $null
            }
        }

        if ($type -eq "MSI") {
            try {
                $pc = Get-MsiProductCode -MsiPath $installer.FullName
                if ($pc) {
                    $meta.Detection.Mode = "MsiProductCode"
                    $meta.Detection.ProductCode = $pc
                    Write-Log "Extracted MSI ProductCode: $pc" "OK"
                } else {
                    Write-Log "MSI ProductCode not found. Falling back to Marker detection." "WARN"
                }
            } catch {
                Write-Log "Failed to extract MSI ProductCode. Falling back to Marker detection. Error: $($_.Exception.Message)" "WARN"
            }
        } else {
            # Handle portable apps specially - they use file-based detection only
            if ($isPortable) {
                # Portable apps: detect by file existence, not registry
                $portableInstallPath = "C:\Program Files\$resolvedAppName"
                $portableExePath = "$portableInstallPath\$($installer.Name)"

                $meta.Detection.Mode = "FileBased"
                $meta.Detection.FilePath = $portableExePath
                $meta.SilentArgs = ""  # Portable apps don't have installers

                Write-Log "PORTABLE: Will copy EXE to $portableInstallPath" "OK"
                Write-Log "PORTABLE: Detection via file existence: $portableExePath" "OK"
            } else {
                # Phase 3: Try to get DisplayName from winget for registry-based detection
                $displayName = Get-WingetAppDisplayName -Id $id
                if ($displayName) {
                    $meta.Detection.Mode = "UninstallDisplayNameVersion"
                    $meta.Detection.DisplayName = $displayName
                    $meta.Detection.MinVersion = $Version
                    Write-Log "EXE detection: UninstallDisplayNameVersion (DisplayName='$displayName', MinVersion='$Version')" "OK"
                } else {
                    Write-Log "Could not auto-detect DisplayName. Falling back to Marker detection." "WARN"
                }

                # Set expected file path for fallback detection
                $meta.Detection.FilePath = "$expectedPath\$($resolvedAppName).exe"

                if ($silent) { Write-Log "EXE silent args set: $silent" "OK" }
                else { Write-Log "No EXE silent args found/inferred." "WARN" }
            }

            if ($installScope -eq "User") {
                Write-Log "Install Scope: USER - Consider deploying as 'Available' to user collections" "WARN"
            }
        }

        $uncMetaPath = Join-Path $uncVerFolder $MetadataFileName
        $fsMetaPath  = Get-FSPath -UncPath $uncMetaPath

        ($meta | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $fsMetaPath -Encoding UTF8 -Force
        Write-Log "Wrote metadata: $uncMetaPath" "OK"

        Write-Host ""
        Write-Host "=== STAGED ==="
        Write-Host "Package        : $id"
        Write-Host "AppName        : $resolvedAppName"
        Write-Host "Version(label) : $Version"
        Write-Host "WingetVersion  : $WingetVersion"
        Write-Host "Installer      : $($installer.Name) ($type) - $installerSize MB"
        Write-Host "InstallerTech  : $($meta.InstallerTech)$(if ($isPortable) { ' [PORTABLE - will copy to Program Files]' } else { '' })"
        Write-Host "InstallScope   : $installScope$(if ($installScope -eq 'User') { ' [WARNING: Per-user installer]' } else { '' })"
        Write-Host "SilentArgs     : $(if ($isPortable) { '(N/A - portable)' } else { $silent })"
        Write-Host "Publisher      : $(if ($meta.Publisher) { $meta.Publisher } else { '(not available)' })"
        Write-Host "ReleaseDate    : $releaseDate"
        Write-Host "Est. Install   : $estimatedTime minutes"
        Write-Host "Icon           : $(if ($iconFile) { $iconFile } else { '(not extracted)' })"
        Write-Host "SCCM Folder    : $uncVerFolder"
        Write-Host "Metadata       : $uncMetaPath"
        Write-Host ""
    }

    Write-Log "All packages staged successfully." "OK"
}
catch {
    Write-Log $_.Exception.Message "ERROR"
    throw
}

