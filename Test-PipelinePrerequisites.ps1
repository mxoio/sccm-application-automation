<#
.SYNOPSIS
    Pre-flight validation script for the SCCM Application Automation Pipeline.

.DESCRIPTION
    Checks all prerequisites before running the pipeline:
    - SCCM Console/Module availability
    - SCCM site connectivity
    - winget availability and version
    - Network paths accessible
    - Config file valid

    Returns detailed status for each check and overall pass/fail.

.PARAMETER ConfigPath
    Path to the apps-config.json file to validate.

.PARAMETER SiteCode
    SCCM site code (if not using config file).

.PARAMETER ContentRoot
    Content root path (if not using config file).

.PARAMETER Quiet
    Only output pass/fail, no details.

.EXAMPLE
    .\Test-PipelinePrerequisites.ps1 -ConfigPath .\apps-config.json

.EXAMPLE
    .\Test-PipelinePrerequisites.ps1 -SiteCode "HLL" -ContentRoot "\\Server\Share"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath,
    [string]$SiteCode,
    [string]$ContentRoot,
    [string]$DPName,
    [switch]$Quiet
)

#region Helper Functions

function Write-Check {
    param(
        [string]$Name,
        [string]$Status,  # Pass, Fail, Warn, Skip
        [string]$Message
    )

    if ($Quiet -and $Status -notin @("Fail", "Warn")) { return }

    $icon = switch ($Status) {
        "Pass" { "[OK]" }
        "Fail" { "[X]" }
        "Warn" { "[!]" }
        "Skip" { "[-]" }
        default { "[?]" }
    }

    $color = switch ($Status) {
        "Pass" { "Green" }
        "Fail" { "Red" }
        "Warn" { "Yellow" }
        "Skip" { "Gray" }
        default { "White" }
    }

    $line = "$icon $Name"
    if ($Message) { $line += ": $Message" }

    Write-Host $line -ForegroundColor $color
}

function Test-WingetInstalled {
    try {
        $version = & winget --version 2>$null
        if ($version) {
            return @{ Success = $true; Version = $version.Trim() }
        }
        return @{ Success = $false; Message = "winget not responding" }
    }
    catch {
        return @{ Success = $false; Message = "winget not found in PATH" }
    }
}

function Test-WingetDownloadSupport {
    try {
        $help = & winget download --help 2>$null | Out-String
        if ($help -match 'download') {
            return @{ Success = $true }
        }
        return @{ Success = $false; Message = "winget download command not available" }
    }
    catch {
        return @{ Success = $false; Message = "winget download not supported - update winget" }
    }
}

function Test-SCCMConsole {
    $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1" -ErrorAction SilentlyContinue

    if (-not $env:SMS_ADMIN_UI_PATH) {
        return @{ Success = $false; Message = "SMS_ADMIN_UI_PATH not set - SCCM Console not installed?" }
    }

    if (-not (Test-Path $modulePath -ErrorAction SilentlyContinue)) {
        return @{ Success = $false; Message = "ConfigurationManager.psd1 not found at expected path" }
    }

    return @{ Success = $true; Path = $modulePath }
}

function Test-SCCMConnection {
    param([string]$SiteCode)

    try {
        $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
        Import-Module $modulePath -Force -ErrorAction Stop

        if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteCode -ErrorAction Stop | Out-Null
        }

        Push-Location "$SiteCode`:" -ErrorAction Stop
        $site = Get-CMSite -ErrorAction Stop
        Pop-Location

        return @{ Success = $true; SiteName = $site.SiteName; Version = $site.Version }
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Test-NetworkPath {
    param([string]$Path)

    if (-not $Path) {
        return @{ Success = $false; Message = "Path not specified" }
    }

    # Handle UNC paths from CM drive context
    $fsPath = if ($Path -match '^\\\\') {
        "Microsoft.PowerShell.Core\FileSystem::$Path"
    } else {
        $Path
    }

    try {
        if (Test-Path -LiteralPath $fsPath -ErrorAction Stop) {
            return @{ Success = $true }
        }
        return @{ Success = $false; Message = "Path does not exist" }
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Test-ConfigFile {
    param([string]$Path)

    if (-not $Path) {
        return @{ Success = $false; Message = "No config path specified" }
    }

    if (-not (Test-Path $Path -ErrorAction SilentlyContinue)) {
        return @{ Success = $false; Message = "Config file not found" }
    }

    try {
        $config = Get-Content $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

        # Validate required fields
        $errors = @()

        if (-not $config.Settings) {
            $errors += "Missing 'Settings' section"
        } else {
            if (-not $config.Settings.SiteCode) { $errors += "Missing Settings.SiteCode" }
            if (-not $config.Settings.ContentRoot) { $errors += "Missing Settings.ContentRoot" }
            if (-not $config.Settings.DPName) { $errors += "Missing Settings.DPName" }
        }

        if (-not $config.Applications -or $config.Applications.Count -eq 0) {
            $errors += "No applications defined"
        } else {
            $i = 0
            foreach ($app in $config.Applications) {
                $i++
                if (-not $app.WingetId) {
                    $errors += "Application #$i missing WingetId"
                }
            }
        }

        if ($errors.Count -gt 0) {
            return @{ Success = $false; Message = ($errors -join "; "); Config = $config }
        }

        return @{ Success = $true; Config = $config; AppCount = $config.Applications.Count }
    }
    catch {
        return @{ Success = $false; Message = "Invalid JSON: $($_.Exception.Message)" }
    }
}

function Test-DistributionPoint {
    param([string]$SiteCode, [string]$DPName)

    try {
        Push-Location "$SiteCode`:" -ErrorAction Stop
        $dp = Get-CMDistributionPoint -SiteSystemServerName $DPName -ErrorAction SilentlyContinue
        Pop-Location

        if ($dp) {
            return @{ Success = $true }
        }
        return @{ Success = $false; Message = "DP not found: $DPName" }
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

#endregion

#region Main

$allPassed = $true
$warnings = 0

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host " SCCM Application Pipeline - Pre-flight Check" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Load config if provided
$config = $null
if ($ConfigPath) {
    Write-Host "Config File Validation" -ForegroundColor Yellow
    Write-Host "----------------------"

    $configTest = Test-ConfigFile -Path $ConfigPath
    if ($configTest.Success) {
        Write-Check -Name "Config file valid" -Status "Pass" -Message "$($configTest.AppCount) applications defined"
        $config = $configTest.Config

        # Use config values if not overridden
        if (-not $SiteCode) { $SiteCode = $config.Settings.SiteCode }
        if (-not $ContentRoot) { $ContentRoot = $config.Settings.ContentRoot }
        if (-not $DPName) { $DPName = $config.Settings.DPName }
    } else {
        Write-Check -Name "Config file valid" -Status "Fail" -Message $configTest.Message
        $allPassed = $false
    }
    Write-Host ""
}

# winget checks
Write-Host "Winget Validation" -ForegroundColor Yellow
Write-Host "-----------------"

$wingetTest = Test-WingetInstalled
if ($wingetTest.Success) {
    Write-Check -Name "winget installed" -Status "Pass" -Message "Version $($wingetTest.Version)"

    $downloadTest = Test-WingetDownloadSupport
    if ($downloadTest.Success) {
        Write-Check -Name "winget download support" -Status "Pass"
    } else {
        Write-Check -Name "winget download support" -Status "Fail" -Message $downloadTest.Message
        $allPassed = $false
    }
} else {
    Write-Check -Name "winget installed" -Status "Fail" -Message $wingetTest.Message
    Write-Check -Name "winget download support" -Status "Skip"
    $allPassed = $false
}
Write-Host ""

# SCCM checks
Write-Host "SCCM Validation" -ForegroundColor Yellow
Write-Host "---------------"

$consoleTest = Test-SCCMConsole
if ($consoleTest.Success) {
    Write-Check -Name "SCCM Console installed" -Status "Pass"

    if ($SiteCode) {
        $siteTest = Test-SCCMConnection -SiteCode $SiteCode
        if ($siteTest.Success) {
            Write-Check -Name "SCCM site connection" -Status "Pass" -Message "$($siteTest.SiteName) ($SiteCode)"

            # Check DP
            if ($DPName) {
                $dpTest = Test-DistributionPoint -SiteCode $SiteCode -DPName $DPName
                if ($dpTest.Success) {
                    Write-Check -Name "Distribution Point" -Status "Pass" -Message $DPName
                } else {
                    Write-Check -Name "Distribution Point" -Status "Fail" -Message $dpTest.Message
                    $allPassed = $false
                }
            } else {
                Write-Check -Name "Distribution Point" -Status "Skip" -Message "No DP specified"
            }
        } else {
            Write-Check -Name "SCCM site connection" -Status "Fail" -Message $siteTest.Message
            Write-Check -Name "Distribution Point" -Status "Skip"
            $allPassed = $false
        }
    } else {
        Write-Check -Name "SCCM site connection" -Status "Skip" -Message "No SiteCode specified"
        Write-Check -Name "Distribution Point" -Status "Skip"
    }
} else {
    Write-Check -Name "SCCM Console installed" -Status "Fail" -Message $consoleTest.Message
    Write-Check -Name "SCCM site connection" -Status "Skip"
    Write-Check -Name "Distribution Point" -Status "Skip"
    $allPassed = $false
}
Write-Host ""

# Network path checks
Write-Host "Network Path Validation" -ForegroundColor Yellow
Write-Host "-----------------------"

if ($ContentRoot) {
    $pathTest = Test-NetworkPath -Path $ContentRoot
    if ($pathTest.Success) {
        Write-Check -Name "Content root accessible" -Status "Pass" -Message $ContentRoot
    } else {
        Write-Check -Name "Content root accessible" -Status "Fail" -Message "$ContentRoot - $($pathTest.Message)"
        $allPassed = $false
    }
} else {
    Write-Check -Name "Content root accessible" -Status "Skip" -Message "No ContentRoot specified"
}

# Check local staging folder
$stagingPath = "C:\Winget-Staging"
if (Test-Path $stagingPath -ErrorAction SilentlyContinue) {
    Write-Check -Name "Local staging folder" -Status "Pass" -Message $stagingPath
} else {
    Write-Check -Name "Local staging folder" -Status "Warn" -Message "Will be created: $stagingPath"
    $warnings++
}

# Disk space check for local staging
$stagingDrive = "C:"
try {
    $disk = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='$stagingDrive'" -ErrorAction SilentlyContinue
    if ($disk) {
        $freeGB = [math]::Round($disk.FreeSpace / 1GB, 2)
        if ($freeGB -lt 5) {
            Write-Check -Name "Staging disk space" -Status "Fail" -Message "Only $freeGB GB free on $stagingDrive (need at least 5 GB)"
            $allPassed = $false
        } elseif ($freeGB -lt 10) {
            Write-Check -Name "Staging disk space" -Status "Warn" -Message "$freeGB GB free on $stagingDrive (10+ GB recommended)"
            $warnings++
        } else {
            Write-Check -Name "Staging disk space" -Status "Pass" -Message "$freeGB GB free on $stagingDrive"
        }
    }
} catch {
    Write-Check -Name "Staging disk space" -Status "Skip" -Message "Could not query disk space"
}

# Write permission test on content root
if ($ContentRoot) {
    try {
        $testFileName = ".sccm-write-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        $testFilePath = Join-Path $ContentRoot $testFileName

        # Handle UNC paths
        $fsTestPath = if ($testFilePath -match '^\\\\') {
            "Microsoft.PowerShell.Core\FileSystem::$testFilePath"
        } else {
            $testFilePath
        }

        "test" | Set-Content -Path $fsTestPath -ErrorAction Stop
        Remove-Item -Path $fsTestPath -Force -ErrorAction SilentlyContinue
        Write-Check -Name "Content root writable" -Status "Pass" -Message "Write access confirmed"
    } catch {
        Write-Check -Name "Content root writable" -Status "Fail" -Message "Cannot write to content root: $($_.Exception.Message)"
        $allPassed = $false
    }
}

Write-Host ""

# Additional SCCM checks (if connected)
if ($consoleTest.Success -and $SiteCode) {
    Write-Host "Extended SCCM Validation" -ForegroundColor Yellow
    Write-Host "------------------------"

    # SCCM console version check
    try {
        $consoleVer = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\SMS\Setup" -ErrorAction SilentlyContinue).UIVersion
        if ($consoleVer) {
            Write-Check -Name "SCCM Console version" -Status "Pass" -Message "v$consoleVer"
        } else {
            Write-Check -Name "SCCM Console version" -Status "Skip" -Message "Version not found in registry"
        }
    } catch {
        Write-Check -Name "SCCM Console version" -Status "Skip" -Message "Could not read console version"
    }

    # Check PowerShell execution policy
    try {
        $execPolicy = Get-ExecutionPolicy -Scope LocalMachine -ErrorAction SilentlyContinue
        if ($execPolicy -eq "Restricted") {
            Write-Check -Name "Execution Policy" -Status "Warn" -Message "$execPolicy - may need to be changed for scripts to run"
            $warnings++
        } elseif ($execPolicy -in @("AllSigned", "RemoteSigned", "Unrestricted", "Bypass")) {
            Write-Check -Name "Execution Policy" -Status "Pass" -Message $execPolicy
        } else {
            Write-Check -Name "Execution Policy" -Status "Warn" -Message $execPolicy
            $warnings++
        }
    } catch {
        Write-Check -Name "Execution Policy" -Status "Skip" -Message "Could not determine execution policy"
    }

    Write-Host ""
}

# Summary
Write-Host "============================================" -ForegroundColor Cyan
if ($allPassed) {
    Write-Host " PRE-FLIGHT CHECK: PASSED" -ForegroundColor Green
    if ($warnings -gt 0) {
        Write-Host " ($warnings warnings)" -ForegroundColor Yellow
    }
    $exitCode = 0
} else {
    Write-Host " PRE-FLIGHT CHECK: FAILED" -ForegroundColor Red
    Write-Host " Fix the issues above before running the pipeline." -ForegroundColor Yellow
    $exitCode = 1
}
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

exit $exitCode

#endregion
