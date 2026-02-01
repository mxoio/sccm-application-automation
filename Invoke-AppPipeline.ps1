<#
.SYNOPSIS
    Phase 4: Bulk application pipeline orchestrator.

.DESCRIPTION
    Reads a JSON config file containing a list of applications and orchestrates
    the full pipeline: Stage -> Create -> Deploy for each app.

    Features:
    - Auto-fetches latest version from winget (or uses pinned version)
    - Skips apps that already exist in SCCM at the same version
    - Continues on error, reports summary at end
    - Supports -WhatIf for dry-run preview

.PARAMETER ConfigPath
    Path to the JSON configuration file (see apps-config.example.json)

.PARAMETER StageOnly
    Only run the staging phase (download installers)

.PARAMETER CreateOnly
    Only run the create phase (create SCCM apps - assumes already staged)

.PARAMETER DeployOnly
    Only run the deploy phase (assumes apps already created)

.PARAMETER WhatIf
    Preview what would happen without making changes

.PARAMETER AppFilter
    Process only apps matching this filter (supports wildcards)

.EXAMPLE
    .\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json

.EXAMPLE
    .\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -WhatIf

.EXAMPLE
    .\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -AppFilter "VLC*"

.EXAMPLE
    .\Invoke-AppPipeline.ps1 -ConfigPath .\apps-config.json -StageOnly
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$ConfigPath,

    [switch]$StageOnly,
    [switch]$CreateOnly,
    [switch]$DeployOnly,

    [string]$AppFilter = "*",

    # Stop processing on first error (default: continue and report all failures)
    [switch]$StopOnFirstError,

    # Override config settings
    [string]$SiteCode,
    [string]$ContentRoot,
    [string]$DPName
)

# Import shared helpers
$helperModule = Join-Path $PSScriptRoot "SCCMPipelineHelpers.psm1"
if (Test-Path $helperModule) {
    Import-Module $helperModule -Force -ErrorAction SilentlyContinue
}

#region Logging

$script:LogFile = Join-Path $PSScriptRoot "pipeline-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","OK","SECTION")]$Level = "INFO"
    )
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $prefix = switch ($Level) {
        "INFO"    { "[INFO ]" }
        "WARN"    { "[WARN ]" }
        "ERROR"   { "[ERROR]" }
        "OK"      { "[ OK  ]" }
        "SECTION" { "[=====]" }
    }
    $line = "[$ts] $prefix $Message"

    switch ($Level) {
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "OK"      { Write-Host $line -ForegroundColor Green }
        "SECTION" { Write-Host $line -ForegroundColor Cyan }
        default   { Write-Host $line }
    }

    Add-Content -Path $script:LogFile -Value $line -ErrorAction SilentlyContinue
}

#endregion

#region Winget Helpers

function Get-WingetLatestVersion {
    <#
    .SYNOPSIS
        Gets the latest version of a package from winget.
    #>
    param([Parameter(Mandatory)][string]$PackageId)

    try {
        $output = & winget show --id $PackageId --accept-source-agreements 2>$null | Out-String

        if ($output -match 'Version:\s*(\S+)') {
            return $Matches[1].Trim()
        }

        Write-Log "Could not parse version from winget for $PackageId" "WARN"
        return $null
    }
    catch {
        Write-Log "Error querying winget for $PackageId`: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

#endregion

#region App Metadata Helpers

function Get-AppMetadata {
    <#
    .SYNOPSIS
        Reads the app.json metadata for a staged application.
    #>
    param(
        [Parameter(Mandatory)][string]$ContentRoot,
        [Parameter(Mandatory)][string]$AppName,
        [Parameter(Mandatory)][string]$Version
    )

    $appJsonPath = Join-Path $ContentRoot "Applications\$AppName\$Version\app.json"

    if (Test-Path $appJsonPath) {
        try {
            return Get-Content $appJsonPath -Raw | ConvertFrom-Json
        }
        catch {
            Write-Log "Could not read app.json at $appJsonPath`: $($_.Exception.Message)" "WARN"
            return $null
        }
    }

    return $null
}

function Show-UserScopeWarning {
    <#
    .SYNOPSIS
        Displays warnings for user-scoped applications that may have detection issues.
    #>
    param(
        [Parameter(Mandatory)]$AppMetadata,
        [Parameter(Mandatory)][string]$AppName
    )

    if ($AppMetadata.InstallScope -eq "User") {
        Write-Log "USER-SCOPED APP DETECTED: $AppName" "WARN"
        Write-Log "  This app installs to the user profile (e.g., %AppData%)" "WARN"
        Write-Log "  SCCM runs as SYSTEM, so detection may fail or install to wrong location" "WARN"
        Write-Log "  Consider: Install for current user only, or use file-based detection" "WARN"
        Write-Host ""

        return $true
    }

    return $false
}

#endregion

#region SCCM Helpers

function Test-SCCMAppExists {
    <#
    .SYNOPSIS
        Checks if an SCCM application with the given name already exists.
    #>
    param(
        [Parameter(Mandatory)][string]$AppName,
        [Parameter(Mandatory)][string]$SiteCode
    )

    try {
        # Ensure we're in the CM drive
        if ((Get-Location).Path -notlike "$SiteCode`:*") {
            Set-Location "$SiteCode`:"
        }

        $app = Get-CMApplication -Name $AppName -Fast -ErrorAction SilentlyContinue
        return ($null -ne $app)
    }
    catch {
        Write-Log "Error checking SCCM for app '$AppName': $($_.Exception.Message)" "WARN"
        return $false
    }
}

function Connect-CMSiteIfNeeded {
    param([Parameter(Mandatory)][string]$SiteCode)

    $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
    if (-not (Test-Path $modulePath -ErrorAction SilentlyContinue)) {
        throw "ConfigurationManager module not found. Run this on a machine with the SCCM console installed."
    }

    if (-not (Get-Module ConfigurationManager -ErrorAction SilentlyContinue)) {
        Import-Module $modulePath -Force
    }

    if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
        New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteCode | Out-Null
    }
}

#endregion

#region Main Pipeline

function Invoke-AppPipeline {
    param(
        [Parameter(Mandatory)]$AppConfig,
        [Parameter(Mandatory)]$Settings,
        [switch]$StageOnly,
        [switch]$CreateOnly,
        [switch]$DeployOnly,
        [switch]$WhatIf
    )

    $wingetId = $AppConfig.WingetId
    $appName = if ($AppConfig.AppName) { $AppConfig.AppName } else { ($wingetId -split '\.')[-1] }
    $collection = if ($AppConfig.Collection) { $AppConfig.Collection } else { $Settings.DefaultCollection }
    $purpose = if ($AppConfig.Purpose) { $AppConfig.Purpose } else { $Settings.DefaultPurpose }

    Write-Log "Processing: $appName ($wingetId)" "SECTION"

    # Determine version (pinned or latest)
    $version = $null
    if ($AppConfig.Version) {
        $version = $AppConfig.Version
        Write-Log "Using pinned version: $version"
    }
    else {
        Write-Log "Fetching latest version from winget..."
        $version = Get-WingetLatestVersion -PackageId $wingetId
        if (-not $version) {
            return @{ Status = "Failed"; Reason = "Could not determine version from winget" }
        }
        Write-Log "Latest version: $version" "OK"
    }

    $sccmAppName = "$appName - $version"

    # Check if already exists in SCCM (skip check if DeployOnly - we want to deploy existing apps)
    if (-not $StageOnly -and -not $DeployOnly) {
        $exists = Test-SCCMAppExists -AppName $sccmAppName -SiteCode $Settings.SiteCode
        if ($exists) {
            Write-Log "App '$sccmAppName' already exists in SCCM. Skipping." "WARN"
            return @{ Status = "Skipped"; Reason = "Already exists in SCCM" }
        }
    }

    # Build script paths
    $scriptsPath = $PSScriptRoot
    $stageScript = Join-Path $scriptsPath "Stage-WingetToSCCM.ps1"
    $createScript = Join-Path $scriptsPath "New-CMAppFromTemplate.ps1"
    $deployScript = Join-Path $scriptsPath "Deploy-Application.ps1"

    # Phase 1: Stage
    if (-not $CreateOnly -and -not $DeployOnly) {
        Write-Log "--- Stage Phase ---"

        $stageArgs = @{
            PackageId = $wingetId
            AppName = $appName
            Version = $version
            SccmContentRoot = $Settings.ContentRoot
        }

        if ($AppConfig.ExeSilentArgs) {
            $stageArgs.ExeSilentArgs = $AppConfig.ExeSilentArgs
        }

        if ($WhatIf) {
            Write-Log "[WhatIf] Would run: Stage-WingetToSCCM.ps1 -PackageId $wingetId -AppName $appName -Version $version"
        }
        else {
            try {
                & $stageScript @stageArgs
                if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne $null) {
                    throw "Stage script returned exit code $LASTEXITCODE"
                }
                Write-Log "Stage completed" "OK"

                # Check for user-scoped app and warn
                $appMeta = Get-AppMetadata -ContentRoot $Settings.ContentRoot -AppName $appName -Version $version
                if ($appMeta) {
                    $isUserScoped = Show-UserScopeWarning -AppMetadata $appMeta -AppName $appName
                    if ($isUserScoped) {
                        # Add to results for summary
                        $script:UserScopedApps += $appName
                    }
                }
            }
            catch {
                Write-Log "Stage failed: $($_.Exception.Message)" "ERROR"
                return @{ Status = "Failed"; Reason = "Stage failed: $($_.Exception.Message)" }
            }
        }

        if ($StageOnly) {
            return @{ Status = "Staged"; Reason = "Stage-only mode" }
        }
    }

    # Phase 2: Create
    if (-not $StageOnly -and -not $DeployOnly) {
        Write-Log "--- Create Phase ---"

        $createArgs = @{
            SiteCode = $Settings.SiteCode
            NewAppName = $appName
            NewVersion = $version
            AppContentRoot = $Settings.ContentRoot
        }

        if ($WhatIf) {
            Write-Log "[WhatIf] Would run: New-CMAppFromTemplate.ps1 -NewAppName $appName -NewVersion $version"
        }
        else {
            try {
                & $createScript @createArgs
                Write-Log "Create completed" "OK"
            }
            catch {
                Write-Log "Create failed: $($_.Exception.Message)" "ERROR"
                return @{ Status = "Failed"; Reason = "Create failed: $($_.Exception.Message)" }
            }
        }

        if ($CreateOnly) {
            return @{ Status = "Created"; Reason = "Create-only mode" }
        }
    }

    # Phase 3: Deploy
    if (-not $StageOnly -and -not $CreateOnly) {
        Write-Log "--- Deploy Phase ---"

        if (-not $collection) {
            Write-Log "No collection specified for $appName - skipping deploy" "WARN"
            return @{ Status = "Created"; Reason = "No collection specified" }
        }

        $deployArgs = @{
            SiteCode = $Settings.SiteCode
            AppName = $sccmAppName
            CollectionName = $collection
            DPName = $Settings.DPName
            Purpose = $purpose
            AutoCreateCollection = $true
        }

        if ($Settings.LimitingCollection) {
            $deployArgs.LimitingCollection = $Settings.LimitingCollection
        }

        if ($WhatIf) {
            Write-Log "[WhatIf] Would run: Deploy-Application.ps1 -AppName '$sccmAppName' -CollectionName '$collection'"
        }
        else {
            try {
                & $deployScript @deployArgs
                Write-Log "Deploy completed" "OK"
            }
            catch {
                Write-Log "Deploy failed: $($_.Exception.Message)" "ERROR"
                return @{ Status = "Failed"; Reason = "Deploy failed: $($_.Exception.Message)" }
            }
        }
    }

    return @{ Status = "Success"; Reason = "All phases completed" }
}

#endregion

#region Main

try {
    Write-Log "========================================" "SECTION"
    Write-Log "SCCM Application Pipeline - Phase 4" "SECTION"
    Write-Log "========================================" "SECTION"
    Write-Log "Config: $ConfigPath"
    Write-Log "Log: $script:LogFile"

    # Load config
    if (-not (Test-Path $ConfigPath)) {
        throw "Config file not found: $ConfigPath"
    }

    $config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    Write-Log "Loaded config with $($config.Applications.Count) applications" "OK"

    # Validate config schema
    if (Get-Command Test-ConfigSchema -ErrorAction SilentlyContinue) {
        Write-Log "Validating configuration schema..." "INFO"
        try {
            Test-ConfigSchema -Config $config | Out-Null
            Write-Log "Configuration schema validated" "OK"
        }
        catch {
            Write-Log "Configuration validation failed: $($_.Exception.Message)" "ERROR"
            throw
        }
    }

    # Merge settings with overrides
    $settings = @{
        SiteCode = if ($SiteCode) { $SiteCode } else { $config.Settings.SiteCode }
        ContentRoot = if ($ContentRoot) { $ContentRoot } else { $config.Settings.ContentRoot }
        DPName = if ($DPName) { $DPName } else { $config.Settings.DPName }
        DefaultCollection = $config.Settings.DefaultCollection
        DefaultPurpose = if ($config.Settings.DefaultPurpose) { $config.Settings.DefaultPurpose } else { "Available" }
        LimitingCollection = if ($config.Settings.LimitingCollection) { $config.Settings.LimitingCollection } else { "All Systems" }
    }

    Write-Log "SiteCode: $($settings.SiteCode)"
    Write-Log "ContentRoot: $($settings.ContentRoot)"
    Write-Log "DPName: $($settings.DPName)"

    # Connect to SCCM if needed
    if (-not $StageOnly -and -not $WhatIfPreference) {
        Write-Log "Connecting to SCCM site..."
        Connect-CMSiteIfNeeded -SiteCode $settings.SiteCode
        Write-Log "Connected to SCCM" "OK"
    }

    # Filter applications
    $apps = $config.Applications | Where-Object {
        $name = if ($_.AppName) { $_.AppName } else { ($_.WingetId -split '\.')[-1] }
        $name -like $AppFilter
    }

    Write-Log "Processing $($apps.Count) applications (filter: $AppFilter)"
    Write-Host ""

    # Track results
    $results = @()
    $script:UserScopedApps = @()

    foreach ($app in $apps) {
        $appName = if ($app.AppName) { $app.AppName } else { ($app.WingetId -split '\.')[-1] }

        # Per-app error isolation - catch errors but continue processing unless StopOnFirstError
        try {
            $result = Invoke-AppPipeline `
                -AppConfig $app `
                -Settings $settings `
                -StageOnly:$StageOnly `
                -CreateOnly:$CreateOnly `
                -DeployOnly:$DeployOnly `
                -WhatIf:$WhatIfPreference
        }
        catch {
            # Unexpected error (not a structured failure from Invoke-AppPipeline)
            $result = @{
                Status = "Failed"
                Reason = "Unexpected error: $($_.Exception.Message)"
            }
            Write-Log "App '$appName' failed with unexpected error: $($_.Exception.Message)" "ERROR"

            if ($StopOnFirstError) {
                $results += [PSCustomObject]@{
                    App = $appName
                    WingetId = $app.WingetId
                    Status = $result.Status
                    Reason = $result.Reason
                }
                Write-Log "StopOnFirstError is set - halting pipeline" "ERROR"
                break
            }
        }

        $results += [PSCustomObject]@{
            App = $appName
            WingetId = $app.WingetId
            Status = $result.Status
            Reason = $result.Reason
        }

        # Audit logging for each app
        if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
            Write-AuditLog -Action "Configure" -Target $appName -Result $result.Status -Details $result.Reason
        }

        Write-Host ""
    }

    # Summary
    Write-Log "========================================" "SECTION"
    Write-Log "SUMMARY" "SECTION"
    Write-Log "========================================" "SECTION"

    $success = ($results | Where-Object { $_.Status -eq "Success" }).Count
    $skipped = ($results | Where-Object { $_.Status -eq "Skipped" }).Count
    $failed = ($results | Where-Object { $_.Status -eq "Failed" }).Count
    $staged = ($results | Where-Object { $_.Status -eq "Staged" }).Count
    $created = ($results | Where-Object { $_.Status -eq "Created" }).Count

    Write-Log "Total: $($results.Count) | Success: $success | Skipped: $skipped | Failed: $failed"

    if ($staged -gt 0) { Write-Log "Staged only: $staged" }
    if ($created -gt 0) { Write-Log "Created only: $created" }

    Write-Host ""
    $results | Format-Table App, Status, Reason -AutoSize

    if ($failed -gt 0) {
        Write-Log "Some applications failed - check log for details: $script:LogFile" "WARN"
    }

    # Warn about user-scoped apps in summary
    if ($script:UserScopedApps.Count -gt 0) {
        Write-Host ""
        Write-Log "========================================" "SECTION"
        Write-Log "USER-SCOPED APP WARNINGS" "WARN"
        Write-Log "========================================" "SECTION"
        Write-Log "The following apps install to user profile and may have detection issues:" "WARN"
        foreach ($userApp in $script:UserScopedApps) {
            Write-Log "  - $userApp" "WARN"
        }
        Write-Log "Consider testing these apps manually or adjusting detection methods." "WARN"
    }

    Write-Log "Pipeline complete. Log saved to: $script:LogFile" "OK"
}
catch {
    Write-Log $_.Exception.Message "ERROR"
    throw
}
finally {
    # Return to filesystem
    if ((Get-Location).Path -like "*:") {
        Set-Location C:\
    }
}

#endregion
