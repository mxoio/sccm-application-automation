<#
.SYNOPSIS
    Interactive setup wizard for the SCCM Application Automation Pipeline.

.DESCRIPTION
    This script helps you configure the pipeline for your SCCM environment by:
    - Validating SCCM connectivity
    - Creating/updating apps-config.json with your site settings
    - Adding applications to the config interactively
    - Validating winget availability

.PARAMETER ConfigPath
    Path to save the configuration file. Defaults to apps-config.json in the script directory.

.PARAMETER SkipValidation
    Skip SCCM and winget validation checks.

.EXAMPLE
    .\Initialize-AppPipeline.ps1

.EXAMPLE
    .\Initialize-AppPipeline.ps1 -ConfigPath "C:\SCCM\my-apps.json"
#>

[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot "apps-config.json"),
    [switch]$SkipValidation
)

# Import shared helpers
$helperModule = Join-Path $PSScriptRoot "SCCMPipelineHelpers.psm1"
if (Test-Path $helperModule) {
    Import-Module $helperModule -Force -ErrorAction SilentlyContinue
}

#region Helper Functions

function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step {
    param([string]$Text)
    Write-Host "[*] $Text" -ForegroundColor Yellow
}

function Write-Success {
    param([string]$Text)
    Write-Host "[OK] $Text" -ForegroundColor Green
}

function Write-Failure {
    param([string]$Text)
    Write-Host "[X] $Text" -ForegroundColor Red
}

function Read-UserInput {
    param(
        [string]$Prompt,
        [string]$Default = "",
        [switch]$Required
    )

    $displayPrompt = $Prompt
    if ($Default) {
        $displayPrompt += " [$Default]"
    }
    $displayPrompt += ": "

    do {
        $input = Read-Host $displayPrompt
        if ([string]::IsNullOrWhiteSpace($input)) {
            $input = $Default
        }

        if ($Required -and [string]::IsNullOrWhiteSpace($input)) {
            Write-Host "  This field is required." -ForegroundColor Yellow
        }
    } while ($Required -and [string]::IsNullOrWhiteSpace($input))

    return $input
}

function Test-SCCMConnection {
    param([string]$SiteCode)

    try {
        $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
        if (-not (Test-Path $modulePath)) {
            return @{ Success = $false; Message = "SCCM Console not installed (ConfigurationManager.psd1 not found)" }
        }

        Import-Module $modulePath -Force -ErrorAction Stop

        if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteCode -ErrorAction Stop | Out-Null
        }

        Push-Location "$SiteCode`:"
        $site = Get-CMSite -ErrorAction Stop
        Pop-Location

        return @{ Success = $true; Message = "Connected to site: $($site.SiteName) ($SiteCode)" }
    }
    catch {
        return @{ Success = $false; Message = $_.Exception.Message }
    }
}

function Test-WingetAvailable {
    try {
        $version = & winget --version 2>$null
        if ($version) {
            return @{ Success = $true; Message = "winget version: $version" }
        }
        return @{ Success = $false; Message = "winget not responding" }
    }
    catch {
        return @{ Success = $false; Message = "winget not installed or not in PATH" }
    }
}

function Get-WingetAppInfo {
    param([string]$SearchTerm)

    Write-Host "  Searching winget for '$SearchTerm'..." -ForegroundColor Gray
    $results = & winget search $SearchTerm --accept-source-agreements 2>$null | Out-String

    # Parse results (skip header lines)
    $lines = $results -split "`n" | Where-Object { $_ -match '\S' } | Select-Object -Skip 2

    $apps = @()
    foreach ($line in $lines) {
        if ($line -match '^(.+?)\s{2,}(\S+)\s+(\S+)') {
            $apps += [PSCustomObject]@{
                Name = $Matches[1].Trim()
                Id = $Matches[2].Trim()
                Version = $Matches[3].Trim()
            }
        }
    }

    return $apps | Select-Object -First 10
}

#endregion

#region Main

Write-Header "SCCM Application Automation Pipeline - Setup Wizard"

Write-Host "This wizard will help you configure the pipeline for your environment."
Write-Host "You'll need:"
Write-Host "  - SCCM Console installed on this machine"
Write-Host "  - Your SCCM site code (e.g., PS1, HLL, ABC)"
Write-Host "  - A network share for application content"
Write-Host "  - winget installed for downloading packages"
Write-Host ""

# Load existing config if present
$existingConfig = $null
if (Test-Path $ConfigPath) {
    Write-Host "Found existing config: $ConfigPath" -ForegroundColor Cyan
    $loadExisting = Read-Host "Load existing settings? (Y/n)"
    if ($loadExisting -ne 'n') {
        $existingConfig = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        Write-Success "Loaded existing configuration"
    }
}

Write-Header "Step 1: SCCM Site Settings"

# Site Code
$defaultSiteCode = if ($existingConfig) { $existingConfig.Settings.SiteCode } else { "" }
$siteCode = Read-UserInput -Prompt "SCCM Site Code" -Default $defaultSiteCode -Required

# Validate SCCM connection
if (-not $SkipValidation) {
    Write-Step "Validating SCCM connection..."
    $sccmTest = Test-SCCMConnection -SiteCode $siteCode
    if ($sccmTest.Success) {
        Write-Success $sccmTest.Message
    } else {
        Write-Failure $sccmTest.Message
        $continue = Read-Host "Continue anyway? (y/N)"
        if ($continue -ne 'y') {
            Write-Host "Setup cancelled." -ForegroundColor Yellow
            exit 1
        }
    }
}

# Content Root
$defaultContentRoot = if ($existingConfig) { $existingConfig.Settings.ContentRoot } else { "\\\\SERVER\\Share\\Applications" }
Write-Host ""
Write-Host "Content Root is where application installers will be stored."
Write-Host "This should be a UNC path accessible by SCCM (e.g., \\\\FileServer\\SCCM-Content\\Applications)"
$contentRoot = Read-UserInput -Prompt "Content Root Path" -Default $defaultContentRoot -Required

# Validate path
if (-not $SkipValidation) {
    Write-Step "Validating content root path..."
    if (Test-Path $contentRoot -ErrorAction SilentlyContinue) {
        Write-Success "Path exists and is accessible"
    } else {
        Write-Failure "Path does not exist or is not accessible"
        $create = Read-Host "Attempt to create it? (y/N)"
        if ($create -eq 'y') {
            try {
                New-Item -Path $contentRoot -ItemType Directory -Force | Out-Null
                Write-Success "Created: $contentRoot"
            } catch {
                Write-Failure "Could not create path: $($_.Exception.Message)"
            }
        }
    }
}

# Distribution Point
$defaultDP = if ($existingConfig) { $existingConfig.Settings.DPName } else { "" }
Write-Host ""
Write-Host "Distribution Point is the FQDN of your DP (e.g., sccm-dp01.contoso.com)"
$dpName = Read-UserInput -Prompt "Distribution Point FQDN" -Default $defaultDP -Required

# Limiting Collection
$defaultLimiting = if ($existingConfig) { $existingConfig.Settings.LimitingCollection } else { "All Systems" }
$limitingCollection = Read-UserInput -Prompt "Limiting Collection for new collections" -Default $defaultLimiting

# Default Purpose
$defaultPurpose = if ($existingConfig) { $existingConfig.Settings.DefaultPurpose } else { "Available" }
Write-Host ""
Write-Host "Default deployment purpose: Available (user must install) or Required (auto-install)"
$purpose = Read-UserInput -Prompt "Default Purpose (Available/Required)" -Default $defaultPurpose

Write-Header "Step 2: Validate winget"

if (-not $SkipValidation) {
    Write-Step "Checking winget availability..."
    $wingetTest = Test-WingetAvailable
    if ($wingetTest.Success) {
        Write-Success $wingetTest.Message
    } else {
        Write-Failure $wingetTest.Message
        Write-Host "  winget is required to download application installers." -ForegroundColor Yellow
        Write-Host "  Install from: https://github.com/microsoft/winget-cli/releases" -ForegroundColor Yellow
    }
}

Write-Header "Step 3: Configure Applications"

# Start with existing apps or empty
$applications = @()
if ($existingConfig -and $existingConfig.Applications) {
    $applications = [System.Collections.ArrayList]@($existingConfig.Applications)
    Write-Host "Loaded $($applications.Count) existing applications from config."
    Write-Host ""

    # Show existing
    Write-Host "Current applications:" -ForegroundColor Cyan
    $i = 1
    foreach ($app in $applications) {
        Write-Host "  $i. $($app.AppName) ($($app.WingetId)) -> $($app.Collection)"
        $i++
    }
    Write-Host ""
}

# Add new applications
$addMore = Read-Host "Add new applications? (Y/n)"
if ($addMore -ne 'n') {
    Write-Host ""
    Write-Host "For each app, you can search by name or enter the winget ID directly."
    Write-Host "Type 'done' when finished adding applications."
    Write-Host ""

    while ($true) {
        $search = Read-Host "Search for app (or 'done' to finish)"
        if ($search -eq 'done' -or [string]::IsNullOrWhiteSpace($search)) {
            break
        }

        # Check if it's a direct winget ID (contains a dot)
        if ($search -match '^\w+\.\w+') {
            $wingetId = $search
            Write-Host "  Using winget ID: $wingetId" -ForegroundColor Gray
        } else {
            # Search winget
            $results = Get-WingetAppInfo -SearchTerm $search
            if ($results.Count -eq 0) {
                Write-Host "  No results found." -ForegroundColor Yellow
                continue
            }

            Write-Host ""
            Write-Host "  Results:" -ForegroundColor Cyan
            $i = 1
            foreach ($result in $results) {
                Write-Host "    $i. $($result.Name) [$($result.Id)] v$($result.Version)"
                $i++
            }
            Write-Host ""

            $selection = Read-Host "  Select number (or press Enter to skip)"
            if ([string]::IsNullOrWhiteSpace($selection)) { continue }

            $idx = [int]$selection - 1
            if ($idx -lt 0 -or $idx -ge $results.Count) {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
                continue
            }

            $wingetId = $results[$idx].Id
        }

        # Get app name with validation
        $defaultAppName = ($wingetId -split '\.')[-1]
        $appName = $null
        while (-not $appName) {
            $appNameInput = Read-UserInput -Prompt "  Display name" -Default $defaultAppName
            try {
                if (Get-Command Assert-SafeAppName -ErrorAction SilentlyContinue) {
                    Assert-SafeAppName -Name $appNameInput | Out-Null
                }
                $appName = $appNameInput
            } catch {
                Write-Host "  Invalid app name: $($_.Exception.Message)" -ForegroundColor Red
                Write-Host "  Please enter a valid app name (no special characters, max 100 chars)" -ForegroundColor Yellow
            }
        }

        # Get collection name
        $defaultCollection = "SCCM Software $appName"
        $collection = Read-UserInput -Prompt "  Collection name" -Default $defaultCollection

        # Optional: silent args
        $silentArgs = Read-Host "  Custom silent args (press Enter to auto-detect)"

        # Add to list
        $newApp = [PSCustomObject]@{
            WingetId = $wingetId
            AppName = $appName
            Collection = $collection
        }

        if (-not [string]::IsNullOrWhiteSpace($silentArgs)) {
            $newApp | Add-Member -NotePropertyName "ExeSilentArgs" -NotePropertyValue $silentArgs
        }

        $applications.Add($newApp) | Out-Null
        Write-Success "Added: $appName ($wingetId)"
        Write-Host ""
    }
}

Write-Header "Step 4: Save Configuration"

# Build config object
$config = [PSCustomObject]@{
    Settings = [PSCustomObject]@{
        SiteCode = $siteCode
        ContentRoot = $contentRoot
        DPName = $dpName
        LimitingCollection = $limitingCollection
        DefaultCollection = $null
        DefaultPurpose = $purpose
    }
    Applications = $applications
}

# Show summary
Write-Host "Configuration Summary:" -ForegroundColor Cyan
Write-Host "  Site Code        : $siteCode"
Write-Host "  Content Root     : $contentRoot"
Write-Host "  Distribution Point: $dpName"
Write-Host "  Limiting Collection: $limitingCollection"
Write-Host "  Default Purpose  : $purpose"
Write-Host "  Applications     : $($applications.Count)"
Write-Host ""
Write-Host "Config will be saved to: $ConfigPath"
Write-Host ""

$confirm = Read-Host "Save configuration? (Y/n)"
if ($confirm -eq 'n') {
    Write-Host "Configuration not saved." -ForegroundColor Yellow
    exit 0
}

# Save
$config | ConvertTo-Json -Depth 5 | Set-Content $ConfigPath -Encoding UTF8
Write-Success "Configuration saved to: $ConfigPath"

Write-Header "Setup Complete!"

Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  1. Review your config file:"
Write-Host "     $ConfigPath" -ForegroundColor Gray
Write-Host ""
Write-Host "  2. Run the pipeline:"
Write-Host "     .\Invoke-AppPipeline.ps1 -ConfigPath `"$ConfigPath`"" -ForegroundColor Gray
Write-Host ""
Write-Host "  3. Or run in preview mode first:"
Write-Host "     .\Invoke-AppPipeline.ps1 -ConfigPath `"$ConfigPath`" -WhatIf" -ForegroundColor Gray
Write-Host ""
Write-Host "  4. Process a single app:"
Write-Host "     .\Invoke-AppPipeline.ps1 -ConfigPath `"$ConfigPath`" -AppFilter `"7-Zip`"" -ForegroundColor Gray
Write-Host ""

#endregion
