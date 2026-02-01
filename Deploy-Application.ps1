[CmdletBinding(SupportsShouldProcess)]
param(
  [Parameter(Mandatory)]
  [string]$SiteCode,

  [Parameter(Mandatory)]
  [string]$AppName,              # "AppName - Version" e.g. "PuTTY - 0.83.0.0"

  [Parameter(Mandatory)]
  [string]$CollectionName,       # exact or partial

  # Prefer DP Group if you have one; otherwise leave blank
  [string]$DPGroupName = "",

  # Fallback when no DP Group exists - UPDATE TO YOUR DP FQDN
  [Parameter(Mandatory)]
  [string]$DPName,

  # Available (default) or Required
  [ValidateSet("Available","Required")]
  [string]$Purpose = "Available",

  # Auto-create collection if it doesn't exist (for "SCCM Software *" pattern)
  [switch]$AutoCreateCollection,

  # Limiting collection for new collections (default: All Systems)
  [string]$LimitingCollection = "All Systems"
)

# Import shared helpers
$helperModule = Join-Path $PSScriptRoot "SCCMPipelineHelpers.psm1"
if (Test-Path $helperModule) {
    Import-Module $helperModule -Force
}

# Validate input - extract app name from "AppName - Version" format
$appNamePart = if ($AppName -match '^(.+?)\s*-\s*[\d]') { $Matches[1].Trim() } else { $AppName }
try {
    if (Get-Command Assert-SafeAppName -ErrorAction SilentlyContinue) {
        Assert-SafeAppName -Name $appNamePart | Out-Null
    }
} catch {
    throw "Input validation failed: $($_.Exception.Message)"
}

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

# Local retry wrapper (fallback if helper module not available)
if (-not (Get-Command Invoke-WithRetry -ErrorAction SilentlyContinue)) {
  function Invoke-WithRetry {
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
}

# Connect to ConfigMgr
$modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
Import-Module $modulePath -Force

if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
  New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteCode | Out-Null
}
Set-Location "$SiteCode`:"

# Validate App exists
$app = Get-CMApplication -Name $AppName -ErrorAction SilentlyContinue
if (-not $app) { throw "Application not found (exact name required): $AppName" }
Write-Log "Found app: $($app.LocalizedDisplayName) (CI_ID: $($app.CI_ID))" "OK"

# Validate/find Collection (allow partial match)
$col = Get-CMCollection -Name $CollectionName -ErrorAction SilentlyContinue
if (-not $col) {
  # Try partial match first
  $matches = Get-CMCollection | Where-Object { $_.Name -like "*$CollectionName*" }
  if ($matches.Count -eq 1) {
    $col = $matches
    Write-Log "Collection not exact-match. Using closest match: $($col.Name)" "WARN"
  } elseif ($matches.Count -gt 1) {
    throw "CollectionName was ambiguous. Matches: $($matches.Name -join ', ')"
  } elseif ($AutoCreateCollection -and $CollectionName -like "SCCM Software *") {
    # Auto-create collection with "SCCM Software <AppName>" pattern
    Write-Log "Collection '$CollectionName' not found. Creating it..." "INFO"

    # Verify limiting collection exists
    $limitCol = Get-CMCollection -Name $LimitingCollection -ErrorAction SilentlyContinue
    if (-not $limitCol) {
      throw "Limiting collection not found: $LimitingCollection"
    }

    # Create the device collection
    $newCol = New-CMDeviceCollection `
      -Name $CollectionName `
      -LimitingCollectionName $LimitingCollection `
      -RefreshType Periodic `
      -RefreshSchedule (New-CMSchedule -RecurInterval Days -RecurCount 1) `
      -ErrorAction Stop

    $col = Get-CMCollection -Name $CollectionName -ErrorAction SilentlyContinue
    if ($col) {
      Write-Log "Created collection: $($col.Name) ($($col.CollectionID))" "OK"
    } else {
      throw "Failed to create collection: $CollectionName"
    }
  } else {
    throw "Collection not found: $CollectionName"
  }
}
Write-Log "Target collection: $($col.Name) ($($col.CollectionID))" "OK"

# Distribute content with retry logic
$didDistribute = $false

if ($DPGroupName) {
  $dpg = Get-CMDistributionPointGroup -Name $DPGroupName -ErrorAction SilentlyContinue
  if ($dpg) {
    Write-Log "Distributing content to DP Group: $DPGroupName" "INFO"
    Invoke-WithRetry -OperationName "Content distribution to DP Group" -MaxRetries 3 -DelaySeconds 10 -ScriptBlock {
      Start-CMContentDistribution -ApplicationName $AppName -DistributionPointGroupName $DPGroupName -ErrorAction Stop
    }
    $didDistribute = $true
  } else {
    Write-Log "DP Group '$DPGroupName' not found. Falling back to DP name '$DPName'." "WARN"
  }
}

if (-not $didDistribute) {
  if (-not $DPName) { throw "No DPGroupName found and no DPName provided." }
  Write-Log "Distributing content to DP: $DPName" "INFO"
  Invoke-WithRetry -OperationName "Content distribution to DP" -MaxRetries 3 -DelaySeconds 10 -ScriptBlock {
    Start-CMContentDistribution -ApplicationName $AppName -DistributionPointName $DPName -ErrorAction Stop
  }
}

Write-Log "Content distribution triggered." "OK"

# Deploy (idempotency: skip if already deployed to this collection)
$existing = Get-CMApplicationDeployment -Name $AppName -ErrorAction SilentlyContinue |
  Where-Object { $_.CollectionID -eq $col.CollectionID }

if ($existing) {
  Write-Log "Deployment already exists for '$AppName' to '$($col.Name)'. Skipping." "WARN"
  return
}

Write-Log "Creating deployment: Purpose=$Purpose" "INFO"

New-CMApplicationDeployment `
  -Name $AppName `
  -CollectionName $col.Name `
  -DeployAction Install `
  -DeployPurpose $Purpose `
  -UserNotification DisplayAll `
  -PersistOnWriteFilterDevice $false `
  -OverrideServiceWindow $false `
  -RebootOutsideServiceWindow $false | Out-Null

Write-Log "Deployment created successfully." "OK"

# Audit logging
if (Get-Command Write-AuditLog -ErrorAction SilentlyContinue) {
  Write-AuditLog -Action "Deploy" -Target $AppName -Result "Success" -Details "Deployed to collection '$($col.Name)' with purpose '$Purpose'"
}

