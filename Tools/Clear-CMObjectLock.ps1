<#
.SYNOPSIS
    Clears SCCM object locks that are blocking automation.

.DESCRIPTION
    Run this script ON the SCCM site server to clear orphaned
    object locks that prevent Set-CMApplicationSupersedence from working.

.PARAMETER SiteCode
    SCCM site code (required)

.PARAMETER CI_ID
    Optional: specific CI_ID to unlock

.PARAMETER ListOnly
    Just list current locks without clearing them

.EXAMPLE
    .\Clear-CMObjectLock.ps1 -SiteCode ABC -ListOnly
    .\Clear-CMObjectLock.ps1 -SiteCode ABC -CI_ID 16779763
    .\Clear-CMObjectLock.ps1 -SiteCode ABC  # clears ALL locks owned by current user
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$SiteCode,
    [int]$CI_ID,
    [switch]$ListOnly
)

$ns = "root\SMS\site_$SiteCode"

Write-Host "`n=== SCCM Object Lock Manager ===" -ForegroundColor Cyan
Write-Host "Site Code  : $SiteCode"
Write-Host "Namespace  : $ns"
Write-Host "Machine    : $env:COMPUTERNAME"
Write-Host "User       : $env:USERDOMAIN\$env:USERNAME"
Write-Host ""

# Method 1: Try CM cmdlets first (preferred)
$cmModulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1" -ErrorAction SilentlyContinue
$useCmdlets = $false

if ($cmModulePath -and (Test-Path $cmModulePath -ErrorAction SilentlyContinue)) {
    try {
        Import-Module $cmModulePath -Force -ErrorAction Stop
        if (-not (Get-PSDrive -Name $SiteCode -ErrorAction SilentlyContinue)) {
            New-PSDrive -Name $SiteCode -PSProvider CMSite -Root $SiteCode | Out-Null
        }
        Push-Location "$SiteCode`:"
        $useCmdlets = $true
        Write-Host "[OK] ConfigMgr cmdlets loaded" -ForegroundColor Green
    }
    catch {
        Write-Host "[WARN] Could not load CM cmdlets: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# List current locks
Write-Host "`n--- Current Object Locks ---" -ForegroundColor Yellow

if ($useCmdlets) {
    try {
        $locks = Get-CMObjectLock -ErrorAction Stop
        if ($locks) {
            $locks | Format-Table ObjectPath, LockID, AssignedUser, AssignedMachine, LockState -AutoSize
        } else {
            Write-Host "No object locks found via CM cmdlets." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "Get-CMObjectLock failed: $($_.Exception.Message)" -ForegroundColor Yellow
        $useCmdlets = $false
    }
}

if (-not $useCmdlets) {
    # Fallback to WMI
    try {
        $wmiLocks = Get-WmiObject -Namespace $ns -Class SMS_ObjectLock -ErrorAction Stop
        if ($wmiLocks) {
            $wmiLocks | Format-Table ObjectPath, LockID, AssignedUser, AssignedMachine, LockState -AutoSize
        } else {
            Write-Host "No object locks found via WMI." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "WMI query failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Make sure you're running this on the SCCM site server" -ForegroundColor Yellow
    }
}

if ($ListOnly) {
    Write-Host "`n[ListOnly mode - no changes made]" -ForegroundColor Cyan
    if ($useCmdlets) { Pop-Location }
    exit 0
}

# Clear locks
Write-Host "`n--- Clearing Locks ---" -ForegroundColor Yellow

if ($CI_ID) {
    $targetPath = "SMS_Application.CI_ID=$CI_ID"
    Write-Host "Target: $targetPath"
}

if ($useCmdlets) {
    try {
        if ($CI_ID) {
            # Get the specific application
            $app = Get-CMApplication -Fast | Where-Object { $_.CI_ID -eq $CI_ID }
            if ($app) {
                Write-Host "Found: $($app.LocalizedDisplayName) (CI_ID: $CI_ID)"
                Unlock-CMObject -InputObject $app -Force -ErrorAction Stop
                Write-Host "[OK] Lock cleared via Unlock-CMObject" -ForegroundColor Green
            } else {
                Write-Host "[WARN] Application with CI_ID $CI_ID not found" -ForegroundColor Yellow
            }
        } else {
            # Clear all locks for current user
            $locks = Get-CMObjectLock -ErrorAction SilentlyContinue
            if ($locks) {
                foreach ($lock in $locks) {
                    Write-Host "Clearing: $($lock.ObjectPath)"
                    # Try to get the object and unlock it
                    if ($lock.ObjectPath -match "SMS_Application\.CI_ID=(\d+)") {
                        $id = [int]$Matches[1]
                        $app = Get-CMApplication -Fast | Where-Object { $_.CI_ID -eq $id }
                        if ($app) {
                            Unlock-CMObject -InputObject $app -Force -ErrorAction SilentlyContinue
                            Write-Host "  [OK] Unlocked" -ForegroundColor Green
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Host "[ERROR] CM cmdlet unlock failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "Trying WMI method..." -ForegroundColor Yellow
        $useCmdlets = $false
    }
}

if (-not $useCmdlets) {
    # WMI fallback - invoke ReleaseLock method
    try {
        if ($CI_ID) {
            $lock = Get-WmiObject -Namespace $ns -Class SMS_ObjectLock -ErrorAction Stop |
                Where-Object { $_.ObjectPath -eq "SMS_Application.CI_ID=$CI_ID" }
        } else {
            $lock = Get-WmiObject -Namespace $ns -Class SMS_ObjectLock -ErrorAction Stop |
                Where-Object { $_.AssignedUser -like "*$env:USERNAME*" }
        }

        if ($lock) {
            foreach ($l in $lock) {
                Write-Host "Releasing lock: $($l.ObjectPath) (LockID: $($l.LockID))"

                # Method 1: Try ReleaseLock method
                $lockClass = [wmiclass]"\\.\$ns`:SMS_ObjectLockRequest"
                $result = $lockClass.ReleaseLock($l.LockID)

                if ($result.ReturnValue -eq 0) {
                    Write-Host "  [OK] Lock released via WMI ReleaseLock" -ForegroundColor Green
                } else {
                    Write-Host "  [WARN] ReleaseLock returned: $($result.ReturnValue)" -ForegroundColor Yellow

                    # Method 2: Try direct delete
                    Write-Host "  Trying direct WMI delete..."
                    $l.Delete()
                    Write-Host "  [OK] Lock deleted directly" -ForegroundColor Green
                }
            }
        } else {
            Write-Host "No matching locks found to clear." -ForegroundColor Green
        }
    }
    catch {
        Write-Host "[ERROR] WMI unlock failed: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Verify
Write-Host "`n--- Verification ---" -ForegroundColor Yellow
Start-Sleep -Seconds 2

if ($useCmdlets) {
    $remaining = Get-CMObjectLock -ErrorAction SilentlyContinue
    Pop-Location
} else {
    $remaining = Get-WmiObject -Namespace $ns -Class SMS_ObjectLock -ErrorAction SilentlyContinue
}

if ($remaining) {
    Write-Host "Remaining locks:" -ForegroundColor Yellow
    $remaining | Format-Table ObjectPath, AssignedUser, AssignedMachine -AutoSize
} else {
    Write-Host "[OK] No locks remaining" -ForegroundColor Green
}

Write-Host "`n=== Complete ===" -ForegroundColor Cyan
