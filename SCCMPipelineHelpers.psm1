<#
.SYNOPSIS
    Shared helper module for SCCM Application Automation Pipeline.

.DESCRIPTION
    Contains common functions used across all pipeline scripts:
    - Write-Log: Standardized logging
    - Invoke-WithRetry: Retry logic wrapper
    - Assert-SafeAppName: Input sanitization
    - Write-AuditLog: Audit logging for compliance
    - Get-FSPath: FileSystem path helper for UNC paths
#>

#region Logging Functions

function Write-Log {
    <#
    .SYNOPSIS
        Writes a timestamped log message to console with color coding.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet("INFO", "WARN", "ERROR", "OK", "SECTION")]
        [string]$Level = "INFO"
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
}

function Write-AuditLog {
    <#
    .SYNOPSIS
        Writes an audit log entry for compliance tracking.

    .DESCRIPTION
        Creates JSON-formatted audit entries with user, computer, action, and result.
        Logs to both a file and Windows Event Log when available.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Stage", "Create", "Deploy", "Delete", "Validate", "Configure")]
        [string]$Action,

        [Parameter(Mandatory)]
        [string]$Target,

        [Parameter(Mandatory)]
        [ValidateSet("Success", "Failed", "Skipped", "Warning")]
        [string]$Result,

        [string]$Details,

        [string]$LogPath = "$env:ProgramData\SCCM-Automation\audit.log"
    )

    $entry = [PSCustomObject]@{
        Timestamp = Get-Date -Format "o"
        User      = "$env:USERDOMAIN\$env:USERNAME"
        Computer  = $env:COMPUTERNAME
        Action    = $Action
        Target    = $Target
        Result    = $Result
        Details   = $Details
    }

    # Ensure directory exists
    $dir = Split-Path $LogPath -Parent
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    # Append JSON line
    $entry | ConvertTo-Json -Compress | Add-Content -Path $LogPath -ErrorAction SilentlyContinue

    # Also write to Windows Event Log if available
    try {
        # Register event source if needed (requires admin on first run)
        $source = "SCCM-Automation"
        if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
            [System.Diagnostics.EventLog]::CreateEventSource($source, "Application")
        }

        $eventType = switch ($Result) {
            "Success" { [System.Diagnostics.EventLogEntryType]::Information }
            "Failed"  { [System.Diagnostics.EventLogEntryType]::Error }
            "Warning" { [System.Diagnostics.EventLogEntryType]::Warning }
            default   { [System.Diagnostics.EventLogEntryType]::Information }
        }

        Write-EventLog -LogName Application -Source $source -EventId 1000 -EntryType $eventType -Message "$Action - $Target - $Result$(if ($Details) { ": $Details" })"
    }
    catch {
        # Event log writing is best-effort, don't fail on errors
    }
}

#endregion

#region Retry Logic

function Invoke-WithRetry {
    <#
    .SYNOPSIS
        Executes a script block with retry logic.

    .DESCRIPTION
        Wraps an operation with configurable retry attempts and delay.
        Useful for network operations that may transiently fail.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ScriptBlock]$ScriptBlock,

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

#endregion

#region Input Validation

function Assert-SafeAppName {
    <#
    .SYNOPSIS
        Validates an application name for safety.

    .DESCRIPTION
        Rejects path traversal attempts, invalid characters, and overly long names.
        Throws an exception if validation fails.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [int]$MaxLength = 100
    )

    # Check for empty/whitespace
    if ([string]::IsNullOrWhiteSpace($Name)) {
        throw "App name cannot be empty or whitespace"
    }

    # Reject path traversal attempts
    if ($Name -match '\.\.[\\/]|[\\/]\.\.') {
        throw "Invalid app name - path traversal detected: $Name"
    }

    # Reject dangerous characters (file system and command injection)
    $dangerousChars = '[<>:"/\\|?*`$;]'
    if ($Name -match $dangerousChars) {
        throw "Invalid characters in app name: $Name (contains reserved characters)"
    }

    # Reject overly long names (causes file system issues)
    if ($Name.Length -gt $MaxLength) {
        throw "App name exceeds $MaxLength characters: $Name"
    }

    # Reject names that start or end with spaces/dots
    if ($Name -match '^\s|^\.|\.`$|\s`$') {
        throw "App name cannot start or end with spaces or dots: $Name"
    }

    return $true
}

function Assert-SafeVersion {
    <#
    .SYNOPSIS
        Validates a version string for safety.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Version
    )

    if ([string]::IsNullOrWhiteSpace($Version)) {
        throw "Version cannot be empty or whitespace"
    }

    # Allow standard version formats: 1.0, 1.0.0, 1.0.0.0, 1.0-beta, etc.
    if ($Version -notmatch '^[\d][\d\.\-\w]{0,50}$') {
        throw "Invalid version format: $Version"
    }

    return $true
}

#endregion

#region Path Helpers

function Get-FSPath {
    <#
    .SYNOPSIS
        Converts a UNC path to FileSystem provider path.

    .DESCRIPTION
        When running from SCCM drive (e.g., HLL:), PowerShell cmdlets need
        explicit FileSystem provider paths for UNC operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path -match '^\\\\') {
        return "Microsoft.PowerShell.Core\FileSystem::$Path"
    }
    return $Path
}

function Test-UNCPathAccessible {
    <#
    .SYNOPSIS
        Tests if a UNC path is accessible with proper provider handling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fsPath = Get-FSPath -Path $Path
    return (Test-Path -LiteralPath $fsPath -ErrorAction SilentlyContinue)
}

#endregion

#region Config Validation

function Test-ConfigSchema {
    <#
    .SYNOPSIS
        Validates a pipeline configuration object against the expected schema.

    .DESCRIPTION
        Checks for required fields, valid formats, and logical consistency.
        Returns validation errors as an array.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Config
    )

    $errors = @()

    # Required Settings section
    if (-not $Config.Settings) {
        $errors += "Missing 'Settings' section"
    }
    else {
        # Required Settings fields
        if (-not $Config.Settings.SiteCode) {
            $errors += "Missing Settings.SiteCode"
        }
        elseif ($Config.Settings.SiteCode -notmatch '^[A-Z0-9]{2,3}$') {
            $errors += "Invalid SiteCode format '$($Config.Settings.SiteCode)' (expected 2-3 alphanumeric chars)"
        }

        if (-not $Config.Settings.ContentRoot) {
            $errors += "Missing Settings.ContentRoot"
        }
        elseif ($Config.Settings.ContentRoot -notmatch '^\\\\') {
            $errors += "ContentRoot should be a UNC path (starts with \\)"
        }

        if (-not $Config.Settings.DPName) {
            $errors += "Missing Settings.DPName"
        }

        # Optional but validate if present
        if ($Config.Settings.DefaultPurpose -and $Config.Settings.DefaultPurpose -notin @("Available", "Required")) {
            $errors += "Invalid DefaultPurpose '$($Config.Settings.DefaultPurpose)' (expected 'Available' or 'Required')"
        }
    }

    # Required Applications section
    if (-not $Config.Applications) {
        $errors += "Missing 'Applications' section"
    }
    elseif ($Config.Applications.Count -eq 0) {
        $errors += "Applications array is empty"
    }
    else {
        $i = 0
        foreach ($app in $Config.Applications) {
            $i++
            if (-not $app.WingetId) {
                $errors += "Application #$i missing WingetId"
            }
            elseif ($app.WingetId -notmatch '^\w+\.\w+') {
                $errors += "Application #$i has invalid WingetId format '$($app.WingetId)'"
            }

            if ($app.Purpose -and $app.Purpose -notin @("Available", "Required")) {
                $errors += "Application #$i has invalid Purpose '$($app.Purpose)'"
            }
        }
    }

    if ($errors.Count -gt 0) {
        throw "Config validation failed:`n$($errors -join "`n")"
    }

    return $true
}

#endregion

#region Hash Verification

function Get-InstallerHash {
    <#
    .SYNOPSIS
        Calculates SHA256 hash of an installer file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fsPath = Get-FSPath -Path $Path
    if (-not (Test-Path -LiteralPath $fsPath)) {
        throw "File not found: $Path"
    }

    return (Get-FileHash -LiteralPath $fsPath -Algorithm SHA256).Hash
}

function Test-InstallerIntegrity {
    <#
    .SYNOPSIS
        Verifies an installer file against its expected hash.

    .DESCRIPTION
        Compares the current SHA256 hash of a file against an expected value.
        Returns $true if hashes match, throws on mismatch.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string]$ExpectedHash
    )

    $currentHash = Get-InstallerHash -Path $Path

    if ($currentHash -ne $ExpectedHash) {
        throw "Installer integrity check failed! Expected: $ExpectedHash, Got: $currentHash"
    }

    return $true
}

#endregion

# Export functions
Export-ModuleMember -Function @(
    'Write-Log',
    'Write-AuditLog',
    'Invoke-WithRetry',
    'Assert-SafeAppName',
    'Assert-SafeVersion',
    'Get-FSPath',
    'Test-UNCPathAccessible',
    'Test-ConfigSchema',
    'Get-InstallerHash',
    'Test-InstallerIntegrity'
)
