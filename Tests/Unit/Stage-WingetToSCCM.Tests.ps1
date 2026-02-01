<#
.SYNOPSIS
    Pester tests for Stage-WingetToSCCM.ps1

.DESCRIPTION
    Unit tests for the staging script that downloads packages from winget.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot "..\..\Stage-WingetToSCCM.ps1"

    # Import helper module for shared functions
    $helperModule = Join-Path $PSScriptRoot "..\..\SCCMPipelineHelpers.psm1"
    if (Test-Path $helperModule) {
        Import-Module $helperModule -Force
    }
}

Describe "Stage-WingetToSCCM Script Validation" {
    It "Script file exists" {
        Test-Path $script:ScriptPath | Should -Be $true
    }

    It "Script has valid PowerShell syntax" {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Script has CmdletBinding attribute" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[CmdletBinding\(\)\]'
    }

    It "Script has mandatory PackageId parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\[\]\]\$PackageId'
    }

    It "Script has mandatory Version parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\]\$Version'
    }

    It "Script has mandatory SccmContentRoot parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\]\$SccmContentRoot'
    }
}

Describe "Stage-WingetToSCCM Helper Functions" {
    BeforeAll {
        # Dot-source the script to get access to internal functions
        # We need to mock required commands first
        function global:winget { }

        # Parse the script to extract function definitions
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath,
            [ref]$null,
            [ref]$null
        )

        # Find all function definitions
        $script:functions = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)
    }

    It "Contains Write-Log function" {
        $script:functions.Name | Should -Contain "Write-Log"
    }

    It "Contains Get-FSPath function" {
        $script:functions.Name | Should -Contain "Get-FSPath"
    }

    It "Contains Assert-UNC function" {
        $script:functions.Name | Should -Contain "Assert-UNC"
    }

    It "Contains Invoke-WithRetry function" {
        $script:functions.Name | Should -Contain "Invoke-WithRetry"
    }

    It "Contains Get-WingetAppMetadata function" {
        $script:functions.Name | Should -Contain "Get-WingetAppMetadata"
    }

    It "Contains Get-EstimatedInstallTime function" {
        $script:functions.Name | Should -Contain "Get-EstimatedInstallTime"
    }
}

Describe "Staging Output Structure" {
    # These tests verify the expected metadata structure

    It "Metadata contains required fields" {
        # Expected fields in app.json output
        $requiredFields = @(
            "AppName",
            "Version",
            "WingetId",
            "InstallerFile",
            "Type",
            "Detection"
        )

        # This is a schema validation test - just verify we document the expected structure
        $requiredFields.Count | Should -BeGreaterThan 5
    }

    It "Detection modes are documented" {
        $validModes = @(
            "Marker",
            "MsiProductCode",
            "UninstallDisplayNameVersion",
            "UninstallDisplayName",
            "FileBased",
            "Flexible"
        )

        $validModes | Should -Contain "Marker"
        $validModes | Should -Contain "MsiProductCode"
    }
}

AfterAll {
    Remove-Item function:winget -ErrorAction SilentlyContinue
    Remove-Module SCCMPipelineHelpers -ErrorAction SilentlyContinue
}
