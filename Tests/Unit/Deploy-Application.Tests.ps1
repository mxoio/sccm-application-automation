<#
.SYNOPSIS
    Pester tests for Deploy-Application.ps1

.DESCRIPTION
    Unit tests for the deployment script.
#>

BeforeAll {
    $script:ScriptPath = Join-Path $PSScriptRoot "..\..\Deploy-Application.ps1"

    # Import helper module
    $helperModule = Join-Path $PSScriptRoot "..\..\SCCMPipelineHelpers.psm1"
    if (Test-Path $helperModule) {
        Import-Module $helperModule -Force
    }
}

Describe "Deploy-Application Script Validation" {
    It "Script file exists" {
        Test-Path $script:ScriptPath | Should -Be $true
    }

    It "Script has valid PowerShell syntax" {
        $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script:ScriptPath, [ref]$null, [ref]$errors)
        $errors.Count | Should -Be 0
    }

    It "Script has CmdletBinding with SupportsShouldProcess" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[CmdletBinding\(SupportsShouldProcess\)\]'
    }

    It "Script has mandatory SiteCode parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\]\$SiteCode'
    }

    It "Script has mandatory AppName parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\]\$AppName'
    }

    It "Script has mandatory CollectionName parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\]\$CollectionName'
    }

    It "Script has mandatory DPName parameter" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[Parameter\(Mandatory\)\].*\[string\]\$DPName'
    }

    It "Script validates Purpose parameter values" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\[ValidateSet\("Available","Required"\)\]'
    }
}

Describe "Deploy-Application Security Features" {
    BeforeAll {
        $script:content = Get-Content $script:ScriptPath -Raw
    }

    It "Imports helper module for sanitization" {
        $script:content | Should -Match 'Import-Module.*SCCMPipelineHelpers'
    }

    It "Uses Assert-SafeAppName for input validation" {
        $script:content | Should -Match 'Assert-SafeAppName'
    }

    It "Has retry logic for content distribution" {
        $script:content | Should -Match 'Invoke-WithRetry'
    }

    It "Supports audit logging" {
        $script:content | Should -Match 'Write-AuditLog'
    }
}

Describe "Deploy-Application Helper Functions" {
    BeforeAll {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $script:ScriptPath,
            [ref]$null,
            [ref]$null
        )

        $script:functions = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true)
    }

    It "Contains Write-Log function" {
        $script:functions.Name | Should -Contain "Write-Log"
    }

    It "Contains Invoke-WithRetry function" {
        $script:functions.Name | Should -Contain "Invoke-WithRetry"
    }
}

Describe "Deployment Purpose Values" {
    It "Available is a valid purpose" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '"Available"'
    }

    It "Required is a valid purpose" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '"Required"'
    }

    It "Default purpose is Available" {
        $content = Get-Content $script:ScriptPath -Raw
        $content | Should -Match '\$Purpose\s*=\s*"Available"'
    }
}

AfterAll {
    Remove-Module SCCMPipelineHelpers -ErrorAction SilentlyContinue
}
