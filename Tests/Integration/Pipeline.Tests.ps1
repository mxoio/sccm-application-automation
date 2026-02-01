<#
.SYNOPSIS
    Integration tests for the SCCM Application Automation Pipeline.

.DESCRIPTION
    Tests the pipeline end-to-end functionality.
    Note: Some tests require SCCM connectivity and will be skipped if not available.
#>

BeforeAll {
    $script:ScriptsPath = Join-Path $PSScriptRoot "..\..\"
    $script:helperModule = Join-Path $script:ScriptsPath "SCCMPipelineHelpers.psm1"

    if (Test-Path $script:helperModule) {
        Import-Module $script:helperModule -Force
    }

    # Create a test config for integration tests
    $script:testConfigPath = Join-Path $env:TEMP "pester-test-config-$(Get-Random).json"
}

Describe "Pipeline Prerequisites" {
    Context "Script files exist" {
        It "Stage-WingetToSCCM.ps1 exists" {
            $path = Join-Path $script:ScriptsPath "Stage-WingetToSCCM.ps1"
            Test-Path $path | Should -Be $true
        }

        It "New-CMAppFromTemplate.ps1 exists" {
            $path = Join-Path $script:ScriptsPath "New-CMAppFromTemplate.ps1"
            Test-Path $path | Should -Be $true
        }

        It "Deploy-Application.ps1 exists" {
            $path = Join-Path $script:ScriptsPath "Deploy-Application.ps1"
            Test-Path $path | Should -Be $true
        }

        It "Invoke-AppPipeline.ps1 exists" {
            $path = Join-Path $script:ScriptsPath "Invoke-AppPipeline.ps1"
            Test-Path $path | Should -Be $true
        }

        It "Test-PipelinePrerequisites.ps1 exists" {
            $path = Join-Path $script:ScriptsPath "Test-PipelinePrerequisites.ps1"
            Test-Path $path | Should -Be $true
        }

        It "SCCMPipelineHelpers.psm1 exists" {
            Test-Path $script:helperModule | Should -Be $true
        }
    }

    Context "Script syntax validation" {
        It "Stage-WingetToSCCM.ps1 has valid syntax" {
            $path = Join-Path $script:ScriptsPath "Stage-WingetToSCCM.ps1"
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "New-CMAppFromTemplate.ps1 has valid syntax" {
            $path = Join-Path $script:ScriptsPath "New-CMAppFromTemplate.ps1"
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Deploy-Application.ps1 has valid syntax" {
            $path = Join-Path $script:ScriptsPath "Deploy-Application.ps1"
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "Invoke-AppPipeline.ps1 has valid syntax" {
            $path = Join-Path $script:ScriptsPath "Invoke-AppPipeline.ps1"
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }

        It "SCCMPipelineHelpers.psm1 has valid syntax" {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:helperModule, [ref]$null, [ref]$errors)
            $errors.Count | Should -Be 0
        }
    }
}

Describe "Config File Handling" {
    BeforeAll {
        # Create a valid test config
        $validConfig = @{
            Settings = @{
                SiteCode = "PS1"
                ContentRoot = "\\server\share\Applications"
                DPName = "dp.contoso.com"
                DefaultPurpose = "Available"
            }
            Applications = @(
                @{
                    WingetId = "VideoLAN.VLC"
                    AppName = "VLC"
                    Collection = "SCCM Software VLC"
                }
            )
        }
        $validConfig | ConvertTo-Json -Depth 5 | Set-Content $script:testConfigPath
    }

    It "Test-ConfigSchema validates the test config" {
        $config = Get-Content $script:testConfigPath -Raw | ConvertFrom-Json
        { Test-ConfigSchema -Config $config } | Should -Not -Throw
    }

    It "Invoke-AppPipeline can parse the config" -Skip:(-not (Test-Path $script:testConfigPath)) {
        $pipelineScript = Join-Path $script:ScriptsPath "Invoke-AppPipeline.ps1"
        # Just test that the script can be invoked with -WhatIf without errors
        # This validates config loading without actually running the pipeline
        $result = & $pipelineScript -ConfigPath $script:testConfigPath -WhatIf -ErrorAction SilentlyContinue 2>&1
        # The script should not throw a config parsing error
        $result | Should -Not -Match "Config file not found"
    }

    AfterAll {
        Remove-Item $script:testConfigPath -Force -ErrorAction SilentlyContinue
    }
}

Describe "Winget Availability" -Tag "RequiresWinget" {
    It "winget is installed" {
        $winget = Get-Command winget -ErrorAction SilentlyContinue
        $winget | Should -Not -BeNullOrEmpty
    }

    It "winget can return version" {
        $version = & winget --version 2>$null
        $version | Should -Match "v\d+\.\d+"
    }

    It "winget download command is available" {
        $help = & winget download --help 2>$null | Out-String
        $help | Should -Match "download"
    }
}

Describe "SCCM Connectivity" -Tag "RequiresSCCM" {
    BeforeAll {
        $script:sccmAvailable = $false
        if ($env:SMS_ADMIN_UI_PATH) {
            $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
            if (Test-Path $modulePath) {
                $script:sccmAvailable = $true
            }
        }
    }

    It "SCCM Console is installed" -Skip:(-not $script:sccmAvailable) {
        $env:SMS_ADMIN_UI_PATH | Should -Not -BeNullOrEmpty
    }

    It "ConfigurationManager module can be found" -Skip:(-not $script:sccmAvailable) {
        $modulePath = Join-Path $env:SMS_ADMIN_UI_PATH "..\ConfigurationManager.psd1"
        Test-Path $modulePath | Should -Be $true
    }
}

Describe "Helper Module Functions" {
    It "Write-Log function is exported" {
        Get-Command Write-Log -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "Write-AuditLog function is exported" {
        Get-Command Write-AuditLog -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "Invoke-WithRetry function is exported" {
        Get-Command Invoke-WithRetry -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "Assert-SafeAppName function is exported" {
        Get-Command Assert-SafeAppName -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "Assert-SafeVersion function is exported" {
        Get-Command Assert-SafeVersion -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "Test-ConfigSchema function is exported" {
        Get-Command Test-ConfigSchema -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    It "Test-InstallerIntegrity function is exported" {
        Get-Command Test-InstallerIntegrity -Module SCCMPipelineHelpers -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
}

Describe "Retry Logic" {
    It "Invoke-WithRetry succeeds on first attempt" {
        $counter = 0
        $result = Invoke-WithRetry -ScriptBlock { $script:counter++; "success" } -MaxRetries 3
        $result | Should -Be "success"
    }

    It "Invoke-WithRetry retries on failure" {
        $script:attempts = 0
        $result = Invoke-WithRetry -ScriptBlock {
            $script:attempts++
            if ($script:attempts -lt 2) { throw "fail" }
            "success"
        } -MaxRetries 3 -DelaySeconds 0

        $result | Should -Be "success"
        $script:attempts | Should -Be 2
    }

    It "Invoke-WithRetry throws after max retries" {
        { Invoke-WithRetry -ScriptBlock { throw "always fails" } -MaxRetries 2 -DelaySeconds 0 } | Should -Throw
    }
}

AfterAll {
    Remove-Module SCCMPipelineHelpers -ErrorAction SilentlyContinue
}
