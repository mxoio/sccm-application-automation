<#
.SYNOPSIS
    Pester tests for SCCMPipelineHelpers.psm1

.DESCRIPTION
    Unit tests for shared helper functions used across the SCCM Application Automation Pipeline.
#>

BeforeAll {
    # Import the module under test
    $modulePath = Join-Path $PSScriptRoot "..\..\SCCMPipelineHelpers.psm1"
    Import-Module $modulePath -Force
}

Describe "Assert-SafeAppName" {
    Context "Valid app names" {
        It "Accepts standard app name" {
            { Assert-SafeAppName -Name "VLC Media Player" } | Should -Not -Throw
        }

        It "Accepts app name with numbers" {
            { Assert-SafeAppName -Name "7-Zip" } | Should -Not -Throw
        }

        It "Accepts app name with hyphens" {
            { Assert-SafeAppName -Name "Visual-Studio-Code" } | Should -Not -Throw
        }

        It "Returns true for valid names" {
            $result = Assert-SafeAppName -Name "ValidApp"
            $result | Should -Be $true
        }
    }

    Context "Invalid app names" {
        It "Rejects path traversal with .." {
            { Assert-SafeAppName -Name "..\malicious" } | Should -Throw "*path traversal*"
        }

        It "Rejects path traversal with backslash" {
            { Assert-SafeAppName -Name "app\..\etc" } | Should -Throw "*path traversal*"
        }

        It "Rejects special characters <" {
            { Assert-SafeAppName -Name "App<script>" } | Should -Throw "*Invalid characters*"
        }

        It "Rejects special characters >" {
            { Assert-SafeAppName -Name "App>test" } | Should -Throw "*Invalid characters*"
        }

        It "Rejects pipe character" {
            { Assert-SafeAppName -Name "App|test" } | Should -Throw "*Invalid characters*"
        }

        It "Rejects colon" {
            { Assert-SafeAppName -Name "C:test" } | Should -Throw "*Invalid characters*"
        }

        It "Rejects question mark" {
            { Assert-SafeAppName -Name "App?" } | Should -Throw "*Invalid characters*"
        }

        It "Rejects asterisk" {
            { Assert-SafeAppName -Name "App*" } | Should -Throw "*Invalid characters*"
        }

        It "Rejects empty string" {
            { Assert-SafeAppName -Name "" } | Should -Throw "*empty*"
        }

        It "Rejects whitespace only" {
            { Assert-SafeAppName -Name "   " } | Should -Throw "*empty*"
        }

        It "Rejects names starting with dot" {
            { Assert-SafeAppName -Name ".hidden" } | Should -Throw "*cannot start*"
        }

        It "Rejects names exceeding max length" {
            $longName = "A" * 101
            { Assert-SafeAppName -Name $longName } | Should -Throw "*exceeds*"
        }
    }
}

Describe "Assert-SafeVersion" {
    Context "Valid versions" {
        It "Accepts standard version 1.0" {
            { Assert-SafeVersion -Version "1.0" } | Should -Not -Throw
        }

        It "Accepts three-part version 1.0.0" {
            { Assert-SafeVersion -Version "1.0.0" } | Should -Not -Throw
        }

        It "Accepts four-part version 1.0.0.0" {
            { Assert-SafeVersion -Version "1.0.0.0" } | Should -Not -Throw
        }

        It "Accepts version with prerelease suffix" {
            { Assert-SafeVersion -Version "1.0-beta" } | Should -Not -Throw
        }

        It "Accepts version with numbers in suffix" {
            { Assert-SafeVersion -Version "1.2.8-test3" } | Should -Not -Throw
        }

        It "Returns true for valid versions" {
            $result = Assert-SafeVersion -Version "1.0"
            $result | Should -Be $true
        }
    }

    Context "Invalid versions" {
        It "Rejects empty string" {
            { Assert-SafeVersion -Version "" } | Should -Throw "*empty*"
        }

        It "Rejects whitespace only" {
            { Assert-SafeVersion -Version "   " } | Should -Throw "*empty*"
        }

        It "Rejects version not starting with digit" {
            { Assert-SafeVersion -Version "v1.0" } | Should -Throw "*Invalid version*"
        }
    }
}

Describe "Get-FSPath" {
    Context "UNC paths" {
        It "Prepends FileSystem provider for UNC paths" {
            $result = Get-FSPath -Path "\\server\share\folder"
            $result | Should -Be "Microsoft.PowerShell.Core\FileSystem::\\server\share\folder"
        }

        It "Handles UNC paths with deep nesting" {
            $result = Get-FSPath -Path "\\server\share\a\b\c\d"
            $result | Should -Match "^Microsoft\.PowerShell\.Core\\FileSystem::"
        }
    }

    Context "Local paths" {
        It "Returns local paths unchanged" {
            $result = Get-FSPath -Path "C:\Temp\file.txt"
            $result | Should -Be "C:\Temp\file.txt"
        }

        It "Returns relative paths unchanged" {
            $result = Get-FSPath -Path ".\folder\file.txt"
            $result | Should -Be ".\folder\file.txt"
        }
    }
}

Describe "Test-ConfigSchema" {
    Context "Valid configurations" {
        It "Accepts minimal valid config" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "PS1"
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                }
                Applications = @(
                    [PSCustomObject]@{ WingetId = "VideoLAN.VLC" }
                )
            }
            { Test-ConfigSchema -Config $config } | Should -Not -Throw
        }

        It "Accepts config with all optional fields" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "ABC"
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                    DefaultPurpose = "Available"
                }
                Applications = @(
                    [PSCustomObject]@{
                        WingetId = "VideoLAN.VLC"
                        AppName = "VLC"
                        Purpose = "Required"
                    }
                )
            }
            { Test-ConfigSchema -Config $config } | Should -Not -Throw
        }
    }

    Context "Invalid configurations" {
        It "Rejects config missing Settings" {
            $config = [PSCustomObject]@{
                Applications = @([PSCustomObject]@{ WingetId = "VideoLAN.VLC" })
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*Missing 'Settings'*"
        }

        It "Rejects config missing SiteCode" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                }
                Applications = @([PSCustomObject]@{ WingetId = "VideoLAN.VLC" })
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*Missing Settings.SiteCode*"
        }

        It "Rejects invalid SiteCode format" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "TOOLONG"
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                }
                Applications = @([PSCustomObject]@{ WingetId = "VideoLAN.VLC" })
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*Invalid SiteCode*"
        }

        It "Rejects non-UNC ContentRoot" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "PS1"
                    ContentRoot = "C:\local\path"
                    DPName = "dp.contoso.com"
                }
                Applications = @([PSCustomObject]@{ WingetId = "VideoLAN.VLC" })
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*UNC path*"
        }

        It "Rejects empty Applications array" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "PS1"
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                }
                Applications = @()
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*empty*"
        }

        It "Rejects application missing WingetId" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "PS1"
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                }
                Applications = @([PSCustomObject]@{ AppName = "VLC" })
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*missing WingetId*"
        }

        It "Rejects invalid DefaultPurpose" {
            $config = [PSCustomObject]@{
                Settings = [PSCustomObject]@{
                    SiteCode = "PS1"
                    ContentRoot = "\\server\share"
                    DPName = "dp.contoso.com"
                    DefaultPurpose = "Invalid"
                }
                Applications = @([PSCustomObject]@{ WingetId = "VideoLAN.VLC" })
            }
            { Test-ConfigSchema -Config $config } | Should -Throw "*Invalid DefaultPurpose*"
        }
    }
}

Describe "Test-InstallerIntegrity" {
    BeforeAll {
        # Create a test file
        $script:testFile = Join-Path $env:TEMP "pester-test-file-$(Get-Random).txt"
        "test content" | Set-Content $script:testFile
        $script:testHash = (Get-FileHash $script:testFile -Algorithm SHA256).Hash
    }

    AfterAll {
        Remove-Item $script:testFile -Force -ErrorAction SilentlyContinue
    }

    It "Returns true when hash matches" {
        $result = Test-InstallerIntegrity -Path $script:testFile -ExpectedHash $script:testHash
        $result | Should -Be $true
    }

    It "Throws when hash does not match" {
        $wrongHash = "0000000000000000000000000000000000000000000000000000000000000000"
        { Test-InstallerIntegrity -Path $script:testFile -ExpectedHash $wrongHash } | Should -Throw "*integrity check failed*"
    }

    It "Throws when file not found" {
        { Test-InstallerIntegrity -Path "C:\nonexistent\file.exe" -ExpectedHash "abc123" } | Should -Throw "*not found*"
    }
}

AfterAll {
    Remove-Module SCCMPipelineHelpers -ErrorAction SilentlyContinue
}
