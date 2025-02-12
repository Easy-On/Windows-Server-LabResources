@{
    Activities = @(
        @{
            ID = 'InstallRSAT'
            DisplayName = 'Practice: Install Remote Server Administration Tools'
            Script = 'Install-RemoteServerAdministrationTools.ps1'
        }
        @{
            ID = 'CustomMMC'
            DisplayName = 'Practice: Create a custom Microsoft Management Console'
            Script = 'New-CustomMMC.ps1'
            DependsOn = 'InstallRSAT'
        }
        @{
            ID = 'AddServerManagerServers'
            DisplayName = 'Practice: Explore Server Manager'
            Script = 'Add-ServerManagerServers.ps1'
            DependsOn = 'InstallRSAT'
        }
        @{
            ID = 'InstallWAC'
            DisplayName = 'Practice: Install Windows Admin Center using a Script'
            Script = 'Install-AdminCenter.ps1'
        }
        @{
            ID = 'InstallWT'
            DisplayName = 'Practice: Install Windows Terminal'
            Script = 'Install-WindowsTerminal.ps1'
        }
        @{
            ID = 'InstallFS'
            DisplayName = 'Practice: Install roles using Server Manager'
            Script = 'Install-FileServer.ps1'
            DependsOn = 'AddServerManagerServers'
        }
        @{
            ID = 'InstallCAWebEnrollment'
            DisplayName = 'Practice: Install roles using Windows Admin Center'
            Script = 'Install-CAWebEnrollment.ps1'
            DependsOn = 'Add-WACServers.ps1'
        }
        @{
            ID = 'InstallBackup'
            DisplayName = 'Practice: Manage features using PowerShell'
            Script = 'Install-WindowsServerBackup.ps1'
            DependsOn = 'InstallRSAT'
        }
        @{
            ID = 'ManageServices'
            DisplayName = 'Practice: Manage services using Windows Admin Center'
            DependsOn = 'AddWACServers'
        }
        @{
            ID = 'ViewEvents'
            DisplayName = 'Practice: View events using Windows Admin Center'
        }
        @{
            ID = 'NewLocalUsers'
            DisplayName = 'Practice: Manage local users'
            Script = 'New-LocalAdmins.ps1'
            DependsOn = 'CustomMMC', 'AddWACServers'
        }
        @{
            ID = 'AddLocalAdmins'
            DisplayName = 'Practice: Manage local groups'
            Script = 'Add-LocalAdministratorsMember.ps1'
            DependsOn = 'NewLocalusers'
        }
        @{
            ID = 'EnableADRecycleBin'
            DisplayName = 'Practice: Enable the Active Directory Recycle Bin'
            Script = 'Enable-ADRecycleBin.ps1'
            DependsOn = 'InstallRSAT'
        }
        @{
            ID = 'AddWACServers'
            DisplayName = 'Lab: Explore Windows Admin Center/Practice: Configure Windows Admin Center'
            Script = 'Add-WACServers.ps1'
            DependsOn = 'InstallWAC', 'InstallRSAT'
        }
        @{
            ID = 'EnableRemoteMgmt'
            DisplayName = 'Lab: Manage servers remotely using Microsoft Management Console'
            Script = 'Enable-ComputerRemoteManagement.ps1'
            DependsOn = 'CustomMMC', 'AddWACServers'
        }
        @{
            ID = 'ADMgmt'
            DisplayName = 'Lab: Manage domain users, groups, and computers'
            Script = 'New-ADObjects.ps1'
            DependsOn = @(
                'CustomMMC'
                'AddWACServers'
                'AddLocalAdmins'
                'EnableADRecycleBin'
            )
        }
        @{
            ID = 'LocalStorage'
            DisplayName = 'Lab: Manage local storage'
            Script = 'New-Volumes.ps1'
            DependsOn = @(
                'EnableRemoteMgmt'
                'InstallFS'
            )
        }
        @{
            ID = 'FileSharing'
            DisplayName = 'Lab: Manage file sharing'
            Script = 'New-Shares.ps1'
            DependsOn = 'LocalStorage'
        }
        @{
            ID = 'HardenSMB'
            DisplayName = 'Practice: Harden SMB'
            Script = 'Set-SMB.ps1'
            DependsOn = 'FileSharing'
        }
        @{
            ID = 'InstallGPMC'
            DisplayName = 'Practice: Install Group Policy Management'
            Script = 'Install-GPMC.ps1'
            DependsOn = $null
        }
        @{
            ID = 'AuditFS'
            DisplayName = 'Lab: Audit file server events'
            Script = 'Enable-FSAuditing.ps1'
            DependsOn = 'FileSharing', 'InstallGPMC'
        }
        @{
            ID = 'ADRMS'
            DisplayName = 'Lab: Active Directory Rights Management Service'
            Script = 'Invoke-ADRMSConfig.ps1'
            DependsOn = 'AuditFS'
        }
        @{
            ID = 'InstallFSRM'
            DisplayName = 'Practice Install File Server Resource Manager'
            Script = 'Install-FSRM.ps1'
            DependsOn = 'InstallFS'
        }
        @{
            ID = 'FSRMEmailSettings'
            DisplayName = 'Practice: Configure e-mail notifications in FSRM'
            Script = 'Set-FSRMEmail.ps1'
            DependsOn = 'InstallFSRM'
        }
        @{
            ID = 'FSRMAccessDeniedAssistance'
            DisplayName = 'Practice: Configure Access-Denied-Assistance'
            Script = 'Enable-AccessDeniedAssistance.ps1'
            DependsOn = 'InstallFSRM'
        }
        @{
            ID = 'FSRMClassificationSchedule'
            DisplayName = 'Practice: Configure a classification schedule'
            Script = 'Set-ClassificationSchedule.ps1'
            DependsOn = 'InstallFSRM'
        }
        @{
            ID = 'FilterPack'
            DisplayName = 'Practice: Install the Microsoft Office Filter Pack'
            Script = 'Install-FilterPack.ps1'
            DependsOn = 'FileSharing'
        }
        @{
            ID = 'FSRMReportOptions'
            DisplayName = 'Practice: Configure storage report options'
            Script = 'Set-FSRMReports.ps1'
            DependsOn = 'FileSharing'
        }
        @{
            ID = 'FSRM'
            DisplayName = 'Lab: File server resource managenent'
            Script = 'Invoke-FSRMConfiguration.ps1'
            DependsOn = @(
                'FSRMEmailSettings'
                'FSRMAccessDeniedAssistance'
                'FSRMClassificationSchedule'
                'FilterPack'
                'FSRMReportOptions'
            )
        }
        @{
            ID = 'DynamicAccessControl'
            DisplayName = 'Lab: Dynamic access control'
            DependsOn = @(
                'InstallGPMC'
                'FSRM'
            )
        }
        @{
            ID = 'RSATDHCP'
            DisplayName = `
                'Practice: Install File Server Resource Manager and Tools'
            Script = 'Install-RSATDHCP.ps1'
        }
        @{
            ID = 'DHCPServerRole'
            DisplayName = 'Practice: Install the DHCP server role'
            Script = 'Install-DHCP.ps1'
            DependsOn = @(
                'InstallRSAT'
            )
        }
        @{
            ID = 'DHCPServerOptions'
            DisplayName = 'Practice: Configure DHCP server options'
            Script = 'Set-DHCPServerOptions.ps1'
            DependsOn = @(
                'RSATDHCP'
                'DHCPServerRole'
            )
        }
        @{
            ID = 'AddDHCPServerScope'
            DisplayName = 'Practice: Add a DHCP scope'
            Script = 'New-DHCPScope.ps1'
            DependsOn = @(
                'DHCPServerOptions'
            )
        }
        @{
            ID = 'AddDHCPReservations'
            DisplayName = 'Practice: Add DHCP reservations'
            Script = 'New-DHCPReservations.ps1'
            DependsOn = @(
                'AddDHCPServerScope'
            )
        }
        @{
            ID = 'AuthorizeDHCPServerAndActivateScope'
            DisplayName = 'Practice: Authorize DHCP server and activate scope'
            Script = 'Authorize-DHCP.ps1'
            DependsOn = @(
                'AddDHCPReservations'
            )
        }
        @{
            ID = 'InstallDomainControllers'
            Displayname = 'Lab: Deploying domain controllers, Exercises 1 - 5'
            Script = 'Install-DomainControllers.ps1'
            DependsOn = @('InstallRSAT')
        }
        @{
            ID = 'InstallForest'
            Displayname = 'Lab: Deploying domain controllers, Exercise 6'
            Script = 'Install-Forest.ps1'
            DependsOn = @('InstallRSAT')
        }
    )
}