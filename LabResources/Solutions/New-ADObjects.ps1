[CmdletBinding()]
param (
    [Parameter()]
    [switch]
    $SkipDependencies
)

#region Prerequisites

if (-not $SkipDependencies) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Invoke-Dependencies.ps1') `
        -Script $MyInvocation.MyCommand `
        -Confirm:$false
}

#endregion Prerequisites

Write-Host 'Lab: Manage domain users, groups, and computers'

#region Common variables

$domainFQDN = 'ad.adatum.com'
$domainDN = `
    (
        $domainFQDN -split '\.' | ForEach-Object { "DC=$PSItem" }
    ) -join ','

#endregion Common variables

#region Exercise 1: Manage domain users

Write-Host '    Exercise 1: Manage domain users'

#region Task 1: Create domain users

Write-Host '        Task 1: Create domain users'

$firstName = Read-Host "Your first name"
$lastName = Read-Host "Your last name"
$users = @(
    @{ FirstName = $firstName; LastName = $lastName; OU = 'IT' }
    @{ FirstName = 'Aimie'; LastName = 'Draper'; OU = 'IT' }
    @{ FirstName = 'Otto'; LastName = 'Jensen'; OU = 'Development' }
    @{ FirstName = 'Taylan'; LastName = 'Long'; OU = 'Development' }
    @{ FirstName = 'Eduardo'; LastName = 'Conner'; OU = 'Managers' }
    @{ FirstName = 'Azra'; LastName = 'Hendrix'; OU = 'Managers' }
    @{ FirstName = 'Francisco'; LastName = 'Nixon'; OU = 'Marketing' }
    @{ FirstName = 'Bianka'; LastName = 'Fulton'; OU = 'Marketing' }
    @{ FirstName = 'Alton'; LastName = 'Sampson'; OU = 'Research' }
    @{ FirstName = 'Giulia'; LastName = 'Allan'; OU = 'Research' }
    @{ FirstName = 'Keegan'; LastName = 'O''Gallagher'; OU = 'Sales' }
    @{ FirstName = 'Millicent'; LastName = 'Brock'; OU = 'Sales' }
)
$password = ConvertTo-SecureString -String 'Pa$($MyInvocation.MyCommand)w0rd' -AsPlainText -Force

$users | ForEach-Object {
    $ouName = $PSItem.OU

    $path = "OU=$ouName, $domainDN"
    $name = "$($PSItem.FirstName) $($PSItem.LastName)"
    $userPrincipalName = "$($PSItem.Firstname)@$domainFQDN"

    $aDUser = New-ADUser `
        -Path $path `
        -Name $name `
        -DisplayName  $name `
        -GivenName $PSItem.FirstName `
        -Surname $PSItem.LastName `
        -UserPrincipalName $userPrincipalName `
        -SamAccountName $PSItem.FirstName `
        -PassThru
    
    $aDUser | Set-ADAccountPassword -Reset -NewPassword $password
    $aDUser | Set-ADUser -ChangePasswordAtLogon $true
    $aDUser | Enable-ADAccount
}

$ouName = 'IT'
$path = "OU=$ouName, $domainDN"
$name = "$firstName $lastName (Admin)"
$userPrincipalName = "$($firstname)Admin@$domainFQDN"
$samAccountName = "($firstname)Admin"

$aDUser = New-ADUser `
    -Path $path `
    -Name $name `
    -DisplayName  $name `
    -GivenName $PSItem.FirstName `
    -Surname $PSItem.LastName `
    -UserPrincipalName $userPrincipalName `
    -SamAccountName $samAccountName `
    -PassThru

$aDUser | Set-ADAccountPassword -Reset -NewPassword $password
$aDUser | Set-ADUser -ChangePasswordAtLogon $true
$aDUser | Enable-ADAccount


#endregion Task 1: Create domain users

#region Task 2: Rename domain users

Write-Host '        Task 2: Rename domain users'

$usersRename = @(
    @{ 
        FirstName = 'Colette'
        OldLastname = 'Lichtenberg'
        NewLastName = 'Kendall'
    }
    @{ 
        FirstName = 'Logan'
        OldLastname = 'Boyle'
        NewLastName = 'Stanley'
    }
    @{ 
        FirstName = 'Evangelina'
        OldLastname = 'Reeves'
        NewLastName = 'Snow'
    }
)

$usersRename | ForEach-Object {
    $oldName = "$($PSItem.FirstName) $($PSItem.OldLastName)"
    $newName = "$($PSItem.FirstName) $($PSItem.NewLastName)"

    Get-ADUser -Filter "Name -eq '$oldName'" | 
    Rename-ADObject -NewName $newName -PassThru | 
    Set-ADUser -DisplayName $newName -Surname $newLastName
}

#endregion Task 2: Rename domain users

#endregion Exercise 1: Manage domain users

#region Exercise 2: Manage domain groups

Write-Host '    Exercise 2: Manage domain groups'

#region Task 1: Add members to a domain group

Write-Host '        Task 1: Add members to a domain group'

$groups = @(
    @{ Name = 'IT'; Members = @("$firstName $lastName", 'Aimie Draper') }
    @{ Name = 'Development'; Members = @('Otto Jensen', 'Taylan Long') }
    @{ Name = 'Managers'; Members = @('Eduardo Conner', 'Azra Hendrix') }
    @{ Name = 'Marketing'; Members = @('Francisco Nixon', 'Bianka Fulton') }
    @{ Name = 'Research'; Members = @('Alton Sampson', 'Giulia Allan')}
    @{ Name = 'Sales'; Members = @('Keegan O''Gallagher', 'Millicent Brock')}
)

$groups | ForEach-Object {
    $groupName = $PSItem.Name
    $PSItem.Members | ForEach-Object {
        $members = Get-ADUser -Filter "Name -eq ""$PSItem"""
        Add-ADGroupMember -Identity $groupName -Members $members
    }
}

#endregion Task 1: Add members to a domain group

#region Task 2: Create an organizational unit

Write-Host '        Task 2: Create an organizational unit'

$adOrganizationalUnit = New-ADOrganizationalUnit `
    -Path 'dc=ad, dc=adatum, dc=com' `
    -Name 'Organizational Groups' `
    -PassThru

#endregion Task 2: Create an organizational unit


#region Task 3: Create domain groups

Write-Host '        Task 3: Create groups'

$newGroups = @(
    @{ 
        Name = 'Project Managers'
        Members = @(
            'Alyson Winters' 
            'Damian Hadden'
            'Isobel Wilkins'
            'Peter Laamers'
        )
    }
    @{ 
        Name = 'Data Protection Managers'
        Members = @(
            'Adam Hobbs' 
            'Mary Skinner'
        )
    }
    @{ 
        Name = 'Apprentices'
        Members = @(
            'Lara Raisic' 
            'Huong Tang'
            'Huu Hoang'
            'Brigita Krastina'
        )
    }
    @{ 
        Name = 'Pilot users'
        Members = @(
            'Doris David' 
            'Nestor Fiore'
            'Laura Atkins'
            'Ella Perry'
            'Max Pennekamp'
            'Erin Bull'
        )
    }
    
)

$newGroups | ForEach-Object {
    $aDGroup = New-ADGroup `
        -Name $PSItem.Name `
        -Path $adOrganizationalUnit.DistinguishedName `
        -GroupScope Global `
        -PassThru

    $PSItem.Members | ForEach-Object {
        $members = Get-ADUser -Filter "Name -eq ""$PSItem"""
        $aDGroup | Add-ADGroupMember -Members $members
    }
}

#endregion Task 3: Create domain groups

#endregion Exercise 2: Manage domain groups
