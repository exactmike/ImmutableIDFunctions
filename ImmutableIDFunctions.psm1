function Get-GUIDFromByteArray
{
    [cmdletbinding()]
    param
    (
        [byte[]]$GuidByteArray
    )
    New-Object -TypeName guid -ArgumentList (, $GuidByteArray)
}
function Get-ImmutableIDFromGUID
{
    [cmdletbinding()]
    param
    (
        [guid]$Guid
    )
    [Convert]::ToBase64String($Guid.ToByteArray())
}
function Test-ADCredential
{
    param
    (
        [pscredential]$Credential
        ,
        [string]$Domain
    )
    $Username = switch ($Credential.UserName)
    {
        {$_.Contains('@')}
        {
            #Write-Verbose -Verbose -Message "found @"
            $Credential.UserName.split('@')[0]
        }
        {$_.Contains('\')}
        {
            #Write-Verbose -Verbose -Message "found \"
            $Credential.UserName.split('\')[1]
        }
        Default
        {
            #Write-Verbose -Verbose -Message "found neither @ nor \"
            $Credential.UserName
        }
    }
    #Get the AD User and Authenticate the AD User
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    $Authenticated = $false
    $ADUser = $null
    try
    {
        $StartingErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Stop'
        $pc = New-Object System.DirectoryServices.AccountManagement.PrincipalContext $ct, $Domain, $Username, $Credential.GetNetworkCredential().Password
        $ADUser = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($pc, $Username)
        $ErrorActionPreference = $StartingErrorActionPreference
    }
    catch
    {
        $ErrorActionPreference = $StartingErrorActionPreference
    }
    Finally
    {
        $ErrorActionPreference = $StartingErrorActionPreference
    }
    if ($null -ne $ADUser)
    {

        if ($true -eq $pc.ValidateCredentials($Username, $credential.GetNetworkCredential().Password))
        {
            $Authenticated = $true
        }
    }
    $Authenticated
}
function Import-ADModule
{
    $Global:ADPS_LoadDefaultDrive = $false
    Import-Module ActiveDirectory -ErrorAction Stop -Global
}
function Connect-ADDrive
{
    param(
        $Domain
        ,
        [pscredential]$Credential
    )
    $Drive = New-PSDrive -Name Domain -PSProvider ActiveDirectory -Server $Domain -Scope Global -Root '//RootDSE/' -ErrorAction Stop -Credential $Credential
}
function Get-IdentifiedADObject
{
    param(
        $Identity
    )
    Push-Location
    Set-Location Domain:\
    $GetADObjectParams = @{
        ErrorAction = 'Stop'
        Filter      = "SAMAccountName -eq '$Identity' -or DistinguishedName -eq '$Identity' -or ObjectGUID -eq '$Identity'"
        Properties  = 'UserPrincipalName', 'ms-ds-consistencyguid', 'SAMAccountName'
    }
    try
    {
        $ADObject = Get-ADObject @GetADObjectParams | Select-Object -Property @{n = 'ProvidedIdentity'; e = {$Identity}}, SAMAccountName, DistinguishedName, UserPrincipalName, @{n = 'ObjectGUIDString'; e = {$_.ObjectGUID.guid}}, ObjectClass, @{n = 'ms-ds-ConsistencyGuid'; e = {(Get-GuidFromByteArray -GuidByteArray $_.'ms-ds-consistencyguid').guid}}, @{n = 'Found'; e = {$true}}, @{n = 'ImmutableIDSourceSet'; e = {$null -ne $_.'ms-ds-consistencyguid'}}, @{n = 'ExpectedAzureADImmutableID'; e = {Get-ImmutableIDFromGUID $_.'ms-ds-consistencyguid'}}, ObjectGUID
    }
    catch
    {
        $_
    }
    if ($null -eq $ADObject)
    {
        [pscustomobject]@{
            ProvidedIdentity           = $Identity
            SAMAccountName             = $null
            DistinguishedName          = $null
            UserPrincipalName          = $null
            ObjectGUIDString           = ''
            ObjectClass                = $null
            'ms-ds-ConsistencyGuid'    = $null
            Found                      = $false
            ImmutableIDSourceSet       = $null
            ExpectedAzureADImmutableID = $null
            ObjectGUID                 = $null
        }
    }
    else
    {
        $ADObject
    }
    Pop-Location
}
function Set-ADObjectImmutableIDAttribute
{
    param
    (
        $ADObject
    )
    Push-Location
    Set-Location Domain:\
    try
    {
        if ($ADObject.ImmutableIDSourceSet)
        {
            Set-ADObject -Identity $ADObject.ObjectGUIDString -Clear 'ms-DS-ConsistencyGUID' -Confirm:$false -ErrorAction Stop
        }
        Set-ADObject -Identity $ADObject.ObjectGUIDString -Add @{'ms-DS-ConsistencyGUID' = $($ADObject.ObjectGUID)} -Server $Domain -ErrorAction Stop -confirm:$false
        Start-Sleep -Seconds 3
        $GetADObjectParams = @{
            ErrorAction = 'Stop'
            Identity    = $ADObject.ObjectGUIDString
            Properties  = 'UserPrincipalName', 'ms-ds-consistencyguid', 'SAMAccountName'
        }
        $UpdatedADObject = Get-ADObject @GetADObjectParams | Select-Object -Property @{n = 'ProvidedIdentity'; e = {$ADObject.ProvidedIdentity}}, SAMAccountName, DistinguishedName, UserPrincipalName, @{n = 'ObjectGUIDString'; e = {$_.ObjectGUID.guid}}, ObjectClass, @{n = 'ms-ds-ConsistencyGuid'; e = {(Get-GuidFromByteArray -GuidByteArray $_.'ms-ds-consistencyguid').guid}}, @{n = 'Found'; e = {$true}}, @{n = 'ImmutableIDSourceSet'; e = {$null -ne $_.'ms-ds-consistencyguid'}}, @{n = 'ExpectedAzureADImmutableID'; e = {Get-ImmutableIDFromGUID $_.'ms-ds-consistencyguid'}}, ObjectGUID
        $UpdatedADObject
    }
    catch
    {
        $_
    }
    Pop-Location
}
