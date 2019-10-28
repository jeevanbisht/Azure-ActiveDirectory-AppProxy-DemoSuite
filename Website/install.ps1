
<# 
 
.SYNOPSIS
	Kickstart.ps1 is a Windows PowerShell script to install/configure IIS and Website Samples
.DESCRIPTION
	Version: 1.0.0
	Kickstart.ps1 is a Windows PowerShell script to install/configure IIS and Website Samples.
    It relies on bootstrap.ps1 to supply the requred 2 mandatory parmeters.
.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.
	Copyright (c) Microsoft Corporation. All rights reserved.
#> 

param
(    
    
    [Parameter(Mandatory=$true)]
    [string] $BootStrapFolder,

    
    [Parameter(Mandatory=$true)]
    [string] $AppProxyConnector
)

Write-Host $BootStrapFolder
Write-host $AppProxyConnector



Function Create-WebAppAndPool{
    param(
        [Parameter(Mandatory=$true)][string]$SiteName,
        [Parameter(Mandatory=$true)][string]$AppName,
        [Parameter(Mandatory=$true)][string]$AppFolder
         )

    [string]$HostName = "localhost"
    [string]$iisAppPoolDotNetVersion = "v4.0"
    [string]$iisAppPoolName = $AppName+"-AppPool"

    [string]$IISSiteConfigPath = "IIS:\Sites\$SiteName"
    [string]$IISAppConfigPath = "IIS:\Sites\$SiteName\$AppName"
    


    #navigate to the app pools root
    cd IIS:\AppPools\
    $appPool = New-Item $iisAppPoolName
    $appPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $iisAppPoolDotNetVersion

            
    #navigate to the sites root
    cd IIS:\Sites\

    #--------------------------------------------------
    #Create web Application and assign Application Pool
    #--------------------------------------------------
    
    #New-WebApplication -Name testApp -Site 'Default Web Site' -PhysicalPath c:\test -ApplicationPool DefaultAppPool
    New-WebApplication -Name $AppName -Site $SiteName -PhysicalPath $AppFolder -ApplicationPool $iisAppPoolName 
    
           
}
Function Set-KerberosAuthForAppPool{
    param(
        [Parameter(Mandatory=$true)][string]$WebSiteName,
        [Parameter(Mandatory=$true)][string]$AppName
         )

    [string]$IISAppConfigPath = "IIS:\Sites\$WebSiteName\$AppName"
    
    #Setup Authentication to WindowsAuth
    
    Set-WebConfigurationProperty -filter /system.webServer/security/authentication/windowsAuthentication -name enabled -value true -PSPath IIS:\ -location $WebSiteName/$AppName
    Set-WebConfigurationProperty -filter /system.webServer/security/authentication/anonymousAuthentication -name enabled -value False  -PSPath IIS:\ -location $WebSiteName/$AppName
    
    
    
    cd $env:windir\system32\inetsrv
    #.\appcmd.exe set config $SiteName -section:system.webServer/security/authentication/windowsAuthentication /useKernelMode:"False"  /commit:apphost 
    .\appcmd.exe set config $SiteName -section:system.webServer/security/authentication/windowsAuthentication /useAppPoolCredentials:"True"  /commit:apphost
}
Function Set-AppPoolCredentials{
  param(
        [Parameter(Mandatory=$true)][string]$AppName,
        [Parameter(Mandatory=$true)][string]$UserName,
        [Parameter(Mandatory=$true)][string]$Password,
        [Parameter(Mandatory=$true)][string]$Domain
        )

    
    [string]$iisAppPoolName = $AppName+"-AppPool"
    [string]$iisAppDomainUser = $Domain+"\"+$UserName
    $applicationPools = Get-ChildItem IIS:\AppPools | where { $_.Name -eq $iisAppPoolName }
    foreach($applicationPool in $applicationPools)
        {
        $applicationPool.processModel.userName = $iisAppDomainUser
        $applicationPool.processModel.password = $Password
        $applicationPool.processModel.identityType = 3
        $applicationPool | Set-Item
        }

}
Function Add-SPN { 
    param(
    [Parameter(Mandatory=$true)][string]$UserName
    )

    [string]$ShortSPN="http/"+ $env:COMPUTERNAME
    [string]$LongSPN="http/" + $env:COMPUTERNAME+"."+$env:USERDNSDOMAIN
    $Result = Get-ADObject -LDAPFilter "(SamAccountname=$UserName)" 
    Set-ADObject -Identity $Result.DistinguishedName -add @{serviceprincipalname=$ShortSPN} 
    Set-ADObject -Identity $Result.DistinguishedName -add @{serviceprincipalname=$LongSPN} 

 
 }
Function Add-KCD { 
    param(
    [Parameter(Mandatory=$true)][string]$AppPoolUserName,
    [Parameter(Mandatory=$true)][string]$AppProxyConnetor
    )

       

    $dc=Get-ADDomainController -Discover -DomainName $env:USERDNSDOMAIN
    $AppProxyConnetorObj= Get-ADComputer -Identity $AppProxyConnetor -Server $dc.HostName[0]
    $AppPoolUserNameObj = Get-ADObject -LDAPFilter "(SamAccountname=$AppPoolUserName)" 
    
    Set-ADUser -Identity $AppPoolUserNameObj -PrincipalsAllowedToDelegateToAccount $AppProxyConnetorObj
    #Set-ADComputer -Identity jbadp1  -PrincipalsAllowedToDelegateToAccount  $AppPoolUserNameObj
    Get-ADUser -identity $AppPoolUserNameObj -Properties PrincipalsAllowedToDelegateToAccount
        
 }


##Some variables
[string] $WebSiteName = "Default Web Site"
[string] $AppPoolDomain = $env:USERDOMAIN

[string] $appName = "WIASample"
[string] $appPath = $BootStrapFolder + "WIA"

[string] $appName2 = "FormsSample"
[string] $appPath2 = $BootStrapFolder + "Forms"

[string] $Randomizer = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})

[string] $AppPoolUserName = $Randomizer +"-AppPool"

[Reflection.Assembly]::LoadWithPartialName("System.Web")
[string] $passrandom=[system.web.security.membership]::GeneratePassword(8,3)
[string] $AppPoolPassword = "MSFT" + $passrandom



#Install AD Tools
Write-Progress -PercentComplete 5 -id 1 -Activity "App Proxy Demo Installer " -Status "Installing Prerequistes" 
Write-Progress -PercentComplete 1 -id 2 -Activity "Installing Prerequisites" -Status "Remote Administration Tools" 

$addsTools = "RSAT-AD-Tools" 
Add-WindowsFeature $addsTools 

Write-Progress -PercentComplete 50 -id 2 -Activity "Installing Completed" -Status "Remote Administration Tools" 
Write-Progress -PercentComplete 20 -id 1 -Activity "App Proxy Demo Installer " -Status "Installing Prerequistes" 


#Install IIS
Write-Progress -PercentComplete 55 -id 2 -Activity "Installing Prerequisites" -Status "IIS" 
import-module servermanager
add-windowsfeature web-server -includeallsubfeature
Write-Progress -PercentComplete 99 -id 2 -Activity "Installing Completed" -Status "IIS" 


#Install 
Write-Progress -PercentComplete 100 -id 2 -Activity "Module Loaded" -Status "IIS" 
Write-Progress -PercentComplete 50 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Import-Module WebAdministration
Write-Progress -PercentComplete 5 -id 2 -Activity "Initialize Install" -Status "Reading Configuration" 


##Create User
Write-Progress -PercentComplete 50 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 5 -id 2 -Activity "Configuration Started" -Status "Creating App Pool Account" 

new-aduser $AppPoolUserName -enable $true -AccountPassword (ConvertTo-SecureString -AsPlainText $AppPoolPassword -Force) -PassThru -Surname $AppPoolUserName -GivenName $AppPoolUserName  -Description “Test users” 

Write-Progress -PercentComplete 55 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 10 -id 2 -Activity "Configuration Started" -Status "Creating App Pool Account Completed !!" 



##Create WebApp
Write-Progress -PercentComplete 56 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 11 -id 2 -Activity "Configuration Started" -Status "Creating Web Application 1" 

Create-WebAppAndPool -SiteName $WebSiteName -AppName $appName -AppFolder $appPath
Create-WebAppAndPool -SiteName $WebSiteName -AppName $appName2 -AppFolder $appPath2
#Create-WebAppAndPool -SiteName $WebSiteName -AppName $appName3 -AppFolder $appPath3


Write-Progress -PercentComplete 60 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 20 -id 2 -Activity "Configuration Started" -Status "Creating Web Application 1 Completed !!" 

sleep(2)
##Set App Pool Credentials
Write-Progress -PercentComplete 61 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 21 -id 2 -Activity "Configuration Started" -Status "Set App Pool Credentials " 

Set-AppPoolCredentials -AppName $appName -UserName $AppPoolUserName -Password $AppPoolPassword -Domain $AppPoolDomain
Set-AppPoolCredentials -AppName $appName2 -UserName $AppPoolUserName -Password $AppPoolPassword -Domain $AppPoolDomain
#Set-AppPoolCredentials -AppName $appName3 -UserName $AppPoolUserName -Password $AppPoolPassword -Domain $AppPoolDomain

Write-Progress -PercentComplete 70 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 50 -id 2 -Activity "Configuration Started" -Status "Set App Pool Credentials  Completed !!" 


##Setup Kerberos for App Pool
Write-Progress -PercentComplete 71 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 50 -id 2 -Activity "Configuration Started" -Status "Set Kerberos !!" 

Set-KerberosAuthForAppPool -WebSiteName $WebSiteName -AppName $appName

Write-Progress -PercentComplete 80 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 70 -id 2 -Activity "Configuration Started" -Status "Set Kerberos   Completed !!" 


##SetSPn
Write-Progress -PercentComplete 81 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 70 -id 2 -Activity "Configuration Started" -Status "Set SPN !!" 

Add-SPN -UserName $AppPoolUserName

Write-Progress -PercentComplete 90 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 80 -id 2 -Activity "Configuration Started" -Status "Set SPN Completed !!" 

##set KCD

Write-Progress -PercentComplete 91 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration" 
Write-Progress -PercentComplete 81 -id 2 -Activity "Configuration Started" -Status "Set KCD !!" 

#Add-KCD -AppPoolUserName $AppPoolUserName -AppProxyConnetor $AppProxyConnector

Write-Progress -PercentComplete 99 -id 1 -Activity "App Proxy Demo Installer " -Status "Starting Configuration"  
Write-Progress -PercentComplete 99 -id 2 -Activity "Configuration Started" -Status "Set KCD Completed!!" 
sleep (2)

Write-Progress -PercentComplete 100 -id 1 -Activity "App Proxy Demo Installer " -Status "Comppleting Configuration"  
Write-Progress -PercentComplete 100 -id 2 -Activity "Configuration Started" -Status "Confuguration  Completed!!" 
