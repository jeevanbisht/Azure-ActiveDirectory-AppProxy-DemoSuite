
<# 
 
.SYNOPSIS
	BootStrap.ps1 is a Windows PowerShell script to download and kickstart the Azure AD App Proxy Demo environment 
.DESCRIPTION
	Version: 1.0.0
	BootStrap.ps1 is a Windows PowerShell script to download and kickstart the Azure AD App Proxy Demo environment.
        It will install IIS completely, configure the application including KCD. Requires the App Proxy Connector to be preinstalled for KCD configuration.
.DISCLAIMER
	THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
	ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
	THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
	PARTICULAR PURPOSE.
	Copyright (c) Microsoft Corporation. All rights reserved.
#> 


##This can be customized
$destinationDirectory ="c:\AppDemov1"


##Donot Modify
function Invoke-Script
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Script,

        [Parameter(Mandatory = $false)]
        [object[]]
        $ArgumentList
    )

    $ScriptBlock = [Scriptblock]::Create((Get-Content $Script -Raw))
    Invoke-Command -NoNewScope -ArgumentList $ArgumentList -ScriptBlock $ScriptBlock -Verbose
}


[string]$KickStart = $destinationDirectory + "\" + "Azure-ActiveDirectory-AppProxy-DemoSuite-master\Website\Install.ps1"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri "https://github.com/jeevanbisht/Azure-ActiveDirectory-AppProxy-DemoSuite/archive/master.zip"
(New-Object Net.WebClient).DownloadFile('https://github.com/jeevanbisht/Azure-ActiveDirectory-AppProxy-DemoSuite/archive/master.zip',"$env:TEMP\master.zip");
New-Item -Force -ItemType directory -Path $destinationDirectory
Expand-Archive  "$env:TEMP\master.zip" -DestinationPath $destinationDirectory -Force 
Invoke-Script $KickStart

