#Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

#GitHub Repro Credentials
$credentials=""
$repo = "jeevanbisht/Utils"
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Authorization", "token $credentials")
$headers.Add("Accept", "application/json")

[string]$downloadFolder="c:\NaasPreview1\"

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

##Create Folder
if (!(Test-Path $downloadFolder -PathType Container)) {
New-Item -ItemType Directory -Force -Path $downloadFolder
}

$file = "$downloadFolder\master.zip"
$download1= "https://github.com/jeevanbisht/Utils/archive/refs/heads/main.zip"

#Write-Host Dowloading latest release
Invoke-WebRequest -Uri $download1 -Headers $headers -OutFile $file
Expand-Archive "$downloadFolder\master.zip" -DestinationPath $downloadFolder -Force

[string]$kickStartFolder = $downloadFolder + "Utils-main\Version1\"
[string]$kickStartScript = $kickStartFolder + "install.ps1"
Invoke-Script $kickStartScript 
