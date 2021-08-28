[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [string] $azureUsername,

    [Parameter(Mandatory = $true)]
    [string] $azurePassword,
	
    [Parameter(Mandatory = $true)]
    [string] $azurePasswordKey,	
	
    [Parameter(Mandatory = $true)]
    [string] $azureTenantId,

    [Parameter(Mandatory = $true)]
    [string] $azureSubscriptionId,

    [Parameter(Mandatory = $true)]
    [string] $resourceGroupName,
	
    [Parameter(Mandatory = $true)]
    [string] $storageAccountName,

    [Parameter(Mandatory = $true)]
    [string] $domain
)

#####################################

##########
# Helper #
##########
#region Functions
function LogInfo($message)
{
    Log "Info" $message
}

function LogError($message)
{
    Log "Error" $message
}

function LogSkip($message)
{
    Log "Skip" $message
}

function LogWarning($message)
{
    Log "Warning" $message
}

function Log
{

    <#
    .SYNOPSIS
   Creates a log file and stores logs based on categories with tab seperation

    .PARAMETER category
    Category to put into the trace

    .PARAMETER message
    Message to be loged

    .EXAMPLE
    Log 'Info' 'Message'

    #>

    Param (
        $category = 'Info',
        [Parameter(Mandatory = $true)]
        $message
    )

	$logPinpointLabel = "pipeline.yml JoinAzureFilesToTheDomain.ps1:"
    $date = get-date
    $content = "[$date]`t$category`t$logPinpointLabel`t`t$message`n"
    Write-Output "$content"

    if (! $script:Log)
	{
        $File = Join-Path $env:TEMP "log.log"
        Write-Error "pipeline.yml JoinAzureFilesToTheDomain.ps1: Log file not found, create new $File"
        $script:Log = $File
    }
    else
	{
        $File = $script:Log
    }
    Add-Content $File $content -ErrorAction Stop
}

function Set-Logger
{
    <#
    .SYNOPSIS
    Sets default log file and stores in a script accessible variable $script:Log
    Log File name "executionCustomScriptExtension_$date.log"

    .PARAMETER Path
    Path to the log file

    .EXAMPLE
    Set-Logger
    Create a logger in
    #>

    Param (
        [Parameter(Mandatory = $true)]
        $Path
    )

    # Create central log file with given date

    $date = Get-Date -UFormat "%Y-%m-%d %H-%M-%S"

    $scriptName = (Get-Item $PSCommandPath ).Basename
    $scriptName = $scriptName -replace "-", ""

    Set-Variable logFile -Scope Script
    $script:logFile = "executionCustomScriptExtension_" + $scriptName + "_" + $date + ".log"

    if ((Test-Path $path ) -eq $false)
	{
        $null = New-Item -Path $path -type directory
    }

    $script:Log = Join-Path $path $logfile

    Add-Content $script:Log "Date`t`t`tCategory`t`tDetails"
}
#endregion

## MAIN
Set-Logger "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\JoinAzureFilesToTheDomain"

<#
.SYNOPSIS
Upload Scripts and Executable files needed to customize WVD VMs to the created Storage Accounts blob containers.

.DESCRIPTION
This cmdlet uploads files specifiied in the contentToUpload-sourcePath parameter to the blob specified in the contentToUpload-targetBlob parameter to the specified Azure Storage Account.

.PARAMETER Url
Specifies the URI from which to download data.

.PARAMETER FileName
Specifies the name of the local file that is to receive the data.

.PARAMETER Confirm
Will promt user to confirm the action to create invasible commands

.PARAMETER WhatIf
Dry run of the script

.EXAMPLE
    Import-WVDSoftware -Url "https://aka.ms/fslogix_download" -FileName "FSLogixApp.zip"

    Downloads file from the specified Uri and save it to the specified filepath 
#>

function Import-WVDSoftware {

    [CmdletBinding(SupportsShouldProcess = $True)]
    param(
        [Parameter(
            Mandatory = $true,
            HelpMessage = "Specifies the URI from which to download data."
        )]
        [string] $Url,

        [Parameter(
            Mandatory = $true,
            HelpMessage = "Specifies the name of the local file that is to receive the data."
        )]
        [string] $FileName
    )
	
	$message = "Getting current time."
	LogInfo($message)
    Write-Output "$message"
    $start_time = Get-Date

    try
	{
		$message = "Starting download...."
		LogInfo($message)	
        Write-Output "$message"
		
        if ($PSCmdlet.ShouldProcess("Required executable files from $url to $filename", "Import"))
		{
            (New-Object System.Net.WebClient).DownloadFile($Url, $FileName)
        }

		$message = "Download completed."
		LogInfo($message)		
        Write-Output "$message"
		
		$message = "Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"
		LogInfo($message)			
        Write-Output "$message"
    }
    catch
	{
		$message = "Error Message: Download FAILED: $_"
		LogInfo($message)	
        Write-Output "$logPinpointLabel $message"
    }
}
	
$logPinpointLabel = "pipeline.yml Process_JoinAzureFilesToTheDomain_task JoinAzureFilesToTheDomain.ps1 -"

$azFilesHybridPsd1ScriptUrl = "https://gist.githubusercontent.com/RDrilon2020/3fad970ba18c3a29d4eb7724ead95196/raw/08f2e1a4ff725a98e50f456d466004bb3a78d406/AzFilesHybrid.psd1"
$azFilesHybridPsm1ScriptUrl = "https://gist.githubusercontent.com/RDrilon2020/be3a5dbdb48c03a7af6aaa96b646f7c9/raw/d02d8589884332253a288325898c5362b315b771/AzFilesHybrid.psm1"
$copyToPSPathPs1 = "https://gist.githubusercontent.com/RDrilon2020/6ae43fcb13052370e8aadf90e94447fd/raw/7fea133ee3b677b081105480a39fc7c57bfd76d7/CopyToPSPath.ps1"

$message = "Start Log"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Download the [AzFilesHybrid.psd1] script."
LogInfo($message)	
Write-Output "$message"
Import-WVDSoftware -Url "$azFilesHybridPsd1ScriptUrl" -FileName "$PSScriptRoot\AzFilesHybrid.psd1"
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Download the [AzFilesHybrid.psm1] script."
LogInfo($message)	
Write-Output "$message"		
Import-WVDSoftware -Url "$azFilesHybridPsm1ScriptUrl" -FileName "$PSScriptRoot\AzFilesHybrid.psm1"
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Download the [CopyToPSPath.ps1] script."
LogInfo($message)	
Write-Output "$message"		
Import-WVDSoftware -Url "$copyToPSPathPs1" -FileName "$PSScriptRoot\CopyToPSPath.ps1"
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Setting execution policy."
LogInfo($message)	
Write-Output "$message"		
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser -Force
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Import required Powershell modules."
LogInfo($message)	
Write-Output "$message"	
. $PSScriptroot\CopyToPSPath.ps1
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Installing the NuGet package provider..."
LogInfo($message)	
Write-Output "$message"		
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Verbose
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Installing the PowershellGet module..."
LogInfo($message)	
Write-Output "$message"		
Install-Module -Name PowershellGet -MinimumVersion 2.2.4.1 -Force -Verbose
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Installing the Az module..."
LogInfo($message)	
Write-Output "$message"		
Install-Module -Name Az -Force -Verbose
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Installing the AzFilesHybrid module..."
LogInfo($message)	
Write-Output "$message"
Import-Module -Name AzFilesHybrid -Force -Verbose
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Creating [$azureUsername] credentials for logging in to Azure."
LogInfo($message)	
Write-Output "$message"

$azurePasswordKeyDecrypted = ConvertTo-SecureString $azurePasswordKey -Key(1..16)
$message = "azurePasswordKeyDecrypted: $azurePasswordKeyDecrypted"
LogInfo($message)	
Write-Output "$message"

$azurePasswordDecryptedPassword = ConvertTo-SecureString $azurePassword -SecureKey $azurePasswordKeyDecrypted
$message = "azurePasswordDecryptedPassword: $azurePasswordDecryptedPassword"
LogInfo($message)	
Write-Output "$message"

$TestCred1 = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $azureUsername, $azurePasswordDecryptedPassword
$textPass1 = $TestCred1.GetNetworkCredential().password

$StartTime = Get-Date
$message = "Creating a credential object from the Azure Username [$azureUsername] and Password [$textPass1]."
LogInfo($message)	
Write-Output "$message"

$GISAzureSecureStringPassword = ConvertTo-SecureString -String $textPass1 -AsPlainText -Force

$GISAzureCredential = New-Object System.Management.Automation.PSCredential($azureUsername, $GISAzureSecureStringPassword)
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).TotalMinutes) minute(s)"
LogInfo($message)	
Write-Output "$message"	

LogInfo("Using Tenant ID: [$azureTenantId] and Subscription: [$azureSubscriptionId]")

$StartTime = Get-Date
$message = "Logging in to Azure for [$azureUsername]."
LogInfo($message)
Write-Output "$message"
$ConnectAzAccount = Connect-AzAccount -Credential $GISAzureCredential -TenantId $azureTenantId -Subscription $azureSubscriptionId -Verbose

$message = "$ConnectAzAccount"
LogInfo($message)	
Write-Output "$message"	
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$AzureFilesOrganizationalUnit = "AzureFiles"

$StartTime = Get-Date
$message = "Checking if the [$AzureFilesOrganizationalUnit] Organizational Unit already exists."
LogInfo($message)
Write-Output "$message"

$GetADOrganizationalUnit = Get-ADOrganizationalUnit -Filter "Name -like '$AzureFilesOrganizationalUnit'"
$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
if($GetADOrganizationalUnit -eq $null)
{
	$message = "Creating the [$AzureFilesOrganizationalUnit] Organizational Unit since it doesn't exists."
	LogInfo($message)
	Write-Output "$message"

	$NEWADOrganizationalUnit = NEW-ADOrganizationalUnit "$AzureFilesOrganizationalUnit"

	$message = "The [$AzureFilesOrganizationalUnit] Organizational Unit has been created successfully."
	LogInfo($message)
	Write-Output "$message"	
}
else
{
	$message = "GetADOrganizationalUnit: $GetADOrganizationalUnit"
	LogInfo($message)
	Write-Output "$message"	

	$message = "Skipping the creation of the [$AzureFilesOrganizationalUnit] Organizational Unit since it already exists."
	LogInfo($message)
	Write-Output "$message"
}

$message = "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"
LogInfo($message)	
Write-Output "$message"

$StartTime = Get-Date
$message = "Joining the [$storageAccountName] Azure Files to the [$domain] domain."
LogInfo($message)	
Write-Output "$message"

$GetAzContext = Get-AzContext
$message = "GetAzContext: $GetAzContext"
LogInfo($message)
Write-Output "$message"	

$GetAzContextAccount = $GetAzContext.Account
$message = "GetAzContextAccount: $GetAzContextAccount"
LogInfo($message)
Write-Output "$message"	

$GetAzContextName = $GetAzContext.Name
$message = "GetAzContextName: $GetAzContextName"
LogInfo($message)
Write-Output "$message"

$GetAzContextTenant = $GetAzContext.Tenant
$message = "GetAzContextTenant: $GetAzContextTenant"
LogInfo($message)
Write-Output "$message"

$GetAzContextSubscription = $GetAzContext.Subscription
$message = "GetAzContextSubscription: $GetAzContextSubscription"
LogInfo($message)
Write-Output "$message"

Join-AzStorageAccount `
	-ResourceGroupName $resourceGroupName `
	-StorageAccountName $storageAccountName `
	-Domain $domain `
	-DomainAccountType "ComputerAccount" `
	-OrganizationalUnitName "AzureFiles" -OverwriteExistingADObject -Verbose

$message = "Azure Files has been joined to the domain."
LogInfo($message)
Write-Output "$message"	

$message = "Execution of the JoinAzureFilesToTheDomain.ps1 script has completed."
LogInfo($message)	
Write-Output "$message"
