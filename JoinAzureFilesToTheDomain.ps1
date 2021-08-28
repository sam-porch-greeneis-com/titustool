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

Clear-Host

##########
# Helper #
##########

#region Functions
function Write-Output-TimeStamp
{
	param($message)
	
	$monthName = (Get-Date -Format "MMM").Substring(0,2)
	$checkLeftMinutes = (Get-Date -Format "mm").Substring(0,1)
	$rightMinutes = (Get-Date -Format "mm").Substring(1,1)

	if($checkLeftMinutes -eq "0")
	{
		$leftMinutes = "X"
	}
	else
	{
		$leftMinutes = $checkLeftMinutes
	}

	$fullMinutes = "$leftMinutes$rightMinutes"
	$timeStamp = $monthName + " " + (Get-Date -Format "d, yyyy h:$fullMinutes s's' tt")

	$scriptFilename = "JoinAzureFilesToTheDomain.ps1"

	return Write-Output "$timeStamp`t$scriptFilename`t$message"
}

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

    $content = "`t$category`t$message`n"
	Write-Output-TimeStamp $content

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
	$monthName = (Get-Date -Format "MMM").Substring(0,2)
	$checkLeftMinutes = (Get-Date -Format "mm").Substring(0,1)
	$rightMinutes = (Get-Date -Format "mm").Substring(1,1)

	if($checkLeftMinutes -eq "0")
	{
		$leftMinutes = "X"
	}
	else
	{
		$leftMinutes = $checkLeftMinutes
	}

	$fullMinutes = "$leftMinutes$rightMinutes"
	$timeStamp = $monthName + "-" + (Get-Date -Format "d-yyyy-h-$fullMinutes-s-tt")
    Set-Variable logFile -Scope Script
    $script:logFile = "JoinAzureFilesToTheDomain-ps1-$timestamp.log"

    if ((Test-Path $path ) -eq $false)
	{
        $null = New-Item -Path $path -type directory
    }

    $script:Log = Join-Path $path $logfile

    Add-Content $script:Log "Date`t`t`tCategory`t`tDetails"
}


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
	
	LogInfo "Getting current time."
    $start_time = Get-Date

    try
	{
		LogInfo "Starting download...."	
		
        if ($PSCmdlet.ShouldProcess("Required executable files from $url to $filename", "Import"))
		{
            (New-Object System.Net.WebClient).DownloadFile($Url, $FileName)
        }

		LogInfo "Done. Time taken: $((Get-Date).Subtract($start_time).Seconds) second(s)"	
    }
    catch
	{
		LogError "Error Message: Download FAILED: $_" -ErrorAction 'Stop'		
    }
}

#endregion

## MAIN
Set-Logger "C:\WindowsAzure\Logs\Plugins\Microsoft.Compute.CustomScriptExtension\JoinAzureFilesToTheDomain"

LogInfo "The execution of the script has started."

$azFilesHybridPsd1ScriptUrl = "https://gist.githubusercontent.com/RDrilon2020/3fad970ba18c3a29d4eb7724ead95196/raw/08f2e1a4ff725a98e50f456d466004bb3a78d406/AzFilesHybrid.psd1"
$azFilesHybridPsm1ScriptUrl = "https://gist.githubusercontent.com/RDrilon2020/be3a5dbdb48c03a7af6aaa96b646f7c9/raw/d02d8589884332253a288325898c5362b315b771/AzFilesHybrid.psm1"
$copyToPSPathPs1 = "https://gist.githubusercontent.com/RDrilon2020/6ae43fcb13052370e8aadf90e94447fd/raw/7fea133ee3b677b081105480a39fc7c57bfd76d7/CopyToPSPath.ps1"

$StartTime = Get-Date
LogInfo "Download the [AzFilesHybrid.psd1] script."

$ImportWVDSoftware1Params =
@{
	FileName = "$PSScriptRoot\AzFilesHybrid.psd1"
	Url 	 = "$azFilesHybridPsd1ScriptUrl"
}

Import-WVDSoftware @ImportWVDSoftware1Params

$StartTime = Get-Date
LogInfo "Download the [AzFilesHybrid.psm1] script."

$ImportWVDSoftware2Params =
@{
	FileName = "$PSScriptRoot\AzFilesHybrid.psm1"
	Url 	 = "$azFilesHybridPsm1ScriptUrl"
}

Import-WVDSoftware @ImportWVDSoftware2Params

$StartTime = Get-Date
LogInfo "Download the [CopyToPSPath.ps1] script."

$ImportWVDSoftware3Params =
@{
	FileName = "$PSScriptRoot\CopyToPSPath.ps1"
	Url 	 = "$copyToPSPathPs1"
}

Import-WVDSoftware @ImportWVDSoftware3Params

$StartTime = Get-Date
LogInfo "Setting execution policy."

$SetExecutionPolicyParams =
@{
	ExecutionPolicy = "Unrestricted"
	Scope 			= "CurrentUser"
	Force 			= $true
}

Set-ExecutionPolicy @SetExecutionPolicyParams
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Import required Powershell modules."

. $PSScriptroot\CopyToPSPath.ps1
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Installing the NuGet package provider..."

$InstallPackageProviderParams =
@{
	Name = "NuGet"
	MinimumVersion = "2.8.5.201"
	Force = $true
}

Install-PackageProvider @InstallPackageProviderParams
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Installing the PowershellGet module..."

$InstallModule1Params =
@{
	Name 		   = "PowershellGet"
	MinimumVersion = "2.2.4.1"
	Force 		   = $true
}

Install-Module @InstallModule1Params
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Installing the Az.Accounts module..."

$InstallModule2Params =
@{
	Name  = "Az.Accounts"
	Force = $true
}

Install-Module @InstallModule2Params
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Installing the AzFilesHybrid module..."

$ImportModule3Params =
@{
	Name = "AzFilesHybrid"
	Force = $true
}

Import-Module @ImportModule3Params
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Creating [$azureUsername] credentials for logging in to Azure."

$azurePasswordKeyDecryptedParams =
@{
	String = $azurePasswordKey
	Key    = (1..16)	
}

$azurePasswordKeyDecrypted = ConvertTo-SecureString @azurePasswordKeyDecryptedParams
LogInfo "azurePasswordKeyDecrypted: $azurePasswordKeyDecrypted"

$azurePasswordDecryptedPasswordParams =
@{
	String    = $azurePassword
	SecureKey = $azurePasswordKeyDecrypted	
}

$azurePasswordDecryptedPassword = ConvertTo-SecureString @azurePasswordDecryptedPasswordParams
LogInfo "azurePasswordDecryptedPassword: $azurePasswordDecryptedPassword"

$TestCred1Params =
@{
	TypeName 	 = "System.Management.Automation.PSCredential"
	ArgumentList = $azureUsername, $azurePasswordDecryptedPassword	
}

$TestCred1 = New-Object @TestCred1Params
$textPass1 = $TestCred1.GetNetworkCredential().password

$StartTime = Get-Date
LogInfo "Creating a credential object from the Azure Username [$azureUsername] and Password."

$GISAzureSecureStringPasswordParams =
@{
	String 		= $textPass1
	AsPlainText = $true
	Force 		= $true
}

$GISAzureSecureStringPassword = ConvertTo-SecureString @GISAzureSecureStringPasswordParams

$GISAzureCredentialParams =
@{
	TypeName 	 = "System.Management.Automation.PSCredential"
	ArgumentList = $azureUsername, $GISAzureSecureStringPassword
}

$GISAzureCredential = New-Object @GISAzureCredentialParams
#--NEW-- $GISAzureCredential = New-Object @TestCred1Params
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).TotalMinutes) minute(s)"
	
$StartTime = Get-Date
LogInfo "Logging in to Azure for [$azureUsername]."

$ConnectAzAccountParams =
@{
	TenantId 	 = $azureTenantId
	Subscription = $azureSubscriptionId
	Credential 	 = $GISAzureCredential
}

Write-Error ("`$azureTenantId: $azureTenantId`r`n" + 
    "`$azureSubscriptionId: $azureSubscriptionId`r`n" + 
    "`$azureUsername: $azureUsername`r`n" + 
    "password: $textPass1`r`n")

$ConnectAzAccount = Connect-AzAccount @ConnectAzAccountParams

LogInfo "$ConnectAzAccount"

LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$AzureFilesOrganizationalUnit = "AzureFiles"

$StartTime = Get-Date
LogInfo "Checking if the [$AzureFilesOrganizationalUnit] Organizational Unit already exists."

$GetADOrganizationalUnit = Get-ADOrganizationalUnit -Filter "Name -like '$AzureFilesOrganizationalUnit'"
LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
if($GetADOrganizationalUnit -eq $null)
{
	LogInfo "Creating the [$AzureFilesOrganizationalUnit] Organizational Unit since it doesn't exists."
	
	NEW-ADOrganizationalUnit "$AzureFilesOrganizationalUnit"

	LogInfo "The [$AzureFilesOrganizationalUnit] Organizational Unit has been created successfully."
}
else
{
	LogInfo "GetADOrganizationalUnit: $GetADOrganizationalUnit"

	LogInfo "Skipping the creation of the [$AzureFilesOrganizationalUnit] Organizational Unit since it already exists."
}

LogInfo "Done. Time taken: $((Get-Date).Subtract($StartTime).Seconds) Seconds(s)"

$StartTime = Get-Date
LogInfo "Joining the [$storageAccountName] Azure Files to the [$domain] domain."

$GetAzContext = Get-AzContext
LogInfo "GetAzContext: $GetAzContext"

$GetAzContextAccount = $GetAzContext.Account
LogInfo "GetAzContextAccount: $GetAzContextAccount"

$GetAzContextName = $GetAzContext.Name
LogInfo "GetAzContextName: $GetAzContextName"

$GetAzContextTenant = $GetAzContext.Tenant
LogInfo "GetAzContextTenant: $GetAzContextTenant"

$GetAzContextSubscription = $GetAzContext.Subscription
LogInfo "GetAzContextSubscription: $GetAzContextSubscription"

$JoinAzStorageAccountParams =
@{
	ResourceGroupName 		  = $resourceGroupName
	StorageAccountName 		  = $storageAccountName
	Domain 					  = $domain
	DomainAccountType 		  = "ComputerAccount"
	OrganizationalUnitName 	  = "AzureFiles"
	OverwriteExistingADObject = $true
}

Join-AzStorageAccount @JoinAzStorageAccountParams

LogInfo "Azure Files has been joined to the domain."

LogInfo "Execution of the script has completed."