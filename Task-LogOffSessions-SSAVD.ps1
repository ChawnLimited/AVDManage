  #Parameters
  param(
	[Parameter(Mandatory)][String]$SS="",
	[Parameter(Mandatory)][String]$SSRG="",
	[String]$HP="",
	[String]$HPRG=""	
	)

# import modules
import-module Az.Accounts
import-module Az.Compute
import-module Az.DesktopVirtualization

# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave -Scope Process

# Connect to Azure with system-assigned managed identity
$AzureContext = (Connect-AzAccount -Identity).context

# Set and store context
$AzureContext = Set-AzContext -SubscriptionName $AzureContext.Subscription -DefaultProfile $AzureContext


# Logoff AVD Sessions for all VM instances in the Scale Set
$SSVMs=get-azvmssvm -ResourceGroupName $SSRG -VMScaleSetName $SS

%{
foreach ($VM in $SSVMs) 
	{$VMName='*'+$VM.OsProfile.Computername+'*';
	Get-AzWvdUserSession -HostPoolName $hp -ResourceGroupName $hprg | Where-Object {$_.Name -like $vmname} | Remove-AzWvdUserSession -Force}
}

