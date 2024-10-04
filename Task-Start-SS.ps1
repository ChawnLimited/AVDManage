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

# check the Scale Set is not Ephemeral
$caching=(Get-AzVmss -ResourceGroupName $SSRG -VMScaleSetName $SS).VirtualMachineProfile.StorageProfile.OsDisk.Caching

if ($caching -eq 'ReadWrite')
{
	# update all VM instances at the same time
	Start-AzVmss -ResourceGroupName $SSRG -VMScaleSetName $SS -InstanceId *
}
