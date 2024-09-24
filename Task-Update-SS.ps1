  #Parameters
  param(
	[Parameter(Mandatory)][String]$SS="",
	[Parameter(Mandatory)][String]$RG="",
	[String]$HP=""
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


# update all VM instances as the same time
Update-AzVmssInstance -ResourceGroupName $RG -VMScaleSetName $SS -InstanceId *

