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

# Get the Scale Set
$VMSS=get-azvmss -ResourceGroupName $SSRG -VMScaleSetName $SS
# Get the Orchestration Mode
$OrchMode=$vmss.OrchestrationMode
# Specialized or Generalized
%{
	If ($VMSS.VirtualMachineProfile.OsProfile.ComputerNamePrefix) {$Global:VMSSIMage="Generalized"}
	else {$Global:VMSSIMage="Specialized"}
}

# Get the VMSS VM Instances
%{
	if ($Orchmode -eq 'Uniform'){$SSVMs=get-azvmssvm -ResourceGroupName $SSRG -VMScaleSetName $SS}
	else {$SSVMs=get-azvm -ResourceGroupName $ssrg | where-object {$_.VirtualMachineScaleSet.id -eq $vmss.id}}
}

# Disable AVD Logons for all VM instances in the Scale Set
%{
foreach ($VM in $SSVMs)
	{
	if ($VMSSIMage -eq "Generalized") {$VMName=$VM.OsProfile.Computername + "."}
	else {$VMNAME=$VM.Name.Replace('_','') + "."}
	write-host "Disable Logons for " $VMNAME
	Get-AzWvdSessionHost -HostPoolName $HP -ResourceGroupName $HPRG | where-object {$_.Name.contains($VMName)} | Update-AzWvdSessionHost -AllowNewSession:$False -Force
	}
}

