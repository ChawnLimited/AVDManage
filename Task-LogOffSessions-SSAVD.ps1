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
	If ($VMSS.VirtualMachineProfile.OsProfile.ComputerNamePrefix) {$Global:VMSSImage="Generalized"}
	else {$Global:VMSSImage="Specialized"}
}

# AD or Entra joined
%{
	$VS=get-azvmss -ResourceGroupName $SSRG -VMScaleSetName $SS
	if ($ADDomain=(($VS.VirtualMachineProfile.ExtensionProfile.Extensions | Where-Object {$_.Name -eq 'AVDTurbo'}).settings)["ADDomain"].value) {$ADDomain = "." + $ADDomain}
}

# Get the VMSS VM Instances
%{
	if ($OrchMode -eq 'Uniform'){$SSVMs=get-azvmssvm -ResourceGroupName $SSRG -VMScaleSetName $SS}
	else {$SSVMs=get-azvm -ResourceGroupName $SSRG | where-object {$_.VirtualMachineScaleSet.id -eq $VMSS.id}}
}

# Logoff AVD Sessions for all VM instances in the Scale Set
%{
foreach ($VM in $SSVMs)
	{
	if ($VMSSImage -eq "Generalized") {$VMName=$VM.OsProfile.Computername + $ADDomain}
	else {$VMName=$VM.Name.Replace('_','') + $ADDomain}
	write-host "Logoff sessions for " $VMName
	Get-AzWvdUserSession -HostPoolName $hp -ResourceGroupName $hprg -SessionHostName $VMName | Remove-AzWvdUserSession -Force
	}
}


