AVDJoin.ps1 is used to join an Azure VM to an Azure Virtual Desktop HostPool. Service Principal Credentials are used to authenticate to Azure, remove the VM if it already exists in the hostpool, create a WVD token if necessary, download RD Agents and install. The Service Principal must have the ‘Desktop Virtualization Contributor role’ to the Resource Group that contains AVD Host Pools. 
Task scripts are used for runbooks with an Azure Automation Account to perform scheduled actions on Azure Virtual Machine Scale Sets and Azure Virtual Desktop Session hosts.
AVD-Update.ps1 applies updates to an AVD Session Host Master Image.
AVD-PostUpdate.ps1 performs AVD Session Host Master Image maintenance tasks after an update.
AVD-Optimise.ps1 applies recommended updates to an AVD Session Host Master Image.
AVD-Seal.ps1 prepares an AVD Session Host Master Image for sysprep.
