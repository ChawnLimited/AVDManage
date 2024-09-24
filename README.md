AVDJoin.ps1 is used to join an Azure VM to an Azure Virtual Desktop HostPool. Service Principal Credentials are used to authenticate to Azure, remove the VM if it already exists in the hostpool, create a WVD token if necessary, download RD Agents and install. The Service Principal must have the ‘Desktop Virtualization Contributor role’ to the Resource Group that contains AVD Host Pools. 
