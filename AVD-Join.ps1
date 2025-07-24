# Chawn Limited 2024
# AVDJoin.ps1
# Version 1.0
# Joins a session host to an Azure AVD Hostpool using the AVD-Join Extension at startup or rebuild

  #Parameters
  param(
	[String]$HostPool="",
	[String]$RG="",
	[String]$ClientID = "",
	[String]$ClientSecret = "",
	[String]$TenantID = ""
	)

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-Join.log"


Function LogWrite
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

Function UpdateNuget
{
# update Nuget
    try	{
		[Net.ServicePointManager]::SecurityProtocol =
    		[Net.ServicePointManager]::SecurityProtocol -bor
    		[Net.SecurityProtocolType]::Tls12
		Install-PackageProvider -Name NuGet -ForceBootstrap -Scope AllUsers -Force
		LogWrite "Updated NuGet"
    	}
    catch	{LogWrite "NuGet Update Failed"}

# trust PSGalllery
# access to www.powershellgallery.com
    try	{
	    if (-not(Get-PSRepository -Name "PSGallery"))
	    	{Register-PSRepository -Default -InstallationPolicy Trusted
	    	Register-PSRepository -Name PSGallery -InstallationPolicy Trusted -SourceLocation "https://www.powershellgallery.com/api/v2"
	    	LogWrite "Added PSGallery as trusted repo"}
	    Else {Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted}
	    }
    catch	{LogWrite "Failed to add PSGallery as trusted repo"; exit 100}
}


Function UpdateModule
{
   Param ([string]$module)
	try {
	install-module $module
    Logwrite ('Updated ' + $module)
    }

    catch {
        Logwrite ('Failed to update ' + $module)
    }
}



# check the agents are not already installed
%{
	if (get-item -path "C:\Program Files\Microsoft RDInfra" -ErrorAction SilentlyContinue)
	{exit 1}
}

# check the device is domain joined
%{
if ((gwmi win32_computersystem).partofdomain -eq $false) {logwrite('Device is not AD Domain joined. Exit.')
exit 2}
else {logwrite('Device is AD Domain joined.')}
}


# get the DNS hostname of the VM
$hostname=[System.Net.Dns]::GetHostByName($env:computerName).HostName
logwrite('Hostname:' + $hostname)
logwrite('Hostpool:' + $hostpool)
logwrite('ClientID:' + $ClientID)

### Create the AVD Agent PSCredential
$AVDCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
    UserName = $ClientId
    Password = (ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)[0]})
logwrite('Created PSCreds for Azure')

# Check AZ Modules are present
%{
		try {

		if (Get-PackageProvider -Name Nuget) {Logwrite('Nuget is available')}
		else {logwrite('Nuget is not available. Will try and install.'); UpdateNuget;
    		if (Get-PackageProvider -Name Nuget) {Logwrite('Nuget is available')}
	    	else {logwrite('Nuget is not available. Exit.'); exit 3}
             }

		if (Get-Module -name Az.Accounts -ListAvailable) {Logwrite('Az.Accounts is available.')}
		else {logwrite('Az.Accounts is not available. Will try and install.'); UpdateModule Az.Accounts;
			if (Get-Module -name Az.Accounts -ListAvailable) {Logwrite('Az.Accounts is available')}
			else {logwrite('Az.Accounts is not available. Exit.'); exit 3}
             }

		if (Get-Module -name Az.DesktopVirtualization -ListAvailable) {Logwrite('Az.DesktopVirtualization is available.')}
		else {logwrite('Az.DesktopVirtualization is not available. Will try and install.'); UpdateModule Az.DesktopVirtualization;
            if (Get-Module -name Az.DesktopVirtualization -ListAvailable) {Logwrite('Az.DesktopVirtualization is available')}
	    	else {logwrite('Az.DesktopVirtualization is not available. Exit.'); exit 3}
		     }

		    }
		
        catch {logwrite('Error importing Az Modules'); exit 3}
}

Disable-AzContextAutosave -Scope Process

# Logon to Azure
%{
	try {Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $AVDCred
	if ((Get-AZAccessToken -ErrorAction SilentlyContinue).count -ne 0) {logwrite('Connected to Azure')}
	else {logwrite('Not connected to Azure. Exit.')
	exit 4}
	}
	catch{}
}

# check if the VM exists in the hostpool, if so remove it

%{
if (Get-AzWvdSessionHost -HostPoolName $hostpool -ResourceGroupName $RG -Name $hostname -ErrorAction SilentlyContinue) 

	{Remove-AzWvdSessionHost -ResourceGroupName $RG -HostPoolName $HostPool -Name $hostname -ErrorAction stop
	logwrite ($hostname + ' exists in the ' + $hostpool + ' host pool. Will remove so the VM may join again.')}
}


# check if a valid Token exists to join the hostpool, if not generate one

$now=(get-date).addhours(2)
%{
	if ($now -gt (Get-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool).ExpirationTime)
		{logwrite ('Generate new WVD Token to join WVD Hostpool: ' + $HostPool)
		$WVDToken=(New-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool -ExpirationTime $((get-date).ToUniversalTime().AddHours(25).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))).Token}
	Else {logwrite ('WVDToken exists for Hostpool: ' + $HostPool)
	$WVDToken=(Get-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool).Token}
}


# deploy the RDAgent and RDBootloader

%{
if ($WVDToken)
	{
	logwrite ('WVD Token to join WVD Hostpool: ' + $WVDToken)

		### Install RDAgent
		logwrite('Install Remote Desktop Services Infrastructure Agent')
		$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv"
		Invoke-WebRequest -Uri $URI -OutFile RDAgent.msi -UseBasicParsing
		Start-Process msiexec.exe -Wait -ArgumentList "/I RDAgent.msi REGISTRATIONTOKEN=$WVDToken /qb /L*V RDAgent.log"
		
		### Install RDBroker
		logwrite ('Install Remote Desktop Agent Boot Loader')
		$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH"
		Invoke-WebRequest -Uri $URI -OutFile RDBoot.msi -UseBasicParsing
		Start-Process msiexec.exe -Wait -ArgumentList "/I RDBoot.msi /qb  /L*V RDBoot.log"

	}
	Else {logwrite ('Could not retrieve a WVD Host Token for HostPool:' + $HostPool + '. Skip join WVD Hostpool')}
}

# Logout of Azure
Disconnect-AzAccount
logwrite ('Disconnected from Azure')

exit 0

