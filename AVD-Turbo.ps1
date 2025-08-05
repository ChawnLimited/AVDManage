# Chawn Limited 2025
# AVD-Turbo.ps1
# Version 1.1
# Rename the VM, optionally Join VM (created from a specialized image) to Active Directory, and optionally install AVD Agents

#### Parameters

  param(
	[String]$ADDomain= "",			# Set the domain name in FQDN format
	[String]$OU= "",			# Set the Organisational Unit for the VM
	[String]$ADAdmin= "",			# Set the domain join user account
	[String]$ADAdminPW= "",			# Set the domain join user account password
	[String]$HostPool="",			# Set the WVD HostPool name
	[String]$RG="",				# Set the WVD HostPool Resource Group name
	[String]$ClientID = "",			# Set the AVDJoin Client ID
	[String]$ClientSecret = "",		# Set the AVDJoin Client Secret
	[String]$TenantID = ""			# Set the Azure Tenant ID
	)

#### End of Parameters

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-Turbo.log"

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
        if (Get-PackageProvider -Name Nuget -ListAvailable) {Logwrite('Nuget is available')}
            else {logwrite('Nuget is not available. Will try and install.')

	    	[Net.ServicePointManager]::SecurityProtocol =
    	    	[Net.ServicePointManager]::SecurityProtocol -bor
    		    [Net.SecurityProtocolType]::Tls12
		    
            Install-PackageProvider -Name NuGet -ForceBootstrap -Scope AllUsers -Force
		    if (Get-PackageProvider -Name Nuget -ListAvailable) {Logwrite('Nuget is available')}
	    	else {logwrite('Nuget is not available. Exit.'); exit 3}
            }
    	}
    catch {LogWrite "NuGet Update Failed"; exit 3}

# trust PSGalllery
# access to www.powershellgallery.com
    try	{
	    if (-not(Get-PSRepository -Name "PSGallery"))
	    	{Register-PSRepository -Default -InstallationPolicy Trusted
	    	Register-PSRepository -Name PSGallery -InstallationPolicy Trusted -SourceLocation "https://www.powershellgallery.com/api/v2"
	    	LogWrite "Added PSGallery as trusted repo"}
	    Else {Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted}
	    }
    catch {LogWrite "Failed to add PSGallery as trusted repo"; exit 100}
}


Function UpdateModule
{
   Param ([string]$module)
	try {
	install-module $module
    	Logwrite ('Updated ' + $module)
    	}
    catch {Logwrite ('Failed to update ' + $module)}
}

LogWrite "Starting Up"


# Save some time by starting the RDAGent downloads
if ($HostPool) {
		LogWrite "Download RD Agents"
		New-Item -Path C:\Source -ItemType Directory -Force
		$SB={$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDagent.msi -UseBasicParsing;}
		start-job -name 'DownloadRDInfraAgent' -scriptblock $SB
		$SB={$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDBoot.msi -UseBasicParsing;}
		start-job -name 'DownloadRDBootAgent' -scriptblock $SB
		}


LogWrite "Rename Computer"

	$d1=get-Date
	LogWrite ("Renaming Computer")
	do {
	start-sleep -seconds 1
	} until ((Get-ChildItem -Path C:\WindowsAzure\config -Filter *.xml).count -eq 1)

try {

	$d2=get-Date
	$dur=$d2-$d1
	LogWrite ("Duration: " + $dur.Hours + " hours " + $dur.Minutes + " mins " + $dur.Seconds + " secs")
	$xml=Get-ChildItem -Path C:\WindowsAzure\config -Filter *.xml | sort-object -Property CreationTime -descending
	
	$xmlfile = New-Object xml
	$xmlfile.Load($xml[0].fullname)
	
	$xpath="/RDConfig/Instances/Instance"
	$vmname=(Select-Xml -Path $xml.fullname -XPath $xpath | Select-Object -ExpandProperty Node).id
	$vmname=$vmname.Substring(1)

    if ($vmname -eq $env:computerName) {LogWrite ("Computer is already named " + $VMName + ". This must be the Master VM. Exit");exit 0}
	
	if((gwmi win32_computersystem).partofdomain -eq 0) {
	LogWrite ("Renaming Computer to " + $VMName)
	Rename-Computer -NewName $VMName -Force | Out-File -FilePath $Logfile -Append
	}
    }
Catch {
LogWrite ($_.Exception.Message)
exit 1
}


If ($ADDomain) {
		if((gwmi win32_computersystem).partofdomain -eq 0) {

try {
		$ADDomainCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
		UserName = $ADAdmin
		Password = (ConvertTo-SecureString -String $ADAdminPW -AsPlainText -Force)[0]})

		LogWrite ("Join Domain " + $ADDomain)
		Add-Computer -DomainName $ADDomain -OUPath $ou -Credential $ADDomainCred -Options JoinWithNewName,AccountCreate -Force -PassThru -Verbose | Out-File -FilePath $Logfile -Append
		LogWrite ("Ignore the Computername above. Add-Computer always reports the original name, not the new name.")
    }
catch{
LogWrite ($_.Exception.Message)
exit 2}

		}
}





If ($HostPool) {
		if (get-item -path "C:\Program Files\Microsoft RDInfra" -ErrorAction SilentlyContinue)
		{LogWrite ("Remote Desktop Agents are already installed. Exit")
        exit 3}
}


# check the device is domain joined
	%{
	if ((gwmi win32_computersystem).partofdomain -eq $false) {logwrite('Device is not AD Domain joined. Exit.')
	exit 4}
	else {logwrite('Device is AD Domain joined.')}
	}


# Check AZ Modules are present
%{
		try {
		if (Get-Module -name Az.Accounts -ListAvailable) {Logwrite('Az.Accounts is available.')}
		else {logwrite('Az.Accounts is not available. Will try and install.'); UpdateNuget; UpdateModule Az.Accounts;
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


# get the DNS hostname of the VM
	$hostname=$vmname + "." + $ADDomain
	logwrite('Hostname:' + $hostname)
	logwrite('Hostpool:' + $hostpool)
	logwrite('ClientID:' + $ClientID)

### Create the AVD Agent PSCredential
	$AVDCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
	    UserName = $ClientId
	    Password = (ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)[0]})
	logwrite('Created PSCreds for Azure')


Disable-AzContextAutosave -Scope Process

# Logon to Azure
	%{
		try {Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Credential $AVDCred
		if ((Get-AZAccessToken -ErrorAction SilentlyContinue).count -ne 0) {logwrite('Connected to Azure')}
		else {logwrite('Not connected to Azure. Exit.')
		exit 6}
		}
		catch{logwrite('Error connecting to Azure')
			exit 6}
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
    try {
	    if ($WVDToken)
  		    {
		    logwrite ('WVD Token to join WVD Hostpool: ' + $WVDToken)

    		### Install RDAgent
	    	logwrite('Install Remote Desktop Services Infrastructure Agent')
		    do {} until (get-item -path C:\Source\RDagent.msi)
		    Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=$WVDToken /qb /L*V RDAgent.log"
		
    		### Install RDBoot
	    	logwrite ('Install Remote Desktop Agent Boot Loader')
		    do {} until (get-item -path C:\Source\RDBoot.msi)
		    Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"
		    LogWrite "Install RDS Agents completed."

		    # Wait for the SXS Network Agent and Geneva Agent to install
		    LogWrite "Wait for the SXS Network Agent and Geneva Agent to install"
		    do {start-sleep -Milliseconds 500} until(get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue)
		    do {start-sleep -Milliseconds 500} until(get-package -name "*Geneva*" -ErrorAction SilentlyContinue)
		    LogWrite "SXS Network Agent and Geneva Agent are installed"
		    }
		    Else {logwrite ('Could not retrieve a WVD Host Token for HostPool:' + $HostPool + '. Skip join WVD Hostpool')}
        }
        catch {logwrite('Error installing Remote Desktop Agents'); exit 7}
	}

    # Logout of Azure
	    Disconnect-AzAccount
	    logwrite ('Disconnected from Azure')

	     


	LogWrite "Schedule a restart and exit"
	Start-Process -FilePath "shutdown.exe" -ArgumentList "-r -soft -t 5"
	exit 0


