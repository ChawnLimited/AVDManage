# Chawn Limited 2025
# AVDJoin.ps1
# Version 2.0
# Joins a session host to an Azure AVD Hostpool using the AVD-Join Custom Script Extension at startup or rebuild

  #Parameters
  param(
	[String]$HostPool="",
	[String]$RG=""
	)

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-Join.log"


Function LogWrite
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

LogWrite "Starting Up"

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
	    	else {logwrite('Nuget is not available. Exit. ' + $_.Exception.Message); exit 3}
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
    catch {LogWrite ("Failed to add PSGallery as trusted repo") + $_.Exception.Message; exit 100}
}


Function UpdateModule
{
   Param ([string]$module)
	try {
	install-module $module
    	Logwrite ('Updated ' + $module)
    	}
    catch {Logwrite ('Failed to update ' + $module + "" +  $_.Exception.Message);exit 3}
}

 # Check for a Turbo deployment
	try{
		if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -ErrorAction SilentlyContinue).RegistrationToken)
		{$TURBO=(Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -ErrorAction SilentlyContinue).RegistrationToken;LogWrite ("Turbo Deployment started.")}
		else {$Turbo='False'}
	}
	catch{LogWrite ($_.Exception.Message);exit 200}


# check the device is domain joined
%{
if ((gwmi win32_computersystem).partofdomain -eq $false) {logwrite('Device is not AD Domain joined. Exit.')
exit 2}
else {logwrite('Device is AD Domain joined.')}
}

# check the agents are not already installed
%{
	if ($Turbo -ne "AVDTurbo") {
		if (get-item -path "C:\Program Files\Microsoft RDInfra" -ErrorAction SilentlyContinue)
		{logwrite('Remote Desktop Agents are already installed. Exit.');exit 1}
	}
}




# Check AZ Modules are present
%{
	try {
		if ($Turbo -ne "AVDTurbo") {
			if (Get-Module -name Az.Accounts -ListAvailable) {Logwrite('Az.Accounts is available.')}
			else {logwrite('Az.Accounts is not available. Will try and install.'); UpdateNuget; UpdateModule Az.Accounts;}

			if (Get-Module -name Az.DesktopVirtualization -ListAvailable) {Logwrite('Az.DesktopVirtualization is available.')}
			else {logwrite('Az.DesktopVirtualization is not available. Will try and install.'); UpdateModule Az.DesktopVirtualization;}
		}
	}
    catch {logwrite('Error importing Az Modules. ' + $_.Exception.Message); exit 3}
}

# get the DNS hostname of the VM
$hostname=[System.Net.Dns]::GetHostByName($env:computerName).HostName
logwrite('Hostname:' + $hostname)
logwrite('Hostpool:' + $hostpool)
logwrite('ClientID:' + $ClientID)


# Start the RDAGent downloads
try {
	if ($Turbo -ne "AVDTurbo") {
		if ($HostPool) {
		LogWrite ("Download RD Agents")
		New-Item -Path C:\Source -ItemType Directory -Force
		$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDagent.msi -UseBasicParsing;
		LogWrite ("Downloaded RDAgent.msi")
		$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDBoot.msi -UseBasicParsing;
		LogWrite ("Downloaded RDBoot.msi")		
		}
	}
}
catch {LogWrite ("Failed to download RDAgents. " + $_.Exception.Message);exit 99}


logwrite('Disable AZContextAutoSave')
try{
Disable-AzContextAutosave -Scope Process
}
catch{LogWrite ("Failed to disable AZContextAutoSasve. " + $_.Exception.Message);exit 112}


logwrite('Logon to Azure')
# Logon to Azure
	%{
		try {Add-AzAccount -identity
		if ((Get-AZAccessToken -ErrorAction SilentlyContinue).count -ne 0) {logwrite('Connected to Azure')}
		else {logwrite('Not connected to Azure. Exit.')
		exit 4}
		}
		catch{logwrite('Error connecting to Azure' +  $_.Exception.Message)
			exit 4}
	}

# check if the VM exists in the hostpool, if so remove it

%{
	try{
	if (Get-AzWvdSessionHost -HostPoolName $hostpool -ResourceGroupName $RG -Name $hostname -ErrorAction SilentlyContinue) 

	{Remove-AzWvdSessionHost -ResourceGroupName $RG -HostPoolName $HostPool -Name $hostname -ErrorAction stop
	logwrite ($hostname + ' exists in the ' + $hostpool + ' host pool. Will remove so the VM may join again.')}
	}
	catch{$_.Exception.Message}
}


# check if a valid Token exists to join the hostpool, if not generate one

$now=(get-date).addhours(2)
%{
	try{
	if ($now -gt (Get-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool).ExpirationTime)
		{logwrite ('Generate new WVD Token to join WVD Hostpool: ' + $HostPool)
		$WVDToken=(New-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool -ExpirationTime $((get-date).ToUniversalTime().AddHours(25).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))).Token}
	Else {logwrite ('WVDToken exists for Hostpool: ' + $HostPool)
	$WVDToken=(Get-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool).Token}
	}
	catch{$_.Exception.Message}
}

	try{
		if ($Turbo -eq "AVDTurbo") {
			if ($WVDToken) {
			LogWrite ("Starting Turbo Deployment")
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -Value $WVDTOKEN -force
			Get-Service -Name RDAgentBootLoader | Set-Service -StartupType Automatic
			Get-Service -Name RDAgentBootLoader | start-service
			LogWrite ("Turbo Deployment Complete")
			}
		}
	}
    catch {logwrite('Error with Turbo Deployment. ' + $_.Exception.Message); exit 201}



# deploy the RDAgent and RDBootloader

%{
    try {
		if ($Turbo -ne "AVDTurbo"){
			if ($WVDToken) {
  		    logwrite ('WVD Token to join WVD Hostpool: ' + $WVDToken)

    		### Install RDAgent
	    	logwrite('Install Remote Desktop Services Infrastructure Agent')
		    if (get-item -path C:\Source\RDagent.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=$WVDToken /qb /L*V RDAgent.log"}
			else{Logwrite("RDagent.msi is not available. Exit");exit 99}
		
    		### Install RDBoot
	    	logwrite ('Install Remote Desktop Agent Boot Loader')
		    if (get-item -path C:\Source\RDBoot.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"}
			else{Logwrite("RDBoot.msi is not available. Exit");exit 99}
		    LogWrite "Install RDS Agents completed."
			}
			Else {logwrite ('Could not retrieve a WVD Host Token for HostPool:' + $HostPool + '. Skip join WVD Hostpool')}
		}
	}
    catch {logwrite('Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 7}
}


# Wait for the SXS Network Agent and Geneva Agent to install
	try{		    
		    LogWrite "Wait for the SXS Network Agent and Geneva Agent to install"
			$i=0
			do {start-sleep -Seconds 1;$i++;} until(((get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed') -and ((get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed') -or $i -eq 50)
		    if (((get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed') -and ((get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed'))
			{LogWrite ("SXS Network Agent and Geneva Agent are installed")}
			Else {LogWrite ("SXS Network Agent or Geneva Agent installation failed");LogWrite ("SXS Network Agent: " + ((get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed'));LogWrite ("Geneva Agent: " + ((get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed'));LogWrite("Check " + $env:ProgramFiles + "\Microsoft RDInfra. The MSI files don't download sometimes.")}
		}
    catch {logwrite('Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 8}

# Logout of Azure
Disconnect-AzAccount
logwrite ('Disconnected from Azure')

exit 0

