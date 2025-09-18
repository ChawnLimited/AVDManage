# Chawn Limited 2025
# AVD-Join2.ps1
# Version 2.2
# Joins a session host to an Azure AVD Hostpool using the AVD-Join Custom Script Extension at startup or rebuild - For Generalized Images

  #Parameters
  param(
	[String]$HostPool="",
	[String]$RG="",
	[String]$ClientID = "",
	[String]$ClientSecret = "",
	[String]$TenantID = "",
	[String]$SubID = "",
	[String]$Audience = "",
	[String]$issuer = "",
	[String]$ExchURI = "",
	[String]$Scope = "",
	[String]$cat = "",
	[String]$creds = ""
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
	    	else {logwrite('100: Nuget is not available. Exit. ' + $_.Exception.Message); exit 100}
            }
    	}
    catch {LogWrite "101: NuGet Update Failed"; exit 101}

# trust PSGalllery
# access to www.powershellgallery.com
    try	{
	    if (-not(Get-PSRepository -Name "PSGallery"))
	    	{Register-PSRepository -Default -InstallationPolicy Trusted
	    	Register-PSRepository -Name PSGallery -InstallationPolicy Trusted -SourceLocation "https://www.powershellgallery.com/api/v2"
	    	LogWrite "Added PSGallery as trusted repo"}
	    Else {Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted}
	    }
    catch {LogWrite ("102: Failed to add PSGallery as trusted repo") + $_.Exception.Message; exit 102}
}


Function UpdateModule
{
   Param ([string]$module)
	try {
	install-module $module
    	Logwrite ('Updated ' + $module)
    	}
    catch {Logwrite ('201: Failed to update ' + $module + "" +  $_.Exception.Message);exit 201}
}

 # Check for a Turbo deployment
	try{
		if (($TURBO=Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -ErrorAction SilentlyContinue).RegistrationToken)
		{LogWrite ("Turbo Deployment started. " + $Turbo)}
		else {$Turbo='False'}
	}
	catch{LogWrite ("400: " + $_.Exception.Message);exit 400}


# check the device is domain joined
%{
	if ((gwmi win32_computersystem).partofdomain -eq $false) {logwrite('401: Device is not AD Domain joined. Exit.')
	exit 401}
	else {logwrite('Device is AD Domain joined.')}
}

# check if the RDAgent is already installed - Traditional deployment
if ($Turbo -ne "AVDTurbo")
{
	%{
		try{
		if ($Turbo -ne "AVDTurbo") {
			if (get-item -path "C:\Program Files\Microsoft RDInfra" -ErrorAction SilentlyContinue)
			{logwrite('Remote Desktop Agents are already installed. Exit.');exit 500}
			}
		}
		catch {logwrite('500: RDAgents are already installed' +  $_.Exception.Message); exit 500}
	}

# Check AZ Modules are present
	%{
		try {
							if (Get-Module -name Az.Accounts -ListAvailable) {Logwrite('Az.Accounts is available.')}
				else {logwrite('Az.Accounts is not available. Will try and install.'); UpdateNuget; UpdateModule Az.Accounts;}

				if (Get-Module -name Az.DesktopVirtualization -ListAvailable) {Logwrite('Az.DesktopVirtualization is available.')}
				else {logwrite('Az.DesktopVirtualization is not available. Will try and install.'); UpdateModule Az.DesktopVirtualization;}
			}
		catch {logwrite('200: Error importing Az Modules' +  $_.Exception.Message); exit 200}
	}
	
# Start the RDAGent downloads
	%{
		try {
			if ($HostPool) {
				LogWrite ("Download RD Agents")
				New-Item -Path C:\Source -ItemType Directory -Force
				$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDagent.msi -UseBasicParsing;
				LogWrite ("Downloaded RDAgent.msi")
				$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDBoot.msi -UseBasicParsing;
				LogWrite ("Downloaded RDBoot.msi")		
				}
			}
		catch {LogWrite ("600: Failed to download RDAgents. " + $_.Exception.Message);exit 600}
	}	
}

# get the DNS hostname of the VM
$hostname=[System.Net.Dns]::GetHostByName($env:computerName).HostName
logwrite('Hostname:' + $hostname)
logwrite('Hostpool:' + $hostpool)
logwrite('ClientID:' + $ClientID)


logwrite('Logon to Azure')
# Logon to Azure
	%{	
		try {$accessToken =(Invoke-RestMethod -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-08-01&resource=$audience" -Headers @{Metadata="true"} -Method GET).access_token
			
			if ($accesstoken) {logwrite('Connected to Azure')}
			else {logwrite('800: Not connected to Azure. Exit.')
			exit 800}
		
			$body = @{
			client_id = $clientid
			client_assertion = $accessToken
			client_assertion_type = $cat
			grant_type = $creds
			scope = $scope
			subject=$SubjectID
			audience=$audience
			issuer=$ISS
			}
	
			$response = Invoke-RestMethod -Uri $ExchUri -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
					if ($response) {logwrite('Connected to AzureX');Connect-AzAccount -scope process -accountid $clientid -AccessToken $response.access_token -tenantid $tenantid -subscriptionid $subid}
				else {logwrite('801: Not connected to Azure. Exit.')
				exit 801}
				
		}
		catch{logwrite('800: Error connecting to Azure' +  $_.Exception.Message)
			exit 800}
	}
$accessToken="null"
$response="null"

# check if the VM exists in the hostpool, if so remove it

%{
	try{
	if (Get-AzWvdSessionHost -HostPoolName $hostpool -ResourceGroupName $RG -Name $hostname -ErrorAction SilentlyContinue) 

	{Remove-AzWvdSessionHost -ResourceGroupName $RG -HostPoolName $HostPool -Name $hostname -ErrorAction stop
	logwrite ($hostname + ' exists in the ' + $hostpool + ' host pool. Will remove so the VM may join again.')}
	}
	catch{Logwrite("900: " + $_.Exception.Message); exit 900}
}


# check if a valid Token exists to join the hostpool, if not generate one
	$now=(get-date).addhours(2)
	%{
        try {
		if ($now -gt ($WVDToken=Get-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool).ExpirationTime)
			{logwrite ('Generate new WVD Token to join WVD Hostpool: ' + $HostPool)
			$WVDToken=(New-AzWvdRegistrationInfo -ResourceGroupName $RG -HostPoolName $HostPool -ExpirationTime $((get-date).ToUniversalTime().AddHours(25).ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ'))).Token}
		Else {logwrite ('WVDToken exists for Hostpool: ' + $HostPool)
		$WVDToken=($WVDToken.Token}
        }
        catch{Logwrite("901: " + $_.Exception.Message); exit 901}
	}

# Start an AVDTurbo deployment
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
    catch {logwrite('900: Error with Turbo Deployment. ' + $_.Exception.Message); exit 902}



# Start a traditional deplyment with the RDAgent and RDBootloader
%{
    try {
		if ($Turbo -ne "AVDTurbo"){
			if ($WVDToken) {
  		    logwrite ('WVD Token to join WVD Hostpool: ' + $WVDToken)

    		### Install RDAgent
	    	logwrite('Install Remote Desktop Services Infrastructure Agent')
		    if (get-item -path C:\Source\RDagent.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=$WVDToken /qb /L*V RDAgent.log"}
			else{Logwrite("901: RDagent.msi is not available. Exit");exit 903}
		
    		### Install RDBoot
	    	logwrite ('Install Remote Desktop Agent Boot Loader')
		    if (get-item -path C:\Source\RDBoot.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"}
			else{Logwrite("902: RDBoot.msi is not available. Exit");exit 904}
		    LogWrite "Install RDS Agents completed."
			}
			Else {logwrite ('Could not retrieve a WVD Host Token for HostPool:' + $HostPool + '. Skip join WVD Hostpool')}
		}
	}
    catch {logwrite('903: Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 905}
}


# Wait for the SXS Network Agent and Geneva Agent to install
%{
	try{		    
		    LogWrite "Wait for the SXS Network Agent and Geneva Agent to install"
			$i=0
			do {start-sleep -Seconds 2;$i++;} until((($SXS=(get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -and (($Geneva=(get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -or $i -eq 50)
				if (($SXS -eq 'Installed' ) -and ($Geneva -eq 'Installed'))
				{LogWrite ("SXS Network Agent and Geneva Agent are installed")}
				Else {LogWrite ("1000: SXS Network Agent installed: " + $SXS + ". Geneva Agent installed: " + $Geneva + ". Check " + $env:ProgramFiles + "\Microsoft RDInfra. The MSI files don't download sometimes.")}
		}
    	catch {logwrite('1000: Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 1000}
}



# Logout of Azure
Disconnect-AzAccount
logwrite ('Disconnected from Azure')

exit 0

