# Chawn Limited 2025
# AVD-Join3.ps1
# Version 3.0
# Joins a session host to an Azure AVD Hostpool using the AVD-Join Custom Script Extension at startup or rebuild - For Generalized Images
# No Powershell Modules required

#### Parameters

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
$Logfile = "AVD-Join3.log"


Function LogWrite
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

LogWrite "Starting Up"


Function CheckDomain
{
	try {
		if ((gwmi win32_computersystem).partofdomain -eq $false) {logwrite('401: Device is not AD Domain joined. Exit.')
		exit 401}
		else {logwrite('Device is AD Domain joined.')}
		If (-not $HostPool) {LogWrite ($VMName + " deployment complete. Schedule a restart and exit.")
			Start-Process -FilePath "shutdown.exe" -ArgumentList "/r /t 5 /d p:0:0 /c 'AVDJoin'"
			exit 0}
	}
	catch {LogWrite ("402: " + $_.Exception.Message);exit 402}	
}


Function DownloadAgents
{
	try {
			if (get-item -path "C:\Program Files\Microsoft RDInfra" -ErrorAction SilentlyContinue)
			{logwrite('Remote Desktop Agents are already installed. Exit.');exit 500}
	}
	catch {logwrite('500: RDAgents are already installed' +  $_.Exception.Message); exit 500}

# Start the RDAGent downloads
	try {
		if ($HostPool) {				
			if (-not(get-item c:\source\RDAgent.msi -ErrorAction SilentlyContinue)) {
				LogWrite ("Download RDAgent")
				New-Item -Path C:\Source -ItemType Directory -Force
				$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDagent.msi -UseBasicParsing;
				LogWrite ("Downloaded RDAgent.msi")
			}	
			if (-not(get-item c:\source\RDBoot.msi -ErrorAction SilentlyContinue)) {
				LogWrite ("Download RDBoot")
				$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDBoot.msi -UseBasicParsing;
				LogWrite ("Downloaded RDBoot.msi")		
			}
		}
	}
	catch {LogWrite ("600: Failed to download RDAgents. " + $_.Exception.Message);exit 600}
}	


Function AzureLogon
{
	try {
		logwrite('Logon to Azure')
					
		if ($accessToken =(Invoke-RestMethod -Headers @{"Metadata"="true"} -Method GET -Uri "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2025-04-07&resource=$audience").access_token) {logwrite('Connected to Azure')}
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
			if ($response = (Invoke-RestMethod -Uri $ExchUri -Method POST -Body $body -ContentType "application/x-www-form-urlencoded").access_token) {logwrite('Connected to AzureX')
			$Global:Headers = @{
						"Authorization" = "Bearer $response"
						"Content-Type"  = "application/json"
						}		
			$accessToken="Nothing"
			$Response="Nothing"
			}
			else {logwrite('801: Not connected to AzureX. Exit.')
			exit 801}
			}
		catch {logwrite('800: Error connecting to Azure: ' +  $_.Exception.Message)
		exit 802}
}


Function CheckHostPool
{
	try {
		Logwrite "Remove Session Host from host pool if it exists"
		$deleteURI="https://management.azure.com/subscriptions/$subId/resourceGroups/$RG/providers/Microsoft.DesktopVirtualization/hostPools/$hostPool/sessionHosts/$HostName/?api-version=2024-04-03&force=true"
		Invoke-RestMethod -Uri $deleteURI -Method Delete -Headers $Headers
	}
		catch {Logwrite("900: Error removing Session Host from Host Pool " + $_.Exception.Message); exit 900}
}


Function CheckToken
{
	$now=(get-date).addhours(2)
    try {
		$TokenURI = "https://management.azure.com/subscriptions/$subid/resourceGroups/$rg/providers/Microsoft.DesktopVirtualization/hostPools/$hostPool/retrieveRegistrationToken?api-version=2024-04-03"
		if ($now -gt ($wvdtoken = Invoke-RestMethod -Uri $TokenURI -Method POST -Headers $headers).ExpirationTime)
			{logwrite ('Generate new WVD Token to join WVD Hostpool: ' + $HostPool)
			$NewTokenURI = "https://management.azure.com/subscriptions/$subId/resourceGroups/$RG/providers/Microsoft.DesktopVirtualization/hostPools/$hostPool/?api-version=2024-04-03"
			$tokenPayload = @{
				properties = @{
					registrationinfo = @{
					tokenType = "RegistrationToken"
					expirationTime = (Get-Date).AddHours(4).ToString("o")  
					registrationTokenOperation = "Update"
					resetToken="True"
					}
				}
			} | ConvertTo-Json -Depth 10
			$global:WVDToken=Invoke-RestMethod -Uri $getTokenUrl -Method Patch -Headers $Headers -Body $tokenPayload
			}
		Else {logwrite ('WVDToken exists for Hostpool: ' + $HostPool)
		$global:WVDToken=($WVDToken.Token)}
    }
    catch {Logwrite("901: " + $_.Exception.Message); exit 901}
}


#Get the ComputerName
$VMName=[System.Net.Dns]::GetHostByName($env:computerName).HostName

# Check for a Turbo deployment
%{
	try {
		if ($TURBO=((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -ErrorAction SilentlyContinue).RegistrationToken))
		{LogWrite ("Turbo Deployment started. " + $Turbo)}
		else {$TURBO='False';LogWrite ("Normal Deployment started. AVDTurbo: " + $TURBO)}
	}
	catch {LogWrite ("400: " + $_.Exception.Message);exit 400}
}


# check the device is domain joined
CheckDomain


# check if the RDAgent is already installed - normal deployment
%{
	if ($Turbo -eq "False")
		{
		DownloadAgents
		}
}


# get the DNS hostname of the VM
$hostname=[System.Net.Dns]::GetHostByName($env:computerName).HostName
logwrite('Hostname:' + $hostname)
logwrite('Hostpool:' + $hostpool)


# Logon to Azure
AzureLogon


# check if the VM exists in the hostpool, if so remove it
CheckHostPool


# check if a valid Token exists to join the hostpool, if not generate one
CheckToken


# Logout of Azure
$Headers="Nothing"
logwrite ('Disconnected from Azure')


# Start an AVDTurbo deployment
%{
	try {
		if ($Turbo -eq "AVDTurbo") {
			if ($WVDToken) {
			LogWrite ("Starting Turbo Deployment")
			Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -Value $WVDTOKEN -force
			Get-Service -Name RDAgentBootLoader | Set-Service -StartupType Automatic
			Get-Service -Name RDAgentBootLoader | start-service
			LogWrite ("Turbo Deployment Complete")
			$WVDToken="Null"
			}
		}
	}
    catch {logwrite('900: Error with Turbo Deployment. ' + $_.Exception.Message); exit 902}
}
# or
# Start a normal deployment with the RDAgent and RDBootloader
%{
    try {
		if ($Turbo -eq "False") {
			if ($WVDToken) {

    		### Install RDAgent
	    	logwrite('Install Remote Desktop Services Infrastructure Agent')
		    if (get-item -path C:\Source\RDagent.msi) {Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=$WVDToken /qb /L*V RDAgent.log"}
			else {Logwrite("901: RDagent.msi is not available. Exit");exit 903}
		
    		### Install RDBoot
	    	logwrite ('Install Remote Desktop Agent Boot Loader')
		    if (get-item -path C:\Source\RDBoot.msi) {Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"}
			else {Logwrite("902: RDBoot.msi is not available. Exit");exit 904}
		    LogWrite "Install RDS Agents completed."
			$WVDToken="Null"
			}
			Else {logwrite ('Could not retrieve a WVD Host Token for HostPool:' + $HostPool + '. Skip join WVD Hostpool')}
		}
	}
    catch {logwrite('903: Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 905}
}


# Wait for the SXS Network Agent and Geneva Agent to install
%{
	try {		    
		LogWrite "Wait for the SXS Network Agent and Geneva Agent to install"
		$i=0
		do {start-sleep -Seconds 1;$i++;} until((($SXS=(get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -and (($Geneva=(get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -or $i -eq 100)
			if (($SXS -eq 'Installed' ) -and ($Geneva -eq 'Installed'))
			{LogWrite ("SXS Network Agent and Geneva Agent are installed")}
			Else {LogWrite ("1000: SXS Network Agent installed: " + $SXS + ". Geneva Agent installed: " + $Geneva + ". Check " + $env:ProgramFiles + "\Microsoft RDInfra. The MSI files don't download sometimes.");exit 1000}
		}
    catch {logwrite('1000: Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 1000}
}


# Run post configuration script - AVD-Config
%{
	try {
	    LogWrite ("Check for AVD-Config")
	    If(Get-Item -Path "C:\Scripts\AVD-Config.ps1" -ErrorAction SilentlyContinue) {LogWrite ("Load AVD-Config");PowerShell.exe -ExecutionPolicy Bypass -NoProfile -NoLogo -File "C:\Scripts\AVD-Config.ps1";LogWrite ("AVD-Config Complete")}
		Else {LogWrite ("AVD-Config not present")}
	}
	catch {LogWrite ("Error running AVD-Config. " + $_.Exception.Message)}
}


# Finished
$global:LASTEXITCODE = 0
LogWrite ($VMName + " deployment complete. Schedule a restart and exit.")
Start-Process -FilePath "shutdown.exe" -ArgumentList "/soft /r /t 1 /d p:0:0 /c 'AVDJoin'"
