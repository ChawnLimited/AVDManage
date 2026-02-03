# Chawn Limited 2026
# AVD-Turbo5.ps1
# Version 5.0
# Rename the VM (if created from a Specialized Image.), optionally Join VM to Active Directory or Entra ID, and optionally install AVD Agents - For Specialized and Generalized Images, RIP AVDJoin
# No Powershell Modules required

#### Parameters

  param(
	[String]$Rename= "",				# Y|N rename the computer to the VM Name
	[String]$EntraJoin= "",				# Y|N Join Entra ID
	[String]$EntraDNSSuffix= "None",	# Optionally set a DNS Suffix or pass None
	[String]$ADDomain= "",				# Set the domain name in FQDN format
	[String]$OU= "",					# Set the Organisational Unit for the VM
	[String]$ADAdmin= "",				# Set the domain join user account
	[String]$ADAdminPW= "",				# Set the domain join user account password
	[String]$HostPool="",				# Set the WVD HostPool name
	[String]$RG="",						# Set the WVD HostPool Resource Group name
	[String]$ClientID = "",				# Set the AVDJoin Client ID
	[String]$SubjectID = "",			# Set the AVDManage Subject ID
	[String]$TenantID = "",				# Set the Azure Tenant ID
	[String]$SubID = "",				# Set the Azure Subscription ID
	[String]$Audience = "",
	[String]$issuer = "",
	[String]$ExchURI = "",
	[String]$Scope = "",
	[String]$cat = "",
	[String]$creds = ""
	)

#### End of Parameters

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-Turbo5.log"

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
			if (-not(get-item c:\source\RDAgent.msi)) {
				LogWrite ("Download RDAgent")
				New-Item -Path C:\Source -ItemType Directory -Force
				$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDagent.msi -UseBasicParsing;
				LogWrite ("Downloaded RDAgent.msi")
			}	
			if (-not(get-item c:\source\RDBoot.msi)) {
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
		catch {logwrite('802: Error connecting to Azure: ' +  $_.Exception.Message)
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
	$now=(get-date).addhours(1)
    try {
		$TokenURI = "https://management.azure.com/subscriptions/$subid/resourceGroups/$rg/providers/Microsoft.DesktopVirtualization/hostPools/$hostPool/retrieveRegistrationToken?api-version=2024-04-03"
		if ($now -gt ($wvdtoken = Invoke-RestMethod -Uri $TokenURI -Method POST -Headers $headers).ExpirationTime)
			{logwrite ('Generate new WVD Token to join WVD Hostpool: ' + $HostPool)
			$NewTokenURI = "https://management.azure.com/subscriptions/$subId/resourceGroups/$RG/providers/Microsoft.DesktopVirtualization/hostPools/$hostPool/?api-version=2024-04-03"
			$body = @{
				properties = @{
					registrationinfo = @{
					tokenType = "RegistrationToken"
					expirationTime = (Get-Date).AddHours(8).ToString("o")  
					registrationTokenOperation = "Update"
					resetToken="True"
					}
				}
			} | ConvertTo-Json -Depth 10
			$global:WVDToken=(Invoke-RestMethod -Uri $NewTokenURI -Method Patch -Headers $Headers -Body $body).properties.registrationInfo.token
			}
		Else {logwrite ('WVDToken exists for Hostpool: ' + $HostPool)
		$global:WVDToken=($WVDToken.Token)}
    }
    catch {Logwrite("901: " + $_.Exception.Message); exit 901}
}

#Uniform Scale Set with Generalized image will have the correct computerName
#Uniform Scale Set with Specialized image will require rename
#Flexible Scale Set with Generalized image will have the correct computerName
#Flexible Scale Set Specialized image will require rename
Function RenameComputer
{
	try {
		LogWrite "Rename Computer"
		do {
		start-sleep -seconds 1
		} until ($xml=(Get-ChildItem -Path C:\WindowsAzure\config -Filter *.xml | sort-object -Property LastAccessTime | select -Last 1))
		
		$xpath="/RDConfig/Instances/Instance"
		$vmname=(Select-Xml -Path $xml.fullname -XPath $xpath | Select-Object -ExpandProperty Node).id
		
		$vmname=$vmname.Substring(1).Replace('_','')
		$Global:AZVMNAME=$VMNAME
		
		if ($vmname -eq $env:computerName) {LogWrite ("Computer is already named " + $VMName + ".")}
		else {if ($NotDomainJoined) {
		LogWrite ("Renaming Computer to " + $VMName)
		Rename-Computer -NewName $VMName -Force | Out-File -FilePath $Logfile -Append
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "HostName" -Value $VMName -force
		Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName" -Name "ComputerName" -Value $VMName -force		
             }
		}
	}
	Catch {LogWrite ("300: " + $_.Exception.Message);exit 300}
}


Function JoinDomain
{
	try {
			LogWrite ("Join Domain. Create Credentials.")
			$ADDomainCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
			UserName = $ADAdmin
			Password = (ConvertTo-SecureString -String $ADAdminPW -AsPlainText -Force)[0]})
			LogWrite ("Join Domain: " + $ADDomain)
			Add-Computer -DomainName $ADDomain -OUPath $ou -Credential $ADDomainCred -Options JoinWithNewName,AccountCreate -Force
			LogWrite ($AZVMName + " has joined the " + $ADDomain + " domain")
	}
	catch {LogWrite ("301: " + $_.Exception.Message);exit 301}
}

Function JoinEntraID
{
	try {
		LogWrite ("Join Entra ID using VM System credentials")
		if ($EntraDNSSuffix -ne "None") {Set-DnsClientGlobalSetting -SuffixSearchList @($EntraDNSSuffix)}
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion" -Name "CDJ" -Force -ErrorAction SilentlyContinue
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ" -Name "AzureVmComputeMetadataEndpoint" -Value "http://169.254.169.254/metadata/instance/compute" -force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ" -Name "AzureVmTenantIdEndpoint" -Value "http://169.254.169.254/metadata/identity/info" -force	
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CDJ" -Name "AzureVmMsiTokenEndpoint" -Value "http://169.254.169.254/metadata/identity/oauth2/token" -force
		$proc=Start-Process dsregcmd -ArgumentList "/AzureSecureVMJoin /debug" -Passthru -Wait
		if ($Proc.ExitCode -ne 0) {LogWrite ("405: Exit - Failed to join Entra ID: " + $Proc.ExitCode);exit 405}
		else {LogWrite ("Successfully joined Entra ID: " + $Proc.ExitCode)}
	}
	catch {LogWrite ("406: Exit - Failed to join Entra ID: " + $_.Exception.Message);exit 406}
}



# Check if Vm is AD domain joined
$NotDomainJoined=((gwmi win32_computersystem).partofdomain -eq $false)

# Rename Computer (Specialized Images only)
%{
	if ($Rename -eq "Y") {Logwrite ("Rename VM");RenameComputer;}
	else {Logwrite ("VMName: " + $ENV:ComputerName);$Global:AZVMNAME=$ENV:ComputerName;}
}

# Join Active Directory Domain
%{
	if ($ADDomain){
		if($NotDomainJoined) {JoinDomain;CheckDomain;}
		else{Logwrite ($AZVMName + " is already domain joined.")}
	}
}

# Join Entra ID
%{
	if ($EntraJoin -eq "Y") {JoinEntraID}
}

# Check for an AVD deployment
%{
	if ($hostpool) {LogWrite ("Join AVD HostPool: " + $HostPool)}
	else {LogWrite ($AZVMName + " deployment complete. Schedule a restart and exit.")
	Start-Process -FilePath "shutdown.exe" -ArgumentList "/r /t 5 /d p:0:0 /c 'AVDTurbo'"
	exit 0}
}





# Check for a Turbo deployment
%{
	try {
		if ($TURBO=((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -ErrorAction SilentlyContinue).RegistrationToken))
		{LogWrite ("Turbo Deployment started. " + $Turbo)}
		else {$TURBO='False';LogWrite ("Normal Deployment started. AVDTurbo: " + $TURBO)}
	}
	catch {LogWrite ("400: " + $_.Exception.Message);exit 400}
}


# check if the RDAgent is already installed - normal deployment
%{
	if ($Turbo -eq "False")
		{
		DownloadAgents
		}
}


# get the DNS hostname of the VM
%{
	if ($ADDomain) {$Global:hostname=$AZVMName + "." + $ADDomain}
	else {$Global:hostname=$AZVMName}
	logwrite('Hostname:' + $hostname)
	logwrite('Hostpool:' + $hostpool)
}

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
    catch {logwrite('902: Error with Turbo Deployment. ' + $_.Exception.Message); exit 902}
}
#or
# Start a normal deployment with the RDAgent and RDBootloader
%{
    try {
		if ($Turbo -eq "False") {
			if ($WVDToken) {
  		    
    		### Install RDAgent
	    	logwrite('Install Remote Desktop Services Infrastructure Agent')
		    if (get-item -path C:\Source\RDagent.msi) {Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=$WVDToken /qb /L*V RDAgent.log"}
			else {Logwrite("903: RDagent.msi is not available. Exit");exit 903}
		
    		### Install RDBoot
	    	logwrite ('Install Remote Desktop Agent Boot Loader')
		    if (get-item -path C:\Source\RDBoot.msi) {Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"}
			else {Logwrite("904: RDBoot.msi is not available. Exit");exit 904}
		    LogWrite "Install RDS Agents completed."
			$WVDToken="Null"
			}
			Else {logwrite ('Could not retrieve a WVD Host Token for HostPool:' + $HostPool + '. Skip join WVD Hostpool')}
		}
	}
    catch {logwrite('905: Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 905}
}


# Wait for the SXS Network Agent and Geneva Agent to install
%{
	try {		    
		LogWrite "Wait for the SXS Network Agent and Geneva Agent to install"
		$i=0
		do {start-sleep -Seconds 2;$i++;} until((($SXS=(get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -and (($Geneva=(get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -or $i -eq 100)
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
LogWrite ($AZVMName + " deployment complete. Schedule a restart and exit.")
Start-Process -FilePath "shutdown.exe" -ArgumentList "/r /t 5 /d p:0:0 /c 'AVDTurbo'"
