# Chawn Limited 2026
# AVD-Turbo5.ps1
# Version 5.0
# Rename the VM (if created from a Specialized Image), optionally Join VM to Active Directory or Entra ID, and optionally install AVD Agents and join AVD HOst Pool - For Specialized and Generalized Images, RIP AVDJoin
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


# Specialized images will require rename
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


Function CheckEntraID
{
	try {
		$dsregStatus = dsregcmd /status 2>$null
		if (-not $dsregStatus) {
			logwrite ("EntraJoined: NO")
		}
		# Parse AzureAdJoined and DomainJoined values
		$Global:IsEntraJoined = ($dsregStatus | Select-String "AzureAdJoined\s*:\s*(YES|NO)").Matches.Groups[1].Value
		logwrite ("EntraJoined: " + $IsEntraJoined)
	} 
catch {}
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


# Check if VM is AD domain joined
$NotDomainJoined=((gwmi win32_computersystem).partofdomain -eq $false)

# Check if VM is Entra Joined
CheckEntraID


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
	if ($IsEntraJoined -eq "NO"){if ($EntraJoin -eq "Y") {JoinEntraID}}
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
	logwrite('Hostname: ' + $hostname)
	logwrite('Hostpool: ' + $hostpool)
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

# SIG # Begin signature block
# MIInXAYJKoZIhvcNAQcCoIInTTCCJ0kCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC8Nl9XmTDXEoLG
# lAqGhbsMbf7NSpCoyTQfwkpC0nEw66CCIgswggMwMIICtqADAgECAhA3dENPnrQO
# Ih+SNsofLycXMAoGCCqGSM49BAMDMFYxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9T
# ZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENvZGUgU2ln
# bmluZyBSb290IEU0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5NTlaMFcx
# CzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMT
# JVNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBFViBFMzYwWTATBgcqhkjO
# PQIBBggqhkjOPQMBBwNCAATeYxX2c1WJigfhpKs/AWOltt5cfDakxup7PAMZvjm4
# RlCveoj0eC3SThHbqjm6l9fMm3TcXx5+7StE0SzjIMPPo4IBYzCCAV8wHwYDVR0j
# BBgwFoAUz30soJB6mB3dtl6FwuDaFXHS5V4wHQYDVR0OBBYEFBp0pDjXubYOs1v6
# 3F6uP7bwcz2IMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMG
# A1UdJQQMMAoGCCsGAQUFBwMDMBoGA1UdIAQTMBEwBgYEVR0gADAHBgVngQwBAzBL
# BgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29Q
# dWJsaWNDb2RlU2lnbmluZ1Jvb3RFNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBGBggr
# BgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljQ29k
# ZVNpZ25pbmdSb290RTQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2Vj
# dGlnby5jb20wCgYIKoZIzj0EAwMDaAAwZQIxAKB6vcvgJjHZbsfIfO8toCc1571B
# Wo7A6sFhnLKpcREu1mDUOxyx2hhnaCzMRbfNpQIwBou1zB2hXfkAOmu7b3AKFLuQ
# WBe3n30THbvCYv764kIm2HrFivefIXZvZgkMBq07MIIDwjCCAqqgAwIBAgIRANWz
# YAKJWaJ/hGXJ5rGNusswDQYJKoZIhvcNAQEMBQAwezELMAkGA1UEBhMCR0IxGzAZ
# BgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgG
# A1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0
# ZSBTZXJ2aWNlczAeFw0yMzAyMjgwMDAwMDBaFw0yODEyMzEyMzU5NTlaMFYxCzAJ
# BgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNl
# Y3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBSb290IEU0NjB2MBAGByqGSM49AgEG
# BSuBBAAiA2IABAgygQMfjzuib4FHjOV7ubrBabJbScAouRRYbyQzzlCbc9k7wWg5
# nHphzlzSIkdEq4CFqeWVrKquZliGVqe4g4PMtNEOqVH4S2c5f4y5tjloNI8ZSrqO
# IetCuKxWnQncB6OCARIwggEOMB8GA1UdIwQYMBaAFKARCiM+lvEH7OKvKe+CpX/Q
# MKS0MB0GA1UdDgQWBBTPfSygkHqYHd22XoXC4NoVcdLlXjAOBgNVHQ8BAf8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDAzAbBgNVHSAE
# FDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9j
# cmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMDQGCCsG
# AQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuY29tb2RvY2EuY29t
# MA0GCSqGSIb3DQEBDAUAA4IBAQA3P95PqrMZSfh702kbeiCCoqPEYZFEp6eMi/N5
# jTpv58evyW2wD6VyKLfU+0DsadOR5QLRsdU02tbzprhPwc6hJGIGm54YfQ+E6XiV
# yeDZq31799ITQ0PmTveZdPdwfxxRoLUW7vaMmpErxQTMt/+j9XUAC74+Jo8bI2TN
# KyWwMg7msc80yWN9zgkWH7gRuKZGSWw02lj4XMCKE86mKDjiDEvZYzGG0hh/InEg
# V9O8WOTPxi7XOX5mGaC44I8WZFbxVtpwBt71wlcmqNP58ahN7/VTJZgKiuhcvjqc
# Azr0Hfp+tlJBmiF4KFosnIpz6wM5+LTTFsE7JcIl+5kojtHfMIID0zCCA3qgAwIB
# AgIQPGiW/JCi/QY+DN1xuzACNzAKBggqhkjOPQQDAjBXMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgQ0EgRVYgRTM2MB4XDTI1MDgwNzAwMDAwMFoXDTI2MDgw
# NzIzNTk1OVowgZsxETAPBgNVBAUTCDA5MjY3MjU2MRMwEQYLKwYBBAGCNzwCAQMT
# AkdCMR0wGwYDVQQPExRQcml2YXRlIE9yZ2FuaXphdGlvbjELMAkGA1UEBhMCR0Ix
# FTATBgNVBAgMDFdhcndpY2tzaGlyZTEWMBQGA1UECgwNQ2hhd24gTGltaXRlZDEW
# MBQGA1UEAwwNQ2hhd24gTGltaXRlZDB2MBAGByqGSM49AgEGBSuBBAAiA2IABL40
# IgorIEKAAf1TnXLAxGo+wdo/0M7w+PSvfo68r1s8d780ILfHw+lO7EaUTGv+iMQF
# HKeWO7293LR5qW88B7qnd+IqeWG7STTqHLqlzyLra1fuuhpM2Sx0hTZDRPsAxaOC
# AcQwggHAMB8GA1UdIwQYMBaAFBp0pDjXubYOs1v63F6uP7bwcz2IMB0GA1UdDgQW
# BBQ5amzo6Z9aJwpZfE2eDE9ofrEdpTAOBgNVHQ8BAf8EBAMCB4AwDAYDVR0TAQH/
# BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzBJBgNVHSAEQjBAMDUGDCsGAQQBsjEB
# AgEGATAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAHBgVn
# gQwBAzBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1Nl
# Y3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBRVZFMzYuY3JsMHsGCCsGAQUFBwEBBG8w
# bTBGBggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVi
# bGljQ29kZVNpZ25pbmdDQUVWRTM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29j
# c3Auc2VjdGlnby5jb20wNgYDVR0RBC8wLaAbBggrBgEFBQcIA6APMA0MC0dCLTA5
# MjY3MjU2gQ5pbmZvQGNoYXduLmNvbTAKBggqhkjOPQQDAgNHADBEAiB7al/nqmfr
# GdHTa9qo681p5YHo8nK76jvz0NevOhnPKwIgS7v+Wh3DXYWe1FiHs3+cgS+pgqm9
# XmkjxOzb3w86CncwggQyMIIDGqADAgECAgEBMA0GCSqGSIb3DQEBBQUAMHsxCzAJ
# BgNVBAYTAkdCMRswGQYDVQQIDBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcM
# B1NhbGZvcmQxGjAYBgNVBAoMEUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhB
# QUEgQ2VydGlmaWNhdGUgU2VydmljZXMwHhcNMDQwMTAxMDAwMDAwWhcNMjgxMjMx
# MjM1OTU5WjB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVz
# dGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRl
# ZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMIIBIjANBgkqhkiG
# 9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvkCd9G7h6naHHE1FRI6+RsiDBp3BKv4YH47k
# Avrzq11QihYxC5oG0MVwIs1JLVRjzLZuaEYLU+rLTCTAvHJO6vEVrvRUmhIKw3qy
# M2Di2olV8yJY897cz++DhqKMlE+faPKYkEaEJ8d2v+PMNSyLXgdkZYLASLCokflh
# n3YgUKiRx2a163hiA1bwihoT6jGjHqCZ/Tj29icyWG8H9Wu4+xQrr7eqzNZjX3OM
# 2gWZqDioyxd4NlGs6Z70eDqNzw/ZQuKYDKsvnw4B3u+fmUnxLd+sdE0bmLVHxeUp
# 0fmQGMdinL6DxyZ7Poolx8DdneY1aBAgnY/Y3tLDhJwNXugvyQIDAQABo4HAMIG9
# MB0GA1UdDgQWBBSgEQojPpbxB+zirynvgqV/0DCktDAOBgNVHQ8BAf8EBAMCAQYw
# DwYDVR0TAQH/BAUwAwEB/zB7BgNVHR8EdDByMDigNqA0hjJodHRwOi8vY3JsLmNv
# bW9kb2NhLmNvbS9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDA2oDSgMoYwaHR0
# cDovL2NybC5jb21vZG8ubmV0L0FBQUNlcnRpZmljYXRlU2VydmljZXMuY3JsMA0G
# CSqGSIb3DQEBBQUAA4IBAQAIVvwC8Jvo/6T61nvGRIDOT8TF9gBYzKa2vBRJaAR2
# 6ObuXewCD2DWjVAYTyZOAePmsKXuv7x0VEG//fwSuMdPWvSJYAV/YLcFSvP28cK/
# xLl0hrYtfWvM0vNG3S/G4GrDwzQDLH2W3VrCDqcKmcEFi6sML/NcOs9sN1UJh95T
# QGxY7/y2q2VuBPYb3DzgWhXGntnxWUgwIWUDbOzpIXPsmwOh4DetoBUYj/q6As6n
# LKkQEyzU5QgmqyKXYPiQXnTUoppTvfKpaOCibsLXbLGjD56/62jnVvKu8uMrODoJ
# gbVrhde+Le0/GreyY+L1YiyC1GoAQVDxOYOflek2lphuMIIGFDCCA/ygAwIBAgIQ
# eiOu2lNplg+RyD5c9MfjPzANBgkqhkiG9w0BAQwFADBXMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1Ymxp
# YyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMy
# MTIzNTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYw
# ggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDNmNhDQatugivs9jN+JjTk
# iYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc
# 5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiYEpc81KnBkAWgsaXnLURoYZzksHIzzCNx
# tIXnb9njZholGw9djnjkTdAA83abEOHQ4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvfl
# xNMCOwkCnzlH4oCw5+4v1nssWeN1y4+RlaOywwRMUi54fr2vFsU5QPrgb6tSjvEU
# h1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8hJiTWw9jiCKv31pcAaeijS9fc6R7DgyyL
# IGflmdQMwrNRxCulVq8ZpysiSYNi79tw5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+
# HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrcUWhdFczf8O+pDiyGhVYX+bDDP3GhGS7T
# mKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyYVr15OApZYK8CAwEAAaOCAVwwggFYMB8G
# A1UdIwQYMBaAFPZ3at0//QET/xahbIICL9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqi
# YUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIB
# ADATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwTAYDVR0f
# BEUwQzBBoD+gPYY7aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# VGltZVN0YW1waW5nUm9vdFI0Ni5jcmwwfAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUF
# BzAChjtodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3Rh
# bXBpbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGln
# by5jb20wDQYJKoZIhvcNAQEMBQADggIBABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2Im
# IfZVVGnGoUaGdltoX4hDskBMZx5NY5L6SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHW
# zpwVkFJ+996jKKAXyIIaUf5JVKjccev3w16mNIUlNTkpJEor7edVJZiRJVCAmWAa
# Hcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQI
# kms6+yslCRqNXPjEnBnxuUB1fm6bPAV+Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQV
# IMLv5koklInHvyaf6vATJP4DfPtKzSBPkKlOtyaFTAjD2Nu+di5hErEVVaMqSVbf
# Pzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHaC4ACMRCgXjYfQEDtYEK54dUwPJXV7icz
# 0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyPDbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC2
# 7pIOx6TYvyqiYbntinmpOqh/QPAnhDgexKG9GX/n1PggkGi9HCapZp8fRwg8Rftw
# S21Ln61euBG0yONM6noD2XQPrFwpm3GcuqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZs
# wbaiie5fd/W2ygcto78XCSPfFWveUOSZ5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1
# EGvxOb1cnn0CMIIGYjCCBMqgAwIBAgIRAKQpO24e3denNAiHrXpOtyQwDQYJKoZI
# hvcNAQEMBQAwVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYw
# HhcNMjUwMzI3MDAwMDAwWhcNMzYwMzIxMjM1OTU5WjByMQswCQYDVQQGEwJHQjEX
# MBUGA1UECBMOV2VzdCBZb3Jrc2hpcmUxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEwMC4GA1UEAxMnU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBTaWduZXIg
# UjM2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA04SV9G6kU3jyPRBL
# eBIHPNyUgVNnYayfsGOyYEXrn3+SkDYTLs1crcw/ol2swE1TzB2aR/5JIjKNf75Q
# Bha2Ddj+4NEPKDxHEd4dEn7RTWMcTIfm492TW22I8LfH+A7Ehz0/safc6BbsNBzj
# HTt7FngNfhfJoYOrkugSaT8F0IzUh6VUwoHdYDpiln9dh0n0m545d5A5tJD92iFA
# IbKHQWGbCQNYplqpAFasHBn77OqW37P9BhOASdmjp3IijYiFdcA0WQIe60vzvrk0
# HG+iVcwVZjz+t5OcXGTcxqOAzk1frDNZ1aw8nFhGEvG0ktJQknnJZE3D40GofV7O
# 8WzgaAnZmoUn4PCpvH36vD4XaAF2CjiPsJWiY/j2xLsJuqx3JtuI4akH0MmGzlBU
# ylhXvdNVXcjAuIEcEQKtOBR9lU4wXQpISrbOT8ux+96GzBq8TdbhoFcmYaOBZKlw
# PP7pOp5Mzx/UMhyBA93PQhiCdPfIVOCINsUY4U23p4KJ3F1HqP3H6Slw3lHACnLi
# lGETXRg5X/Fp8G8qlG5Y+M49ZEGUp2bneRLZoyHTyynHvFISpefhBCV0KdRZHPcu
# SL5OAGWnBjAlRtHvsMBrI3AAA0Tu1oGvPa/4yeeiAyu+9y3SLC98gDVbySnXnkuj
# jhIh+oaatsk/oyf5R2vcxHahajMCAwEAAaOCAY4wggGKMB8GA1UdIwQYMBaAFF9Y
# 7UwxeqJhQo1SgLqzYZcZojKbMB0GA1UdDgQWBBSIYYyhKjdkgShgoZsx0Iz9LALO
# TzAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggr
# BgEFBQcDCDBKBgNVHSAEQzBBMDUGDCsGAQQBsjEBAgEDCDAlMCMGCCsGAQUFBwIB
# FhdodHRwczovL3NlY3RpZ28uY29tL0NQUzAIBgZngQwBBAIwSgYDVR0fBEMwQTA/
# oD2gO4Y5aHR0cDovL2NybC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0
# YW1waW5nQ0FSMzYuY3JsMHoGCCsGAQUFBwEBBG4wbDBFBggrBgEFBQcwAoY5aHR0
# cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nQ0FS
# MzYuY3J0MCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdvLmNvbTANBgkq
# hkiG9w0BAQwFAAOCAYEAAoE+pIZyUSH5ZakuPVKK4eWbzEsTRJOEjbIu6r7vmzXX
# LpJx4FyGmcqnFZoa1dzx3JrUCrdG5b//LfAxOGy9Ph9JtrYChJaVHrusDh9NgYwi
# GDOhyyJ2zRy3+kdqhwtUlLCdNjFjakTSE+hkC9F5ty1uxOoQ2ZkfI5WM4WXA3ZHc
# NHB4V42zi7Jk3ktEnkSdViVxM6rduXW0jmmiu71ZpBFZDh7Kdens+PQXPgMqvzod
# gQJEkxaION5XRCoBxAwWwiMm2thPDuZTzWp/gUFzi7izCmEt4pE3Kf0MOt3ccgwn
# 4Kl2FIcQaV55nkjv1gODcHcD9+ZVjYZoyKTVWb4VqMQy/j8Q3aaYd/jOQ66Fhk3N
# Wbg2tYl5jhQCuIsE55Vg4N0DUbEWvXJxtxQQaVR5xzhEI+BjJKzh3TQ026JxHhr2
# fuJ0mV68AluFr9qshgwS5SpN5FFtaSEnAwqZv3IS+mlG50rK7W3qXbWwi4hmpylU
# fygtYLEdLQukNEX1jiOKMIIGgjCCBGqgAwIBAgIQNsKwvXwbOuejs902y8l1aDAN
# BgkqhkiG9w0BAQwFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCk5ldyBKZXJz
# ZXkxFDASBgNVBAcTC0plcnNleSBDaXR5MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNU
# IE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJUcnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBB
# dXRob3JpdHkwHhcNMjEwMzIyMDAwMDAwWhcNMzgwMTE4MjM1OTU5WjBXMQswCQYD
# VQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0
# aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2MIICIjANBgkqhkiG9w0B
# AQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVnnR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0
# QUCBdxSZqdTkdizICFNeINCSJS+lV1ipnW5ihkQyC0cRLWXUJzodqpnMRs46npiJ
# PHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE0awqKggE/LkYw3sqaBia67h/3awoqNvG
# qiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3kpqstbl3vcTdOGhtKShvZIvjwulRH87r
# bukNyHGWX5tNK/WABKf+Gnoi4cmisS7oSimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+
# Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hsokDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1
# mNzMyptRwsXKrop06m7NUNHdlTDEMovXAIDGAvYynPt5lutv8lZeI5w3MOlCybAZ
# DpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP0KWZwZIXbYsTIlg1YIetCpi5s14qiXOp
# RsKqFKqav9R1R5vj3NgevsAsvxsAnI8Oa5s2oy25qhsoBIGo/zi6GpxFj+mOdh35
# Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA911cRxgY5SJYubvjay3nSMbBPPFsyl6m
# Y4/WYucmyS9lo3l7jk27MAe145GWxK4O3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQv
# r9sCAwEAAaOCARYwggESMB8GA1UdIwQYMBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bL
# MB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyCAi/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYw
# DwYDVR0TAQH/BAUwAwEB/zATBgNVHSUEDDAKBggrBgEFBQcDCDARBgNVHSAECjAI
# MAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOgQYY/aHR0cDovL2NybC51c2VydHJ1c3Qu
# Y29tL1VTRVJUcnVzdFJTQUNlcnRpZmljYXRpb25BdXRob3JpdHkuY3JsMDUGCCsG
# AQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZaHR0cDovL29jc3AudXNlcnRydXN0LmNv
# bTANBgkqhkiG9w0BAQwFAAOCAgEADr5lQe1oRLjlocXUEYfktzsljOt+2sgXke3Y
# 8UPEooU5y39rAARaAdAxUeiX1ktLJ3+lgxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3w
# z/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAWnvdYOdEMq1W61KE9JlBkB20XBee6JaXx
# 4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtrQdRMRi/fInV/AobE8Gw/8yBMQKKaHt5e
# ia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8OMeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGu
# r18ut97wgGwDiGinCwKPyFO7ApcmVJOtlw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4
# qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduPnmFzbSN/G8reZCL4fvGlvPFk4Uab/JVC
# Smj59+/mB2Gn6G/UYOy8k60mKcmaAZsEVkhOFuoj4we8CYyaR9vd9PGZKSinaZIk
# vVjbH/3nlLb0a7SBIkiRzfPfS9T+JesylbHa1LtRV9U/7m0q7Ma2CQ/t392ioOss
# XW7oKLdOmMBl14suVFBmbzrt5V5cQPnwtd3UOTpS9oCG+ZZheiIvPgkDmA8FzPsn
# fXW5qHELB43ET7HHFHeRPRYrMBKjkb8/IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg
# 8pZVPT8xggSnMIIEowIBATBrMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0
# aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIENvZGUgU2lnbmlu
# ZyBDQSBFViBFMzYCEDxolvyQov0GPgzdcbswAjcwDQYJYIZIAWUDBAIBBQCggYQw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQx
# IgQgi367ZOyF5zbw+9E26iWW0scvvNuMwBbs2kHxs2pnbuAwCwYHKoZIzj0CAQUA
# BGcwZQIwZikcipZfnRY1/ncPppZbkW8gvSo97xnkW/pQx05dBzdPvkBSzF8VxLhX
# BKrlogH2AjEAwfSbyvUGhc+QW0x1Dk0MrAPZw8yc5yR1rwen/VvJvxswqhI4wBBl
# pIz9/DIRA7n6oYIDIzCCAx8GCSqGSIb3DQEJBjGCAxAwggMMAgEBMGowVTELMAkG
# A1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2Vj
# dGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSMzYCEQCkKTtuHt3XpzQIh616
# TrckMA0GCWCGSAFlAwQCAgUAoHkwGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAc
# BgkqhkiG9w0BCQUxDxcNMjYwMjE1MjEzMDI2WjA/BgkqhkiG9w0BCQQxMgQwWY4r
# 6owsJU8bnU2cGhcMBJyv+NwWuujD3UQLxKmGtW5dX2upLwTM958C2V9r1y61MA0G
# CSqGSIb3DQEBAQUABIICAADRpEmcbro3Ei1ciS3/PZ8vuz482VkbKgB6sWRTsWLb
# sPcREnLHx/5wSNwqphsv5ZlaLs99DbfGRwFB6HfqljDj6w9JaqA3RV1Lf5Idslsi
# y99EGP+qGq33Z3rJLX8VQjElNxbpcLHwT+cfupP1miSfbGKvkJdFxtBRdlM4+BGS
# qc9YO7GjaYvjyrOVO6Ip4wtGyjNuxLdyqDrIulubB14JJTTZiUAsicsfoqm7sCdu
# 85Vpm5vA9ux4B+XPTNs3EX3PyX33KrWa99BzKmBXH3st5TAcdCmSrUagIQULojq6
# ysF7ueJOmPTXI6dOX83DItOSrkHn1/0wD9r23agU4Qe8I4vkpG0nB/wpWZgtdbeN
# 76esVRFW5bD7b/u+C5vkrAlSCoZTTVZo/MBsKBJRNFePycuJK+mef+F4PMYCOx74
# lkcF9920NC23UjYAaIrtNvNdwAvpbD1M26GHfOSuEAdtp3z5VVQWqIjbrTCwmP2m
# +dTsqeUCb+/YBDwKZT16LFMZcrgaTxETeb+vMJ1/Kk0wdOXRruYX1kCPkF7QOIrn
# gQ/7vTiog0kE3wytcr5jC/VbxfeqQoFDYcn6LRcikeZei2/Vrm+8/N90zqP0y4jW
# KusA1Ne54PDA5/azgD69kFc7a/Xxsx6kDrQ3FReABAHDMjGc3Pp6tqv9Ptigk5s6
# SIG # End signature block
