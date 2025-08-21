# Chawn Limited 2025
# AVDJoin.ps1
# Version 2.0
# Joins a session host to an Azure AVD Hostpool using the AVD-Join Custom Script Extension at startup or rebuild

  #Parameters
  param(
	[String]$HostPool="",
	[String]$RG="",
	[String]$ClientID = "",
	[String]$ClientSecret = "",
	[String]$TenantID = "",
	[String]$SubID = ""
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
		{$TURBO='True';LogWrite ("Turbo Deployment started.")}
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
	if ($Turbo -eq "False") {
		if (get-item -path "C:\Program Files\Microsoft RDInfra" -ErrorAction SilentlyContinue)
		{logwrite('Remote Desktop Agents are already installed. Exit.');exit 1}
	}
}




# Check AZ Modules are present
%{
	try {
		if ($Turbo -eq "False") {
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
	if ($Turbo -eq "False") {
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



### Create the AVD Agent PSCredential
$AVDCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
    UserName = $ClientId
    Password = (ConvertTo-SecureString -String $ClientSecret -AsPlainText -Force)[0]})
logwrite('Created PSCreds for Azure')


Disable-AzContextAutosave -Scope Process

# Logon to Azure
%{
	try {Connect-AzAccount -ServicePrincipal -TenantId $TenantId -Subscription $subid -Credential $AVDCred
	if ((Get-AZAccessToken -ErrorAction SilentlyContinue).count -ne 0) {logwrite('Connected to Azure')}
	else {logwrite('Not connected to Azure. Exit.')
	exit 4}
	}
	catch{"Failed to connect to Azure. " + $_.Exception.Message}
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
		if ($Turbo -eq "True") {
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
		if ($Turbo -eq "False"){
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
			do {start-sleep -Seconds 1;$i++;} until(((get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed') -and ((get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed') -or $i -eq 20)
		    if (((get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed') -and ((get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed'))
			{LogWrite ("SXS Network Agent and Geneva Agent are installed")}
			Else {LogWrite ("SXS Network Agent or Geneva Agent installation failed");LogWrite ("SXS Network Agent: " + ((get-package -name "*SXS*Network*" -ErrorAction SilentlyContinue).Status -eq 'Installed'));LogWrite ("Geneva Agent: " + ((get-package -name "*Geneva*" -ErrorAction SilentlyContinue).Status -eq 'Installed'));LogWrite("Check " + $env:ProgramFiles + "\Microsoft RDInfra. The MSI files don't download sometimes.")}
		}
    catch {logwrite('Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 8}

# Logout of Azure
Disconnect-AzAccount
logwrite ('Disconnected from Azure')

exit 0


# SIG # Begin signature block
# MIInlQYJKoZIhvcNAQcCoIInhjCCJ4ICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAHJzBbwxXiZiUV
# FSPlZObBInC1lbGCwjEXgL9WbduodKCCIkEwggMwMIICtqADAgECAhA3dENPnrQO
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
# gbVrhde+Le0/GreyY+L1YiyC1GoAQVDxOYOflek2lphuMIIFjTCCBHWgAwIBAgIQ
# DpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0BAQwFADBlMQswCQYDVQQGEwJVUzEV
# MBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29t
# MSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMjIwODAx
# MDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQD
# ExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz7MKnJS7JIT3yithZwuEppz1Yq3aa
# za57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS5F/WBTxSD1Ifxp4VpX6+n6lXFllV
# cq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7bXHiLQwb7iDVySAdYyktzuxeTsiT
# +CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfISKhmV1efVFiODCu3T6cw2Vbuyntd
# 463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jHtrHEtWoYOAMQjdjUN6QuBX2I9YI+
# EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14Ztk6MUSaM0C/CNdaSaTC5qmgZ92k
# J7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2h4mXaXpI8OCiEhtmmnTK3kse5w5j
# rubU75KSOp493ADkRSWJtppEGSt+wJS00mFt6zPZxd9LBADMfRyVw4/3IbKyEbe7
# f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPRiQfhvbfmQ6QYuKZ3AeEPlAwhHbJU
# KSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ERElvlEFDrMcXKchYiCd98THU/Y+wh
# X8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4KJpn15GkvmB0t9dmpsh3lGwIDAQAB
# o4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU7NfjgtJxXWRM3y5n
# P+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8wDgYDVR0P
# AQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAChjdodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURSb290Q0EuY3J0MEUGA1UdHwQ+MDww
# OqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJ
# RFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBDAUAA4IB
# AQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyhhyzshV6pGrsi+IcaaVQi7aSId229
# GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO0Cre+i1Wz/n096wwepqLsl7Uz9FD
# RJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo8L8vC6bp8jQ87PcDx4eo0kxAGTVG
# amlUsLihVo7spNU96LHc/RzY9HdaXFSMb++hUD38dglohJ9vytsgjTVgHAIDyyCw
# rFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5xaiNrIv8SuFQtJ37YOtnwtoeW/VvR
# XKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJygAwIBAgIQDcesVwX/IZkuQEMiDDpJ
# hjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNl
# cnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdp
# Q2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUwNTA3MDAwMDAwWhcNMzgwMTE0MjM1
# OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYg
# U0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
# tHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2NDZS1mZaDLFTtQ2oRjzUXMmxCqvkb
# sDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qftJYJaDNs1+JH7Z+QdSKWM06qchUP+
# AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0trj6Ao+xh/AS7sQRuQL37QXbDhAkt
# VJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX0M980EpLtlrNyHw0Xm+nt5pnYJU3
# Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEpNVWC2ZQ8BbfnFRQVESYOszFI2Wv8
# 2wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coWJ+KdPvMvaB0WkE/2qHxJ0ucS638Z
# xqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdkDjHkccpL6uoG8pbF0LJAQQZxst7V
# vwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0XbQcd8hjj/q8d6ylgxCZSKi17yVp2N
# L+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sfuZDKiDEb1AQ8es9Xr/u6bDTnYCTK
# IsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7vQTCBZtVFJfVZ3j7OgWmnhFr4yUoz
# ZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwbtmsgY1MCAwEAAaOCAV0wggFZMBIG
# A1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFO9vU0rp5AZ8esrikFb2L9RJ7MtO
# MB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIB
# hjATBgNVHSUEDDAKBggrBgEFBQcDCDB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQw
# QwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZI
# AYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAXzvsWgBz+Bz0RdnEwvb4LyLU0pn/N
# 0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQa8j00DNqhCT3t+s8G0iP5kvN2n7J
# d2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd6ywFLerycvZTAz40y8S4F3/a+Z1j
# EMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FHaoq2e26MHvVY9gCDA/JYsq7pGdog
# P8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOczgj5kjatVB+NdADVZKON/gnZruMv
# NYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFbqrXuvTPSegOOzr4EWj7PtspIHBld
# NE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z4y25xUbI7GIN/TpVfHIqQ6Ku/qjT
# Y6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT70kZjE4YtL8Pbzg0c1ugMZyZZd/B
# dHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43esaUeqGkH/wyW4N7OigizwJWeukcyI
# PbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif/sYQsfch28bZeUz2rtY/9TCA6TD8
# dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+VqsS9/wQD7yFylIz0scmbKvFoW2j
# NrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA7xhLjfEFgtHEdqeVdGgwDQYJKoZI
# hvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0
# MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2MDQwMDAwMDBaFw0zNjA5MDMyMzU5
# NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkG
# A1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQwOTYgVGltZXN0YW1wIFJlc3BvbmRl
# ciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDQRqwtEsae
# 0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ3xTWcfsLwOvRxUwXcGx8AUjni6bz
# 52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqVQ+3bzWYesFtkepErvUSbf+EIYLkr
# LKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjoT1FpS54dNApZfKY61HAldytxNM89
# PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R0V3Zp3DjjANwqAf4lEkTlCDQ0/fK
# JLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6UnbksIcFJqLbkIXIPbcNmA98Oskkkr
# vt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39iTTFS+ENTqW8m6THuOmHHjQNC3zb
# J6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0dVVZw7knh1WZXOLHgDvundrAtuvz
# 0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6llN3QgshRta6Eq4B40h5avMcpi54wm
# 0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wggn8O2klETsJ7u8xEehGifgJYi+6I
# 03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmSF3voIgMFtNGh86w3ISHNm0IaadCK
# CkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwIDAQABo4IBlTCCAZEwDAYDVR0TAQH/
# BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85FxYxlQQ89hjOgwHwYDVR0jBBgwFoAU
# 729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQM
# MAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSBiDCBhTAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsGAQUFBzAChlFodHRwOi8vY2FjZXJ0
# cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0
# MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0fBFgwVjBUoFKgUIZOaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0VGltZVN0YW1waW5nUlNB
# NDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1UdIAQZMBcwCAYGZ4EMAQQCMAsGCWCG
# SAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEAZSqt8RwnBLmuYEHs0QhEnmNAciH4
# 5PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZhY+hIfP2JkQ38U+wtJPBVBajYfrb
# IYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/ciZmUnthfAEP1HShTrY+2DE5qjzv
# Zs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk6FxRPyUPxAAYH2Vy1lNM4kzekd8o
# EARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQUSntbjZ80FU3i54tpx5F/0Kr15zW
# /mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdCG1+lqvP4FbrQ6IwSBXkZagHLhFU9
# HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y58678IgmfORBPC1JKkYaEt2OdDh4G
# mO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V08X1JUPvB4ILfJdmL+66Gp3CSBXG6
# IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1qmcwbdUfcSYCn+OwncVUXf53VJUNO
# aMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfYxJ7La54i71McVWRP66bW+yERNpbJ
# CjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhDBf3Froguzzhk++ami+r3Qrx5bIbY
# 3TVzgiFI7Gq3zWcxggSqMIIEpgIBATBrMFcxCzAJBgNVBAYTAkdCMRgwFgYDVQQK
# Ew9TZWN0aWdvIExpbWl0ZWQxLjAsBgNVBAMTJVNlY3RpZ28gUHVibGljIENvZGUg
# U2lnbmluZyBDQSBFViBFMzYCEDxolvyQov0GPgzdcbswAjcwDQYJYIZIAWUDBAIB
# BQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYK
# KwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG
# 9w0BCQQxIgQgo4VkL3fWa3/VI6mclpsAcxWQl6/xtvEkA/IqFst48QswCwYHKoZI
# zj0CAQUABGcwZQIxAPUYz/s376GSbfkqD2XDJ0VYUSb2STCP1qaVVP9TDWCxsxmh
# 5fU+ESYrgJwtTsicgAIwcsGD9YWA53+cfaJ4sD2B2VDBu0y/f8mUMGm3zALVr8Tz
# wTRfa8x9hfG7SHg5o0L6oYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0w
# aTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQD
# EzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1
# NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDgyMTA1
# MzAxMFowLwYJKoZIhvcNAQkEMSIEIIIL11dqRNbmkEa4IJ88Qt7z23L+KLYOKKX7
# I8EaF6bVMA0GCSqGSIb3DQEBAQUABIICAE1sdj8QIwtvdxKpisHTD2C50NGRw8Z0
# ggq2BMl1q3wI450AHvjXZjwORf8aHK34TCxP86PMG5erib/QgapiCuj/QEOeOo03
# Bbl9CjICvwMGFpUmNkjkRqghce664tX+CNOSGfEO4hkZfwywYi8bJ1KrIWnnOrvi
# a6W4ajTMRk0gEnLWRCQHQkyfDzbiRLdaBxxuQe90Dq6Dgntbp7ZdAaGBOhrO0YqC
# gBqTrBFEf5ZeafoQqedDFEo0Md8L1T7wamALEKZdvsu90/76uz1zGp/7iTk98aye
# 1TqmGI0yZp5CPoZv4szaUZofQ/20fGhoIQcUY2yYSQWDtjT1S/PNYfJpUKlz3J6j
# GBAMsvBbjDjPlz7k4fsJgOJqQ9taRfLDupqckN4RkGxbB+wQ9pCTg9CKsEAsiEco
# OzKCGMFiTasQn+Ap+2goG+GxLNg56NX8W/+8GfAOIOMxSaMgwEUz81QCkfgJc4pC
# bpojwYwL5e2fcq1yCOLS0sMZAZ9Ke0hUvDIwxKnePrXsssGklRwGL9IZw25ZnyH9
# XYVNyUocA4fxiNyk684IeEHdNuk67Js4NFGaAiHxxXRxyGNyOKiIyWk8iWqUjBSr
# nID7L36Ywfqwp7dEJMIu7i2ZyrQZCw8aLE5bbyFp/gZMtyURKOBgDc2N8CG7XAeE
# QFEYhzqe/qKi
# SIG # End signature block
