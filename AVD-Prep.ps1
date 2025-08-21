# Chawn Limited 2025
# AVD-Prep.ps1
# Version 2.0
# Check Pre-requisites for AVD Deployment - Nuget, PSGallery, Az Modules
# Download / Update Microsoft Remote Desktop Infrastructure and Boot Agents
# Install Agents silently with no Registration Token
# Neutralise the Agents before running sysprep
# This allows AVDTurbo and AVD Join to perform faster deployments

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-Prep.log"

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
    catch {LogWrite ("Failed to add PSGallery as trusted repo. " + $_.Exception.Message); exit 100}
}


Function UpdateModule
{
   Param ([string]$module)
	try {
	install-module $module
    	Logwrite ('Installed ' + $module)
    	}
    catch {Logwrite ('Failed to update ' + $module + " " + $_.Exception.Message);exit 3}
}

# Check AZ Modules are present
%{
		try {
		if (Get-Module -name Az.Accounts -ListAvailable) {Logwrite('Az.Accounts is available.')}
		else {logwrite('Az.Accounts is not available. Will try and install.'); UpdateNuget; UpdateModule Az.Accounts;}

		if (Get-Module -name Az.DesktopVirtualization -ListAvailable) {Logwrite('Az.DesktopVirtualization is available.')}
		else {logwrite('Az.DesktopVirtualization is not available. Will try and install.'); UpdateModule Az.DesktopVirtualization;}
		    }
        	catch {logwrite('Error importing Az Modules' +  $_.Exception.Message); exit 3}
}

# Start the RDAGent downloads
		try {
		LogWrite ("Download RD Agents")
		New-Item -Path C:\Source -ItemType Directory -Force
		$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrmXv";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDagent.msi -UseBasicParsing;
		LogWrite ("Downloaded RDAgent.msi")
		$URI="https://query.prod.cms.rt.microsoft.com/cms/api/am/binary/RWrxrH";Invoke-WebRequest -Uri $URI -OutFile C:\Source\RDBoot.msi -UseBasicParsing;
		LogWrite ("Downloaded RDBoot.msi")		
		    }
		catch {LogWrite ("Failed to download RDAgents. " + $_.Exception.Message);exit 99}


# Deploy and Neutralise RD Agents
	LogWrite ("Failed to configure RDAgents.")
	try {
	    if (get-item -path C:\Source\RDagent.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=[INVALIDTOKEN] /qb /L*V RDAgent.log"}
	    if (get-item -path C:\Source\RDBoot.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"}
		start-sleep -seconds 5
		Get-Service -Name RDAgentBootLoader | Stop-Service
		Get-Service -Name RDAgentBootLoader | Set-Service -StartupType Disabled
		start-sleep -seconds 10
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Recurse -Force
		new-Item -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -Value "AVDTurbo" -force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "HostPoolType" -Value "Default" -force
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -PropertyType dword -Name "IsRegistered" -Value 0 -Force
	}
catch {LogWrite ("Failed to configure RDAgents. " + $_.Exception.Message);exit 999}

Write-Host "You can now either shudown the VM or run Sysprep"







