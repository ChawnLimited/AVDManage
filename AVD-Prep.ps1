# Chawn Limited 2026
# AVD-Prep.ps1
# Version 4.0
# Remove RDSIA and RDSBL if instaleld
# Download / Update Microsoft Remote Desktop Infrastructure and Boot Agents
# Install Agents silently with no Registration Token
# Neutralise the Agents before running sysprep
# This allows AVDTurbo to perform faster deployments

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-Prep.log"

Function LogWrite
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

# Remove existing agents if present
%{
	try {
		if (get-package -name 'Remote Desktop Agent Boot Loader') {Uninstall-Package -Name 'Remote Desktop Agent Boot Loader' -AllVersions -Force; LogWrite ("Uninstalled Remote Desktop Agent Boot Loader")}
		if (get-package -name 'Remote Desktop Services Infrastructure Agent') {Uninstall-Package -Name 'Remote Desktop Services Infrastructure Agent' -AllVersions -Force; ; LogWrite ("Remote Desktop Services Infrastructure Agent")}
	}
	catch {}
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


# Deploy RDS Agents
LogWrite ("Install & Configure RDAgents.")
%{
	try{
	    if (get-item -path C:\Source\RDagent.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDAgent.msi REGISTRATIONTOKEN=[INVALIDTOKEN] /qb /L*V RDAgent.log"}
	    if (get-item -path C:\Source\RDBoot.msi){Start-Process msiexec.exe -Wait -ArgumentList "/I C:\Source\RDBoot.msi /qb  /L*V RDBoot.log"}		
			$i=0
			do {start-sleep -Seconds 2;$i++;} until((($RDSIA=(get-package -name "Remote Desktop Services Infrastructure Agent" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -and (($RDSABL=(get-package -name "Remote Desktop Agent Boot Loader" -ErrorAction SilentlyContinue).Status -eq 'Installed')) -or $i -eq 50)
				if (($RDSIA -eq 'Installed' ) -and ($RDSABL -eq 'Installed'))
				{logwrite ("Remote Desktop Services Infrastructure Agent and Remote Desktop Agent Boot Loader are installed")}
				Else {logwrite ("Remote Desktop Services Infrastructure Agent installed: " + $RDSIA + ". Remote Desktop Agent Boot Loader installed: " + $RDSABL)}
		}
    	catch {logwrite('Error installing Remote Desktop Agents. ' + $_.Exception.Message); exit 999}
}
		
		
		Get-Service -Name RDAgentBootLoader | Set-Service -StartupType Disabled
		Get-Service -Name RDAgentBootLoader | Stop-Service
		Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Recurse -Force
		new-Item -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "RegistrationToken" -Value "AVDTurbo" -force
		Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -Name "HostPoolType" -Value "Default" -force
		New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\RDInfraAgent" -PropertyType dword -Name "IsRegistered" -Value 0 -Force
		LogWrite ("RDAgents Complete.")


$log=Get-Content .\AVD-Prep.log -Delimiter :
write-host $log
Write-Host "You can now either shudown the VM (Specialize) or run Sysprep (Generalize)"
