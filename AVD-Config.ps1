# Chawn Limited 2026
# AVD-Config.ps1
# Version 2.3
# Configure a Session Host after joining an AVD Host Pool

$ProgressPreference ="SilentlyContinue"

# Disable Logons - we don't want users logging on until after the reboot
stop-service RDAgentBootLoader

# Add commands to disable services
Function DisService {
Param ([string]$servname)
try	{
		if (get-service -ServiceName $servname -ErrorAction SilentlyContinue)
		{
		Get-Service -ServiceName $servname | Set-Service -StartupType Disabled -ErrorAction SilentlyContinue
		}	
	}
	catch{}
}

# Add commands to set services to manual
Function ManService {
Param ([string]$servname)
try	{
		if (get-service -ServiceName $servname -ErrorAction SilentlyContinue)
		{
		Get-Service -ServiceName $servname | Set-Service -StartupType Manual -ErrorAction SilentlyContinue
		}	
	}
	catch{}
}

# Add commands to disable tasks
Function DisTask {
Param ([string]$taskname)
try	{
		if (Get-ScheduledTask -TaskName  $taskname -ErrorAction SilentlyContinue)
		{
			Get-ScheduledTask -TaskName  $taskname | Disable-ScheduledTask -ErrorAction SilentlyContinue
		}
	}
catch{}
}

# Add defender folder and process exclusions
Function MPExclude {
Param ([string]$file)
try	{
		Add-MpPreference -ExclusionPath $file
		if ($file.EndsWith('.exe')) {Add-MpPreference -ExclusionProcess $file}
	}
catch{}
}


# Disable Bitlocker
Function noBDE {
	manage-bde -off C:
 	manage-bde -off D:
	reg delete "HKEY_CLASSES_ROOT\Drive\shell\decrypt-bde" /f
	reg delete "HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev" /f
   New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker" -Name "PreventDeviceEncryption" -Value 1 -Force -ErrorAction SilentlyContinue
}
# UnComment to enable
# noBDE


# Set page File to Memory Size on D:\
# Specialized images retain configured pagefile settings so this is intended for Generalized images
Function SetPageFile{
	$MemMB = (Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1MB

	if (Get-Volume -DriveLetter D) {$pfPath = "D:\pagefile.sys"}
	else {$pfPath = "C:\pagefile.sys"}

	$Sys = Get-WmiObject -Class Win32_ComputerSystem -EnableAllPrivileges
	$Sys.AutomaticManagedPagefile = $false
	$Sys.Put() | Out-Null

	$pf = Get-CimInstance -ClassName Win32_PageFileSetting
	Get-WmiObject -Class Win32_PageFileSetting | ForEach-Object {$_.Delete() | Out-Null}
	$pf = New-CimInstance -ClassName Win32_PageFileSetting -Property @{ Name= $pfpath }
	$pf | Set-CimInstance -Property @{ InitialSize = $memMB; MaximumSize = $memMB }
}
# UnComment to enable
# SetPageFile


# Disable Network Bindings - Disables IPv6, LLDP Protocols from all NICs
Function NoBindings{
	try{
	$nics=Get-NetAdapter -Name *Ethernet*
	foreach ($nic in $nics) { Disable-NetAdapterBinding -Name $nic.name -ComponentID ms_lltdio,ms_tcpip6,ms_lldp,ms_rspndr -ErrorAction SilentlyContinue}
	}
	Catch{}
}
# UnComment to enable
# NoBindings



# Run your own scripts
# Scripts must be in C:\Scripts
# Scripts must not contain reboot commands - AVDJoin / AVDTurbo will reboot when these scripts have completed
# Run scripts synchronously as below

# PowerShell Scripts
# Powershell -ExecutionPolicy Bypass -NoProfile -NoLogo -File MyScript.ps1

# cmd files
# cmd.exe /c MyScript.cmd

# Processes
# Start /wait <"path to process">