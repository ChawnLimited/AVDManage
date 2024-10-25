# Chawn Limited 2024
# AVD-Seal.ps1
# Version 1.2
# Disables Update Services and Update Tasks
# Edge, Chrome, OneDrive, Office, WSUS
# Disables IPv6, Nic TaskOffload, Machine Password changes
# Resets MSMQ if installed
# Removes ghost hardware
# Empty Recycle Bin
# Clear Branch Cache
# Resets Windows Search
# Removes Azure Logs and Extensions
# Removes WSUS folders
# Configures event logs
# Run Sysprep

Write-Host "Disabling Updaters"
try	{
# Disable Edge Updaters
	Get-Service -name edgeupdate,edgeupdatem,MicrosoftEdgeElevationService | Set-Service -StartupType Disabled | stop-service -force -ErrorAction SilentlyContinue
	$tasks=Get-ScheduledTask -TaskName MicrosoftEdgeUp* -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable Chrome Updaters
	Get-Service -Name GoogleUpdate*,GoogleChrome* | Set-Service -StartupType Disabled | Stop-Service -Force -ErrorAction SilentlyContinue
	$tasks=Get-ScheduledTask -TaskName GoogleUpdate* -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable OneDrive Updater
	$tasks=Get-ScheduledTask -TaskName OneDrive* -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}
	Get-Service -Name "OneDrive Updater Service" | Set-service -startuptype Disabled -ErrorAction SilentlyContinue

# Disable Office Updaters
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Office\ -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable Windows Update tasks
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\UpdateOrchestrator\ -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\WindowsUpdate\ -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable Windows Medic
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\WaaSMedic\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable Windows Maintenance
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\TaskScheduler\ -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\Servicing\ -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}
		set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'-Name 'MaintenanceDisabled' -Value 1 -Force -ErrorAction SilentlyContinue
	}
catch{}

# set wsus to manual
	REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
	REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 1 /f

# disable ipv6
	reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f

# disable task offload
	REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableTaskOffload /t REG_DWORD /d 1 /f

# disable machine password changes
	REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f

# Microsoft Message Queuing
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/94a38814-a56e-4641-bd11-c020c2114e27
try	{
		if (get-service -ServiceName MSMQ -ErrorAction SilentlyContinue)
		{
		Stop-Service -ServiceName msmq,mqac -Force
		REG DELETE "HKEY_LOCAL_MACHINE\Software\Microsoft\MSMQ\Parameters\MachineCache" /v "QMId" /f
		REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\MSMQ\Parameters" /v SysPrep /t REG_DWORD /d 1 /f
		}	
	}
catch{}

# Remove Ghost Hardware
$devs=Get-PnpDevice -class CDrom,Diskdrive,Display,Monitor,Mouse,Net,Ports,Processor,PrintQueue,SCSIAdapter,SoftwareDevice,Volume -ErrorAction Ignore | ? status -eq unknown
	foreach ($d in $devs) 	{
 	&"pnputil" /remove-device $d.InstanceId
				}


# Emtpy Recycle Bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Clear Branch Cache
Clear-BCCache -Force -ErrorAction SilentlyContinue

Write-Host "Reset Windows Search"
# Reset Windows Search
	Get-Service -ServiceName wsearch | Set-Service -StartupType Disabled
	Stop-Service -ServiceName wsearch -Force -ErrorAction Ignore
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f
	Remove-Item -Path "$env:ProgramData\Microsoft\Search\Data\" -Recurse -Force -ErrorAction Ignore
	Get-Service -ServiceName wsearch | Set-Service -StartupType Automatic

Write-Host "Remove temporary files"
# Remove Azure Logs and Extensions
	Remove-Item -Path C:\Packages\ -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\WindowsAzure\Logs -Recurse -Force -ErrorAction Ignore

# empty folders
	Stop-Service -ServiceName wuauserv,bits,msiserver -Force
	Remove-Item -Path C:\Windows\SoftwareDistribution -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\Panther -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\temp\AVD-Update -Recurse -Force -ErrorAction Ignore

Write-Host "Configure Event Logs"
# configure and clear event logs
	wevtutil sl Application /rt:false /ms:67108864
	wevtutil sl System /rt:false /ms:67108864
	wevtutil sl Security /rt:false /ms:67108864
	wevtutil sl Microsoft-FSLogix-Apps/Operational /rt:false /ms:67108864
	wevtutil cl Application
	wevtutil cl System
	wevtutil cl Security
	wevtutil cl Microsoft-FSLogix-Apps/Operational

Write-Host "Add Local Administrators to FS Logix Exclude Groups"
# Add Local Administrators to FS Logix Exclude Groups
if (Get-LocalGroup -Name "FSLogix ODFC Exclude List" -ErrorAction SilentlyContinue)
	{
	Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member "Administrators" -ErrorAction SilentlyContinue
	}
if (Get-LocalGroup -Name "FSLogix Profile Exclude List" -ErrorAction SilentlyContinue)
	{
	Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member "Administrators" -ErrorAction SilentlyContinue
	}

Write-Host "Run Sysprep"
$proc="C:\Windows\System32\Sysprep\sysprep.exe"
$arg="/oobe /generalize /shutdown"
Start-Process -FilePath $proc -ArgumentList $arg

exit 0
