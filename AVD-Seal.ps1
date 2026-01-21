# Chawn Limited 2026
# AVD-Seal.ps1
# Version 4.0
# Disables Update Services and Update Tasks
# Edge, Chrome, OneDrive, Office, WSUS
# Disables IPv6
# Resets MSMQ if installed
# Removes ghost hardware
# Empty Recycle Bin
# Clear Branch Cache
# Resets Windows Search
# Removes Azure Logs and Extensions
# Removes WSUS folders
# Configures event logs
# Neutralise the WindowsAzure Agent
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
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f


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

Write-Host "Remove Ghost Hardware"
# Remove Ghost Hardware
$devs=Get-PnpDevice -class Diskdrive,Display,Monitor,Mouse,Net,Ports,Processor,PrintQueue,SCSIAdapter,SoftwareDevice,Volume -ErrorAction Ignore | ? status -eq unknown
	foreach ($d in $devs) 	{
 	&"pnputil" /remove-device $d.InstanceId
				}




Write-Host "Reset Windows Search"
# Reset Windows Search
	Get-Service -ServiceName wsearch | Set-Service -StartupType Disabled
	Stop-Service -ServiceName wsearch -force -ErrorAction Ignore
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f
	Remove-Item -Path "$env:ProgramData\Microsoft\Search\Data\" -Recurse -Force -ErrorAction Ignore
	Get-Service -ServiceName wsearch | Set-Service -StartupType Automatic

Write-Host "Remove temporary files"
# Remove Azure Logs and Extensions
	Remove-Item -Path C:\Packages\ -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\WindowsAzure\Logs -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\Temp -Recurse -Force -ErrorAction Ignore

# empty files & folders
	Stop-Service -ServiceName wuauserv,bits,msiserver
	Remove-Item -Path C:\Windows\Panther -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\temp\AVD-Update -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\SoftwareDistribution -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\Logs -Recurse -Force -ErrorAction Ignore
	Remove-item -Path C:\Windows\System32\config\systemprofile\AppData\Local -Filter *.tmp -Recurse -Force -ErrorAction Ignore
#	Get-ChildItem -Path c:\ -Include *.tmp, *.dmp, *.etl, *.evtx, thumbcache*.db, *.log -File -Recurse -Force -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue

# Emtpy Recycle Bin
Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Clear Branch Cache
Clear-BCCache -Force -ErrorAction SilentlyContinue

Write-Host "Neutralise the WindowsAzure Agent"
# Neutralise the WindowsAzure Agent
Get-Service -Name RDAgent | stop-service
Get-Service -Name WindowsAzureGuestAgent | stop-service
Get-ChildItem -Path C:\WindowsAzure\config -Filter *.*  | Remove-Item -Force -Recurse
Get-ChildItem -Path C:\WindowsAzure\logs -Filter *.*  | Remove-Item -Force -Recurse
$certs=Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match 'DC=Windows Azure CRP Certificate Generator' };foreach ($c in $certs) {Remove-Item $c.PSPath -Force}
$certs=Get-ChildItem "Cert:\LocalMachine\Windows Azure Environment";foreach ($c in $certs) {Remove-Item $c.PSPath -Force}
$certs=Get-ChildItem "Cert:\LocalMachine\Remote Desktop";foreach ($c in $certs) {Remove-Item $c.PSPath -Force}
$store=Get-Item "Cert:\LocalMachine\Runtime_Transport_Store_*" | select name
$store='Cert:\LocalMachine\'+ $store.Name
$certs=Get-ChildItem $store;foreach ($c in $certs) {Remove-Item $c.PSPath -Force}
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\GuestAgent" -Recurse -Force
Remove-Item -Path "HKLM:SOFTWARE\Microsoft\Windows Azure\HandlerState" -Recurse -Force
Remove-Item -Path "HKLM:SOFTWARE\Microsoft\Windows Azure\ScriptHandler" -Recurse -Force

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

ipconfig /flushdns

Write-Host "Run Sysprep"
$proc="C:\Windows\System32\Sysprep\sysprep.exe"
$arg="/oobe /generalize /shutdown"
Start-Process -FilePath $proc -ArgumentList $arg

exit 0
