# Chawn Limited 2024
# AVD-PostUpdate.ps1
# Version 1.1
# After updates have been applied using AVD-Update.ps1, run this script to compress WinSXS and Optimise .Net and tidy folders
# After running this script, shutdown and snapshot the VM. Then start the VM and run sysprep before creating an updated Image for deployment

# Set exec policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force

New-Item -Path C:\temp\AVD-Update -ItemType Directory -Force
$Logfile = "C:\temp\AVD-Update\Update-VM-$(get-date -f yyyy-MM-dd).log"

# turn off progress bars - https://stackoverflow.com/questions/28682642/powershell-why-is-using-invoke-webrequest-much-slower-than-a-browser-download
$ProgressPreference ="SilentlyContinue"

Function LogIt
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

Function dotNetex
{
   Param ([string]$dotNetPath)
	$arg0="executeQueuedItems"
	$arg1="update /force"
	if (get-item -path $dotnetPath -ErrorAction SilentlyContinue) {Start-Process -FilePath $dotnetPath -ArgumentList $arg0 -wait;Start-Process -FilePath $dotnetPath -ArgumentList $arg1 -wait}
}

LogIt " ------------------------------ Post Reboot ------------------------------"
Logit "Running AVD-PostUpdate"

# Log Update Info
try	{
	$Pname=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
	$DVer=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion).DisplayVersion
	$Ed=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID).EditionID
	$CurrB=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuildNumber).CurrentBuildNumber
	$CurrV=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	Logit "Windows Version: $Pname $Dver $ed $CurrB.$CurrV"
	}
catch	{}


# Compress WinSXS
Write-Host "Compress WinSXS"
try	{Logit "Cleaning WinSXS"
	$proc="dism.exe"
	$arg="/online /Cleanup-Image /StartComponentCleanup /ResetBase"
# Start Dism
	Start-Process -FilePath $proc -ArgumentList $arg -wait
	Logit "Cleaning WinSXS Complete"}
Catch	{}	

# Optimise dotNet
Write-Host "Optimise .Net"
try	{
		Logit "Start .Net Optimisation"
	dotNetex "C:\Windows\Microsoft.NET\Framework\v4.0.30319\ngen.exe"
	dotNetex "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngen.exe"
	dotNetex "C:\Windows\Microsoft.NET\Framework\v2.0.50727\ngen.exe"
	dotNetex "C:\Windows\Microsoft.NET\Framework64\v2.0.50727\ngen.exe"
	Get-ScheduledTask -TaskName '.net Framework NGEN*' | Disable-ScheduledTask
	Logit ".Net Optimised"
	}
Catch{Logit ".Net optimisation failed"}


# disable machine password changes
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f

# reset Windows Search
Write-Host "Reset Windows Search"
try 	{
	Get-Service -ServiceName wsearch | Set-Service -StartupType Disabled
	Stop-Service -ServiceName wsearch
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f
	Remove-Item -Path "$env:ProgramData\Microsoft\Search\Data\" -Recurse -Force
	Get-Service -ServiceName wsearch | Set-Service -StartupType Automatic
	Logit "Cleaned Windows Search"
	}
Catch	{Logit "Failed to clean Windows Search"}

Write-Host "Clear temporary files"
# remove old Azure logs and extensions
try	{
	Remove-Item -Path C:\Packages\ -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\WindowsAzure\Logs -Recurse -Force -ErrorAction Ignore
	Logit "Cleared Azure logs and extensions"
	}
Catch {Logit "Could not clear Azure logs and extensions"}

# clean WSUS Software Distribution
try	{
	Get-Service -ServiceName wuauserv,bits,msiserver | Stop-Service -Force
	Remove-Item -Path C:\Windows\SoftwareDistribution -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\Panther -Recurse -Force -ErrorAction Ignore
	Logit "Cleared SoftwareDistribution"
	}
Catch {Logit "Could not clear SoftwareDistribution"}

# remove any downloaded media but leave the log files
try 	{
	Get-ChildItem -Path C:\Temp\AVD-Update -Exclude *.log | Remove-Item -Recurse -Force
	}
catch	{}

# clear main event logs
wevtutil cl Application
wevtutil cl System
wevtutil cl Security

Logit "Take a Snapshot before sysprepping the VM"
Write-Host "Take a Snapshot before sysprepping the VM"

