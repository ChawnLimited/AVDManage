# Chawn Limited 2024
# AVD-Update.ps1
# Version 3.0
# Update Root Certificates, remove expired root certificates, Microsoft Edge for Business, Google Chrome Enterprise,Visual C Redistributables, Office 365, Windows Defender, OneDrive, Teams v2 and Meeting Add-In, FSLogix and Windows Updates using PSWindowsUpate
# Logfile is created in C:\Temp\AVD-Update\Update-VM-<date>.log
# Update services and tasks are disabled after update
# After updates, VM will reboot. Following this, please run AVD-PostUpdate.ps1 to complete image maintenance

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


# Get Current Info
try	{
	$Pname=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ProductName).ProductName
	$DVer=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name DisplayVersion).DisplayVersion
	$Ed=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID).EditionID
	$CurrB=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name CurrentBuildNumber).CurrentBuildNumber
	$CurrV=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
	Logit "Windows Version: $Pname $Dver $ed $CurrB.$CurrV"
	}
catch	{}

# Update Root Certificate
write-host "Updating Root Certificates"
try	{
	$rc=(Get-ChildItem -Path Cert:\LocalMachine\Root\).count
	Logit "Updating Root Certs: $rc"
# download latest SST from Microsoft
	$proc="Certutil.exe"
	$arg="-generateSSTFromWU C:\temp\AVD-Update\RootStore.sst"
	Start-process -FilePath $proc -ArgumentList $arg -wait
	start-sleep -seconds 3
# Import RootStore.sst to Trusted Root CA Store
	$file=Get-ChildItem -Path C:\temp\AVD-Update\Rootstore.sst
	$file | Import-Certificate -CertStoreLocation Cert:\LocalMachine\Root\
# remove expired certs
	$d=get-date -Format MM/dd/yyyy
	$oldcerts=Get-ChildItem -Path Cert:\LocalMachine\Root\ | Where-Object {$_.NotAfter -lt $d} 
	foreach ($c in $oldcerts) {Remove-Item -Path $c.PSPath -Force}
	$rc=(Get-ChildItem -Path Cert:\LocalMachine\Root\).count
	Logit "Updated Root Certs: $rc"
	}
Catch {	Logit "Could not update root certs"}

# Microsoft Edge
# access to go.microsoft.com
write-host "Updating Microsoft Edge"
try{
	if ($EdgeVer=(get-item -Path ${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe -ErrorAction SilentlyContinue).VersionInfo.FileVersion)
	{
	Logit "Edge Version: $EdgeVer"
	Logit "Updating Edge"
# update Edge
# set updates to Manual
	Get-Service -name edgeupdate,edgeupdatem,MicrosoftEdgeElevationService | Set-Service -StartupType Manual
	REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v UpdateDefault /t REG_DWORD /d 2 /f
#https://techcommunity.microsoft.com/t5/discussions/official-download-links-for-microsoft-edge-stable-enterprise/m-p/1082549
#http://go.microsoft.com/fwlink/?LinkID=2093437
	$URI="http://go.microsoft.com/fwlink/?LinkID=2093437"
	(New-Object System.Net.WebClient).DownloadFile($uri, "C:\temp\AVD-Update\MicrosoftEdgeEnterpriseX64.msi")
	$proc="msiexec.exe"
	$arg="/i C:\temp\AVD-Update\MicrosoftEdgeEnterpriseX64.msi ALLUSERS=1 REBOOT=ReallySuppress /qb- /l*v C:\temp\AVD-Update\MicrosoftEdgeEnterpriseX64.log"
# Install / Update Edge
	Start-Process -FilePath $proc -ArgumentList $arg -wait
# Disable Edge Updaters
	Get-Service -name edgeupdate,edgeupdatem,MicrosoftEdgeElevationService | Set-Service -StartupType Disabled | stop-service -force
	$tasks=Get-ScheduledTask -TaskName MicrosoftEdgeUp*
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false}
	$EdgeVer=(get-item -Path ${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe -ErrorAction SilentlyContinue).VersionInfo.FileVersion
	Logit "Edge Version: $EdgeVer"
	}
}
Catch {LogIt "Failed to update Edge"}


# Google Chrome
# access to dl.google.com
write-host "Updating Google Chrome"
try{
	if ($ChromeVer=(get-item -Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion)
	{
	Logit "Chrome Version: $ChromeVer"
	Logit "Updating Chrome"
# set updates to Manual
	Get-Service -Name GoogleUpdate*,GoogleChrome* | Set-Service -StartupType Manual
	REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Google\Update" /v UpdateDefault /t REG_DWORD /d 2 /f
	$URI="https://dl.google.com/dl/chrome/install/googlechromestandaloneenterprise64.msi"
	(New-Object System.Net.WebClient).DownloadFile($uri, "C:\temp\AVD-Update\googlechromestandaloneenterprise64.msi")
	$proc="msiexec.exe"
	$arg="/i C:\temp\AVD-Update\googlechromestandaloneenterprise64.msi ALLUSERS=1 REBOOT=ReallySuppress /qb- /l*v C:\temp\AVD-Update\googlechromestandaloneenterprise64.log"
# Install / Update Chrome
	Start-Process -FilePath $proc -ArgumentList $arg -wait
# Disable Chrome Updaters
	Get-Service -Name GoogleUpdate*,GoogleChrome* | Set-Service -StartupType Disabled | Stop-Service -Force
	$tasks=Get-ScheduledTask -TaskName GoogleUpdate*
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false}
	$ChromeVer=(get-item -Path "$env:ProgramFiles\Google\Chrome\Application\chrome.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
	Logit "Chrome Version: $ChromeVer"
	}
}
Catch {LogIt "Failed to update Chrome"}


# Update Visual C Redistributables
# https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170
write-host "Updating Visual C Redistributables"
try{
	$VisCx64=(Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Microsoft Visual C*X64 Minimum Runtime*"}).version
	Logit "Visual C Version x64: $VisCx64"
	Logit "Updating Visual C x64"
	$URI="https://aka.ms/vs/17/release/vc_redist.x64.exe"
	(New-Object System.Net.WebClient).DownloadFile($uri, "C:\temp\AVD-Update\vc_redist.x64.exe")
	$proc="C:\temp\AVD-Update\vc_redist.x64.exe"
	$arg="/install /quiet /norestart"
# Install / Update VisCx64
	Start-Process -FilePath $proc -ArgumentList $arg -wait
	$VisCx64=(Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Microsoft Visual C*X64 Minimum Runtime*"}).version
	Logit "Visual C Version x64: $VisCx64"

	$VisCx86=(Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Microsoft Visual C*X86 Minimum Runtime*"}).version
	Logit "Visual C Version x86: $VisCx86"
	Logit "Updating Visual C x86"
	$URI="https://aka.ms/vs/17/release/vc_redist.x86.exe"
	(New-Object System.Net.WebClient).DownloadFile($uri, "C:\temp\AVD-Update\vc_redist.x86.exe")
	$proc="C:\temp\AVD-Update\vc_redist.x86.exe"
	$arg="/install /quiet /norestart"
# Install / Update VisCx86
	Start-Process -FilePath $proc -ArgumentList $arg -wait
	$VisCx86=(Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Microsoft Visual C*X86 Minimum Runtime*"}).version
	Logit "Visual C Version x86: $VisCx86"
}
Catch {LogIt "Failed to update Visual C Redistributables"}


# Update Office / MS Apps 365
# Enable Office Updates
write-host "Updating Office 365"
try{	
if (get-item -path "$env:ProgramFiles\Microsoft Office") {Get-Service -Name ClickToRunSvc | Set-service -startuptype Automatic
							REG ADD "HKEY_LOCAL_MACHINE\software\policies\microsoft\office\16.0\common\OfficeUpdate" /v EnableAutomaticUpdates /t REG_DWORD /d 1 /f
							$offver=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' | Select-Object -ExpandProperty VersionToReport
							Logit "Office 365 Version: $offver"
							Logit "Updating Office 365"
							$proc="$env:ProgramFiles\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe"
							$arg="/update User displaylevel=false forceappshutdown=true updatepromptuser=false"
							$updateoffice=[Diagnostics.Process]::new()
							$updateoffice.StartInfo.FileName=$proc
							$updateoffice.StartInfo.Arguments=$arg
							$updateoffice.start()
# wait for the second system process to start
	start-sleep -seconds 30
	do {write-host "Updating Office";start-sleep -seconds 15}  while ((get-process -Name OfficeClickToRun -IncludeUserName | Where-Object {$_.UserName -like "*SYSTEM"}).count -gt 1)
							$offver=Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration' | Select-Object -ExpandProperty VersionToReport
							Logit "Office 365 Version: $offver"
# Disable Office Updates
	REG ADD "HKEY_LOCAL_MACHINE\software\policies\microsoft\office\16.0\common\OfficeUpdate" /v EnableAutomaticUpdates /t REG_DWORD /d 0 /f
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Office\
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false}
							}
}
Catch {LogIt "Failed to update Office"}


# Update OneDrive
write-host "Updating OneDrive"
try{
	if ($ODVer=(get-item -Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion)
	{Logit "OneDrive Version: $ODVER"
	Logit "Updating OneDrive"
	Get-Service -Name "OneDrive Updater Service" | Set-service -startuptype Automatic

	$proc="$env:ProgramFiles\Microsoft OneDrive\OneDriveStandaloneUpdater.exe"
	Start-Process -FilePath $proc
do {write-host "Waiting for update to start";start-sleep -seconds 10}  while ((get-process -Name OneDriveStandaloneUpdater -ErrorAction SilentlyContinue).count -gt 0)
do {write-host "Updating";start-sleep -seconds 10}  while ((get-process -Name OneDriveSetup -ErrorAction SilentlyContinue).count -gt 0)

	$tasks=Get-ScheduledTask -TaskName OneDrive*
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}
	$ODVer=(get-item -Path "$env:ProgramFiles\Microsoft OneDrive\OneDrive.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
	Logit "OneDrive Version: $ODVER"
	Get-Service -Name "OneDrive Updater Service" | Set-service -startuptype Disabled
	}
}
Catch {Logit "Failed to update OneDrive"}

# Update Teams v2 and the Teams Meeting Addin
try	{
		if ($teamver=(Get-AppxPackage -Allusers -Name MSTeams).Version)
		{
		Logit "Teams Version: $teamVer"
		Logit "Updating New Teams"
		$URI="https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
		(New-Object System.Net.WebClient).DownloadFile($uri, "C:\temp\AVD-Update\teamsbootstrapper.exe")
		$URI="https://go.microsoft.com/fwlink/?linkid=2196106"
		(New-Object System.Net.WebClient).DownloadFile($uri, "C:\temp\AVD-Update\teams.msix")
		$proc="C:\temp\AVD-Update\teamsbootstrapper.exe"
		$arg="-p -o C:\temp\AVD-Update\teams.msix"
		Start-Process -FilePath $proc -ArgumentList $arg -wait
		start-sleep -seconds 5
		REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Teams" /v disableAutoUpdate /t REG_DWORD /d 1 /f
		$teamver=(Get-AppxPackage -Allusers -Name MSTeams).Version
		Logit "Teams Version: $teamVer"

		# Get Teams Meeting Addin Version if installed and update
			$TMAddin=Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "*Microsoft Teams Meeting Add-in for Microsoft Office*"}
			if ($TMAddin.version)
			{
			Logit "Teams Meeting Addin Version: $TMAddin"
			$TMAPath = "{0}\WINDOWSAPPS\MSTEAMS_{1}_X64__8WEKYB3D8BBWE\MICROSOFTTEAMSMEETINGADDININSTALLER.MSI" -f $env:programfiles,$teamver
				if ($TMAVersion = (Get-AppLockerFileInformation -Path $TMAPath | Select-Object -ExpandProperty Publisher).BinaryVersion)
				{
    				Logit "Teams Meeting Addin found in $TMAPath. Installing..."
    				$TargetDir = "{0}\Microsoft\TeamsMeetingAddin\{1}\" -f ${env:ProgramFiles(x86)},$TMAVersion
				$params = '/i "{0}" TARGETDIR="{1}" /qn ALLUSERS=1' -f $TMAPath, $TargetDir
				Start-Process msiexec.exe -ArgumentList $params -wait
				}
			$TMAddin=(Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -like "Microsoft Teams Meeting Add-in for Microsoft Office"}).version
			Logit "Teams Meeting Addin Version: $TMAddin"
			}
		}
	}
catch {Logit "Failed to update Microsoft Teams"}



# Update FSLogix
write-host "Updating FSLogix"
try	{
	if ($FSVer=(get-item -Path "$env:ProgramFiles\FSLogix\Apps\frx.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion)
	{Logit "FSLogix Version: $FSVER"
	Logit "Updating FSLogix"
	$URI="https://aka.ms/fslogix_download"
	Invoke-WebRequest -Uri $URI -OutFile C:\Temp\AVD-Update\FSlogix.zip
	Expand-Archive -Path C:\Temp\AVD-Update\FSlogix.zip -DestinationPath C:\Temp\AVD-Update
	$proc="C:\Temp\AVD-Update\x64\Release\FSLogixAppsSetup.exe"
	$arg="/install /quiet /norestart /log C:\Temp\AVD-Update\FSLogix.log"
	Start-Process -FilePath $proc -ArgumentList $arg -wait
	$FSVer=(get-item -Path "$env:ProgramFiles\FSLogix\Apps\frx.exe" -ErrorAction SilentlyContinue).VersionInfo.FileVersion
	Logit "FSlogix Version: $FSVER"
Write-Host "Add Local Administrators to FS Logix Exclude Groups"
# Add Local Administrators to FS Logix Exclude Groups
	if (Get-LocalGroup -Name "FSLogix ODFC Exclude List" -ErrorAction SilentlyContinue)
		{
		Add-LocalGroupMember -Group "FSLogix ODFC Exclude List" -Member "NT Authority\Local account and member of Administrators group" -ErrorAction SilentlyContinue
		}
	if (Get-LocalGroup -Name "FSLogix Profile Exclude List" -ErrorAction SilentlyContinue)
		{
		Add-LocalGroupMember -Group "FSLogix Profile Exclude List" -Member "NT Authority\Local account and member of Administrators group" -ErrorAction SilentlyContinue
		}
	}
	}
Catch	{}

# Install pre-reqs for Windows Update
write-host "Starting Windows Update"
Get-Service -name UsoSVC,wuauserv,Bits | Set-Service -StartupType Manual
# access to go.microsoft.com
# update Nuget
try	{
		[Net.ServicePointManager]::SecurityProtocol =
    		[Net.ServicePointManager]::SecurityProtocol -bor
    		[Net.SecurityProtocolType]::Tls12
		Install-PackageProvider -Name NuGet -ForceBootstrap -Scope AllUsers -Force
		Logit "Updated NuGet"
	}
catch	{Logit "NuGet Update Failed"}

# trust PSGalllery
# access to www.powershellgallery.com
try	{
	    if (-not(Get-PSRepository -Name "PSGallery"))
	    	{Register-PSRepository -Default -InstallationPolicy Trusted
	    	LogWrite "Added PSGallery as trusted repo"}
	    Else {Set-PSRepository -Name "PSGallery" -InstallationPolicy Trusted}
	    }
catch	{Logit "Failed to add PSGallery as trusted repo"}

# install PSWindowsUPdate
try	{
	if (-not(Get-module -Name "PSWindowsUpdate"))
		{Install-Module -Name PSWindowsUpdate -Force
		Import-Module -Name PSWindowsUpdate
		Logit "Installed PSWindowsUpdate"}
	}
catch	{
	Logit "Failed to install PSWindowsUpdate"}

# Windows Update
# access to windowsupdate.microsoft.com + others
# Enable Services
	Logit "Starting Windows Update"
	Get-Service -Name Wuauserv | Set-Service -StartupType Manual
	Get-Service -Name Bits | Set-Service -StartupType Manual
	Set-WUSettings -AUOptions Disabled -IncludeRecommendedUpdates -Confirm:$False
# install Windows Updates but not the MRT KB890830
	Get-WindowsUpdate -MicrosoftUpdate -Install -AcceptAll -IgnoreReboot -UpdateType Software -NotKBArticleID KB890830 | Out-File "c:\temp\AVD-Update\$(get-date -f yyyy-MM-dd)-WindowsUpdate.log" -force
	Logit "Windows Updates Installed"
# remove Windows Update Tasks
	$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\UpdateOrchestrator\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}
	$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\WindowsUpdate\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}
	set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'-Name 'MaintenanceDisabled' -Value 1 -Force -ErrorAction SilentlyContinue

write-host "Finished Windows Update"


# Disable Windows Maintenance Tasks
Unregister-ScheduledTask -TaskName "Microsoft\Windows\TaskScheduler\Idle Maintenance" -confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Microsoft\Windows\TaskScheduler\Regular Maintenance" -confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Microsoft\Windows\TaskScheduler\Manual Maintenance" -confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Microsoft\Windows\TaskScheduler\Maintenance Configurator" -confirm:$false -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName "Microsoft\Windows\Servicing\StartComponentCleanup" -confirm:$false -ErrorAction SilentlyContinue
set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'-Name 'MaintenanceDisabled' -Value 1 -Force -ErrorAction SilentlyContinue

# update defender
write-host "Updating Windows Defender"
try{
if ((Get-MpComputerStatus).RealTimeProtectionEnabled) {$DefVer=(Get-MpComputerStatus).AMProductVersion
							$DefSig=(Get-MpComputerStatus).AntivirusSignatureVersion
							Logit "Defender Product Version: $DefVer"
							Logit "Defender AV Signature Version: $DefSig"
							Logit "Update Windows Defender"
							Update-MpSignature -UpdateSource MicrosoftUpdateServer
							$DefVer=(Get-MpComputerStatus).AMProductVersion
							$DefSig=(Get-MpComputerStatus).AntivirusSignatureVersion
							Logit "Defender Product Version: $DefVer"
							Logit "Defender AV Signature Version: $DefSig"}
}
Catch {Logit "Failed to update Defender"}






# Reboot
Logit " -------------------------------- Reboot --------------------------------"
Logit "Run AVD-PostUpdate.ps1 after the reboot to complete the image maintenance"
Shutdown.exe -r -t 10



