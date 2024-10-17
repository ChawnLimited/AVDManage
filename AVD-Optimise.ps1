# Chawn Limited 2024
# AVD-Optimise.ps1
# Version 1.1
# Implements know optimisations for AVD Session Hosts
# https://learn.microsoft.com/en-us/previous-versions/windows-server/it-pro/windows-server-2019/remote/remote-desktop-services/rds-vdi-recommendations
# Update services and Maintenance tasks are disabled
# Core Domain firewall rules are enabled. User firewall rules are removed
# Microsoft recommended policy settings are implemented
# Windows updates are set to manual
# IPv6, Task Offloading and MachinePasswords are disabled


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

$ProgressPreference ="SilentlyContinue"
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

# Tune the SMB Client
# https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/file-server/#client-tuning-example
write-host "Tuning SMB"
Set-SmbClientConfiguration -EnableBandwidthThrottling 0 -FileInfoCacheEntriesMax 32768 -DirectoryCacheEntriesMax 4096 -FileNotFoundCacheEntriesMax 32768 -MaxCmds 32768 -Force

# Disable Services
# https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server
# https://learn.microsoft.com/en-us/windows/application-management/per-user-services-in-windows
write-host "Disabling Services"
DisService .Net*;					#.NET Framework NGEN
DisService AJRouter;					#AllJoyn Router Service
DisService tzautoupdate;				#Auto Time Zone Updater
DisService bthserv;					#Bluetooth Support Service
DisService BluetoothUserService;			#Bluetooth User Support Service
DisService PeerDistSvc;					#BranchCache
# CDPUserSvc;						#CDPUserSvc leave enabled due to profile load issues	
DisService DiagTrack;					#Connected User Experiences and Telemetry
DisService ConsentUxUserSvc;				#Consent UX User Service
DisService PimIndexMaintenanceSvc;			#Contact Data
DisService DoSvc;					#Delivery Opimization
DisService WdiServiceHost;				#Diagnostic Service Host
DisService TrkWks;					#Distributed Link Tracking Client
DisService dmwappushservice;				#dmwappushservice
DisService MapsBroker;					#Downloaded Maps Manager
DisService BcastDVRUserService;				#Game DVR and Broadcast User Service
DisService lfsvc;					#Geolocation Service
DisService SharedAccess;				#Internet Connection Sharing
DisService lltdsvc;					#Link-Layer Topology Discovery Mapper
DisService CscService;					#Offline Files
DisService defragsvc;					#Optimize drives
DisService PhoneSvc;					#Phone Service
DisService RmSvc;					#Radio Management Service
DisService RemoteAccess;				#Routing and Remote Access
DisService SensorDataService;				#Sensor Data Service
DisService SensrSvc;					#Sensor Monitoring Service
DisService SensorService;				#Sensor Service
DisService SSDPSRV;					#SSDP Discovery
DisService SysMain;					#Superfetch
DisService OneSyncSvc;					#Sync Host
DisService UserDataSvc;					#User Data Access
DisService UnistoreSvc;					#User Data Storage
DisService WalletService;				#WalletService
DisService FrameServer;					#Windows Camera Frame Server
DisService wisvc;					#Windows Insider Service
DisService icssvc;					#Windows Mobile Hotspot Service
DisService WpnService;					#Windows Push Notifications System Service
DisService WpnUserService;				#Windows Push Notifications User Service
DisService XblAuthManager;				#Xbox Live Auth Manager
DisService XblGameSave;					#Xbox Live Game Save
DisService XboxNetApiSvc;				#Xbox Live Networking Service

# Manual Services
ManService BITS;					#Background Intelligent Transfer Service
ManService UsoSvc;					#Update Orchestrator Service for Windows Update
ManService wuauserv;					#Windows Update

# Scheduled Tasks
# https://learn.microsoft.com/en-us/previous-versions/windows-server/it-pro/windows-server-2019/remote/remote-desktop-services/rds-vdi-recommendations-2004#scheduled-tasks
write-host "Disabling Tasks"
DisTask MNO;						# Mobile broadband account experience metadata parser
DisTask AnalyzeSystem;					# This task analyzes the system looking for conditions that may cause high energy use
DisTask Cellular;					# Related to cellular devices
DisTask Compatibility;					# Collects program telemetry information if opted-in to the Microsoft Customer Experience Improvement Program.
DisTask Consolidator;					# If the user has consented to participate in the Windows Customer Experience Improvement Program, this job collects and sends usage data to Microsoft
DisTask Diagnostics;					# DiskFootprint is the combined contribution of all processes that issue storage I/O in the form of storage reads, writes, and flushes.
DisTask FamilySafetyMonitor;				# Initializes Family Safety monitoring and enforcement.
DisTask FamilySafetyRefreshTask;			# Synchronizes the latest settings with the Microsoft family features service.
DisTask MapsToastTask;					# This task shows various Map-related toasts
DisTask Microsoft-Windows-DiskDiagnosticDataCollector;	# The Windows Disk Diagnostic reports general disk and system information to Microsoft for users participating in the Customer Experience Program.
DisTask NotificationTask;				# Background task for performing per user and web interactions
DisTask ProcessMemoryDiagnosticEvents;			# Schedules a memory diagnostic in response to system events
DisTask Proxy;						# This task collects and uploads autochk SQM data if opted-in to the Microsoft Customer Experience Improvement Program.
DisTask QueueReporting;					# Windows Error Reporting task to process queued reports.
DisTask RecommendedTroubleshootingScanner;		# Check for recommended troubleshooting from Microsoft
DisTask RegIdleBackup;					# Registry Idle Backup Task
DisTask RunFullMemoryDiagnostic;			# Detects and mitigates problems in physical memory
DisTask Scheduled;					# The Windows Scheduled Maintenance Task performs periodic maintenance of the computer system by fixing problems automatically or reporting them through Security and Maintenance.
DisTask "Scheduled Scan";
DisTask ScheduledDefrag;				# This task optimizes local storage drives.
DisTask SilentCleanup;					# Maintenance task used by the system to launch a silent auto disk cleanup when running low on free disk space.
DisTask SpeechModelDownloadTask;	
DisTask Sqm-Tasks;					# This task gathers information about the Trusted Platform Module, Secure Boot, and Measured Boot.
DisTask SR;						# This task creates regular system protection points.
DisTask StartComponentCleanup;				# Servicing task that may be better performed during maintenance windows
DisTask StartupAppTask;					# Scans startup entries and raises notification to the user if there are too many startup entries.
DisTask SyspartRepair;	
DisTask USO_UxBroker;
DisTask UpdateLibrary;
DisTask WindowsActionDialog;				# Location Notification
DisTask WinSAT;						# Measures a systems performance and capabilities
DisTask XblGameSaveTask;				# Xbox Live GameSave standby task


# Local Policy Settings
# https://learn.microsoft.com/en-us/previous-versions/windows-server/it-pro/windows-server-2019/remote/remote-desktop-services/rds-vdi-recommendations#group-policy-settings
write-host "Enabling Local Policy Settings"

REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\OneDrive" /v PreventNetworkTrafficPreUserSignIn /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutoRun /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoPublishingWizard /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoOnlinePrintsWizard /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoInternetOpenWith /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v AllowOnlineTips /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\WAU" /v Disabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\MobilityCenter" /v NoMobilityCenter /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableFirstLogonAnimation /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v AllowLinguisticDataCollection /t REG_DWORD /d 0 /f

REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Assistance\Client\1.0" /v NoActiveHelp /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\EventViewer" /v MicrosoftEventVwrDisableLinks /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FindMyDevice" /v AllowFindMyDevice /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Messenger\Client" /v CEIP /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\MicrosoftEdge\Main" /v PreventFirstRunPage /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PCHealth\HelpSvc" /v Headlines /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PCHealth\HelpSvc" /v MicrosoftKBSearch /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PCHealth\ErrorReporting" /v DoReport /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\PeerDist\Service" /v Enable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\policies\Microsoft\Peernet" /v Disabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SearchCompanion" /v DisableContentFileUpdates /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\SQMClient\Windows" /v CEIPEnable /t REG_DWORD /d 0 /f

REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsGetDiagnosticInfo /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessLocation /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessMotion /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessNotifications /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoice /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsActivateWithVoiceAboveLock /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsAccessRadios /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS" /v DisableBranchCache /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS" /v DisablePeerCachingClient /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS" /v DisablePeerCachingServer /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\BITS" /v EnablePeercaching /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v NoCloudApplicationNotification /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSendRequestAdditionalSoftwareToWER /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableBalloonTips /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Setting" /v DisableSendGenericDriverNotFoundToWER /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DeviceInstall\Settings" /v DisableSystemRestore /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DriverSearching" /v DontSearchWindowsUpdate /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v DisallowFlip3d /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v DisallowAnimations /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\DWM" /v DisableAccentGradient /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Explorer" /v NoNewAppAlert /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EdgeUI" /v AllowEdgeSwipe /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\EdgeUI" /v DisableHelpSticker /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameUX" /v DownloadGameInfo /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameUX" /v GameUpdateOptions /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\GameUX" /v ListRecentlyPlayed /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingErrorReports /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HomeGroup" /v DisableHomeGroup /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\HotspotAuthentication" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Internet Connection Wizard" /v ExitOnMSICW /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer" /v LimitSystemRestoreCheckpointing /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocation /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableLocationScripting /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableSensors /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\LocationAndSensors" /v DisableWindowsLocationProvider /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Maps" /v AutoDownloadAndUpdateMapData /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Maps" /v AllowUntriggeredNetworkTrafficOnSettingsPage /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer" /v GroupPrivacyAcceptance /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMediaPlayer" /v PreventLibrarySharing /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMovieMaker" /v WebHelp /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMovieMaker" /v PreventHandwritingDataSharing /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsMovieMaker" /v WebPublish /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetCache" /v Enabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v DisablePassivePolling /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\OOBE" /v DisablePrivacyExperience /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds" /v EnableConfigFlighting /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PreviewBuilds" /v AllowBuildPreview /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Registration Wizard Control" /v NoRegistration /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Reliability Analysis\WMI" /v WMIEnable /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScheduledDiagnostics" /v EnabledExecution /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnostics" /v EnableDiagnostics /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v EnableQueryRemoteServer /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v DisableLockScreenAppNotifications /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v DisableAcrylicBackgroundOnLogon /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\TCPIP\v6Transition" /v Teredo_State /t REG_SZ /d Disabled /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{eb73b633-3f4e-4ba0-8f60-8f3c6f53168f}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{3af8b24a-c441-4fa4-8c5c-bed591bfa867}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{2698178D-FDAD-40AE-9D3C-1371703ADC5B}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WDI\{a7a5847a-7511-4e4e-90b1-45ad2a002f51}" /v ScenarioExecutionEnabled /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v AutoApproveOSDumps /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortanaAboveLock /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v AllowSearchToUseLocation /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v DisableWebSearch /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v ConnectedSearchUseWeb /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v HideUNCTab /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Windows Search" /v PreventIndexingOfflineFiles /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows Mail" /v DisableCommunities /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\SystemRestore" /v DisableSR /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\WindowsStore" /v DisableOSUpgrade /t REG_DWORD /d 1 /f

REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Policies" /v NtfsDisable8dot3NameCreation /t REG_DWORD /d 3 /f


# disable hibernation
# https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
write-host "Disable Hibernation"
powercfg -h off

# disable checkdisk
# https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/chkntfs
chkntfs /X C:

# set wsus to manual
# prevents unexpected updates https://learn.microsoft.com/en-us/windows/deployment/update/waas-wu-settings
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 1 /f

# autoendtasks
REG ADD "HKEY_USERS\.DEFAULT\Control Panel\Desktop" /v AutoEndTasks /t REG_SZ /d 1 /f

# disable ipv6
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-ipv6-in-windows
reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f

# disable task offload
# https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-registry-values-to-enable-and-disable-task-offloading
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v DisableTaskOffload /t REG_DWORD /d 1 /f

# disable machine password changes
# https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/disable-machine-account-password
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v DisablePasswordChange /t REG_DWORD /d 1 /f

# windows firewall - remote management
write-host "Enabling core firewall rules"
get-NetFirewallRule -DisplayGroup "File and Printer Sharing"  -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Desktop Services" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Assistance" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Event Log Management" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Scheduled Tasks Management" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Service Management" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Remote Volume Management" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Windows Management Instrumentation*" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
get-NetFirewallRule -DisplayGroup "Windows Remote Management" -ErrorAction SilentlyContinue | where-object {$_.Profile -like "*Domain*"} | Set-NetFirewallRule -Action Allow -Enabled True
# https://support.microsoft.com/en-us/topic/january-23-2020-kb4534307-os-build-14393-3474-b181594e-2c6a-14ea-e75b-678efea9d27e
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" /v "DeleteUserAppContainersOnLogoff" /t REG_DWORD /d 1 /f
# remove accumulated user firewall rules
# Get-NetFirewallRule | Where-Object {$_.Owner.length -ne 0} | Remove-NetFirewallRule -ErrorAction SilentlyContinue -Confirm:$False

write-host "Disabling Updaters and Maintenance Tasks"
# Disable Edge Updaters
	Get-Service -name edgeupdate,edgeupdatem,MicrosoftEdgeElevationService | Set-Service -StartupType Disabled | stop-service -force
	$tasks=Get-ScheduledTask -TaskName MicrosoftEdgeUp* -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable Chrome Updaters
	Get-Service -Name GoogleUpdate*,GoogleChrome* | Set-Service -StartupType Disabled | Stop-Service -Force
	$tasks=Get-ScheduledTask -TaskName GoogleUpdate* -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Disable OneDrive Updater
	$tasks=Get-ScheduledTask -TaskName OneDrive* -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}
	Get-Service -Name "OneDrive Updater Service" | Set-service -startuptype Disabled

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

$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\.Net Framework\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Bitlocker
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\BitLocker\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Bluetooth
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Bluetooth\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# checkdisk
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Chkdsk\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# CEIP
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Data Integrity
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Data Integrity Scan\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# TPM
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false -ErrorAction SilentlyContinue}

# Emtpy Recycle Bin
	Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Clear Branch Cache
	Clear-BCCache -Force -ErrorAction SilentlyContinue

write-host "Reset Windows Search"
# Reset Windows Search
	Get-Service -ServiceName wsearch | Set-Service -StartupType Disabled
	Stop-Service -ServiceName wsearch -Force
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f
	Remove-Item -Path "$env:ProgramData\Microsoft\Search\Data\" -Recurse -Force  -ErrorAction Ignore
	Get-Service -ServiceName wsearch | Set-Service -StartupType Automatic

write-host "Remove Azure logs and extensions"
# Remove Azure Logs and Extensions
	Remove-Item -Path C:\Packages\ -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\WindowsAzure\Logs -Recurse -Force -ErrorAction Ignore

# empty folders
	Stop-Service -ServiceName wuauserv,bits,msiserver -Force
	Remove-Item -Path C:\Windows\SoftwareDistribution -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\Panther -Recurse -Force -ErrorAction Ignore

# configure and clear event logs
# configure and clear event logs
	wevtutil sl Application /rt:false /ms:67108864
	wevtutil sl System /rt:false /ms:67108864
	wevtutil sl Security /rt:false /ms:67108864
	wevtutil sl Microsoft-FSLogix-Apps/Operational /rt:false /ms:67108864
	wevtutil cl Application
	wevtutil cl System
	wevtutil cl Security
	wevtutil cl Microsoft-FSLogix-Apps/Operational



Write-Host "AVD-Optimise Finished"

