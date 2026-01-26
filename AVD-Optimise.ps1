# Chawn Limited 2026
# AVD-Optimise.ps1
# Version 4.0
# Implements know optimisations for AVD Session Hosts
# https://learn.microsoft.com/en-us/previous-versions/windows-server/it-pro/windows-server-2019/remote/remote-desktop-services/rds-vdi-recommendations
# Update services and Maintenance tasks are disabled
# Core Domain firewall rules are enabled.
# Microsoft recommended policy settings are implemented
# Windows updates are set to manual
# Remove Ghost Hardware
# IPv6


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

Function MPExclude {
Param ([string]$file)
try	{
		Add-MpPreference -ExclusionPath $file
		if ($file.EndsWith('.exe')) {Add-MpPreference -ExclusionProcess $file}
	}
catch{}
}

Function StopEtwTrace{
Param ([string]$trace)
try{
	Stop-EtwTraceSession -Name $trace -ErrorAction SilentlyContinue
	}
catch{}	
}

Function StopTrace{
Param ([string]$trace)
try{
	reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\WMI\Autologger\$trace /v "Start" /t REG_DWORD /d "0" /f
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
# https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration
write-host "Disabling Services"
DisService .Net*;					#.NET Framework NGEN
DisService AJRouter;					#AllJoyn Router Service
DisService tzautoupdate;				#Auto Time Zone Updater
DisService bthserv;					#Bluetooth Support Service
DisService BluetoothUserService;			#Bluetooth User Support Service
DisService PeerDistSvc;					#BranchCache
# CDPUserSvc;						#CDPUserSvc leave enabled due to profile load issues
DisService DiagSvc					#Diagnostic Execution Service
DisService DiagTrack;					#Connected User Experiences and Telemetry
DisService DPS							#Diagnostic Policy Service
DisService DUSMSvc					#Data Usage service
DisService InstallService			#Microsoft Store Install Service
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
DisService WerSvc					#Windows Error Reporting
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
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v AutoDownload /t REG_DWORD /d 2 /f

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v DisableStartupSound /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\EditionOverrides" /v UserSetting_DisableStartupSound /t REG_DWORD /d 1 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v EnableLogonScriptDelay /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\System" /v CompatibleRUPSecurity /t REG_DWORD /d 1 /f

# disable hibernation
# https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/powercfg-command-line-options
write-host "Disable Hibernation"
powercfg -h off

# set power to high performance
write-host "High Performance Power"
powercfg /setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

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
# reg add "HKLM\SYSTEM\CurrentControlSet\Services\tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0xff /f


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
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Disable Chrome Updaters
	Get-Service -Name GoogleUpdate*,GoogleChrome* | Set-Service -StartupType Disabled | Stop-Service -Force
	$tasks=Get-ScheduledTask -TaskName GoogleUpdate* -ErrorAction SilentlyContinue
		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Disable OneDrive Updater
	$tasks=Get-ScheduledTask -TaskName OneDrive* -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}
	Get-Service -Name "OneDrive Updater Service" | Set-service -startuptype Disabled

# Disable Office Updaters
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Office\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Disable Windows Update tasks
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\UpdateOrchestrator\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\WindowsUpdate\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}
	
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\HotPatch\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\InstallService\ -ErrorAction SilentlyContinue	
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Disable Windows Medic
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\WaaSMedic\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Disable Windows Maintenance
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\TaskScheduler\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\Servicing\ -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}
	set-ItemProperty -Path 'HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance'-Name 'MaintenanceDisabled' -Value 1 -Force -ErrorAction SilentlyContinue

$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\.Net Framework\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Bluetooth
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Bluetooth\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# checkdisk
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Chkdsk\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# CEIP
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Customer Experience Improvement Program\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Data Integrity
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\Data Integrity Scan\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# WLAN
$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\WLANSvc\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}
	$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\NLASvc\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}
	$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\WCM\" -ErrorAction SilentlyContinue
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Memory Diagnostics
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\MemoryDiagnostic\ -ErrorAction SilentlyContinue	
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Application Experience
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\Application Experience\ -ErrorAction SilentlyContinue	
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Feedback
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\Feedback\Siuf\ -ErrorAction SilentlyContinue	
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Ras
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\Ras\ -ErrorAction SilentlyContinue	
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Recovery
	$tasks=Get-ScheduledTask -TaskPath \Microsoft\Windows\RecoveryEnvironment\ -ErrorAction SilentlyContinue	
	foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# TPM
#$tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\TPM\" -ErrorAction SilentlyContinue
#		foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}

# Disable Bitlocker
Function noBDE {
	manage-bde -off C:
 	manage-bde -off D:
	reg delete "HKEY_CLASSES_ROOT\Drive\shell\decrypt-bde" /f
	reg delete "HKEY_CLASSES_ROOT\Drive\shell\encrypt-bde-elev" /f
    New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\BitLocker" -Name "PreventDeviceEncryption" -Value 1 -Force -ErrorAction SilentlyContinue
    $tasks=Get-ScheduledTask -TaskPath "\Microsoft\Windows\BitLocker\" -ErrorAction SilentlyContinue
    foreach ($task in $tasks) {Unregister-ScheduledTask -TaskName $task.TaskName -Confirm:$false  -ErrorAction SilentlyContinue}
}
# UnComment to enable
# noBDE

# Restore Classic Context Menus
# UnComment to enable - you need to take ownership of the registry key and assign FC to Administrators manually
#	reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}" /f

# improve Startup / restart time - this is set to 30 by DEFAULT
bcdedit /timeout 1

# Remove Ghost Hardware
$devs=Get-PnpDevice -class Diskdrive,Display,Monitor,Mouse,Net,Ports,Processor,PrintQueue,SCSIAdapter,SoftwareDevice,Volume -ErrorAction Ignore | ? status -eq unknown
	foreach ($d in $devs) 	{
 	&"pnputil" /remove-device $d.InstanceId
				}


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

# Stop Event Traces
StopTrace Cellcore
StopTrace CloudExperienceHostOOBE
StopTrace DiagLog
StopTrace RadioMgr
StopTrace ReadyBoot
StopTrace WDIContextLog
StopTrace WiFiDriverIHVSession
StopTrace WiFiSession
StopTrace WinPhoneCritical
StopEtwTrace DiagLog
StopEtwTrace RadioMgr
StopEtwTrace ReadyBoot
StopEtwTrace WiFiSession


# Add Defender Exclusions
Copy-Item -Path C:\Windows\system32\robocopy.exe -Destination "C:\Program Files\FSLogix\Apps\frxrobocopy.exe" -Force
New-Item -Path "C:\Program Files\FSLogix\Apps\en-US" -type directory -force
Copy-Item -Path C:\Windows\system32\en-US\robocopy.exe.mui -Destination "C:\Program Files\FSLogix\Apps\en-US\frxrobocopy.exe.mui" -Force
mpexclude C:\WindowsAzure\GuestAgent_*\CollectGuestLogs.exe
mpexclude C:\WindowsAzure\GuestAgent_*\CollectVMHealth.exe
mpexclude C:\WindowsAzure\GuestAgent_*\WaAppAgent.exe
mpexclude C:\WindowsAzure\GuestAgent_*\WaSecAgentProv.exe
mpexclude C:\WindowsAzure\GuestAgent_*\WindowsAzureGuestAgent.exe
mpexclude C:\Windows\System32\spoolsv.exe
mpexclude C:\Windows\System32\Winevt\Logs
mpexclude C:\Windows\System32\Winevt\EventLogs
mpexclude C:\Windows\SoftwareDistribution
mpexclude C:\Packages
mpexclude "C:\Program Files\FSLogix\Apps\frxsvc.exe"
mpexclude "C:\Program Files\FSLogix\Apps\frxccds.exe"
mpexclude "C:\Program Files\FSLogix\Apps\FRXRobocopy.exe"
mpexclude "C:\Program Files\Remote Desktop WebRTC Redirector\MsRdcWebRTCSvc.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\*\BootloaderUpdater.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\*\RDAgentBootLoader.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\*\WvdLauncher\RDMonitoringAgentLauncher.exe"
mpexclude "C:\Source\*.msi"
mpexclude "C:\Program Files\Microsoft RDInfra\*.msi"
mpexclude "C:\Program Files\Microsoft RDInfra\RDMonitoringAgent_*\WvdLauncher\RDMonitoringAgentLauncher.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\RDMonitoringAgent_*\Agent\MonAgentClient.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\RDMonitoringAgent_*\Agent\MonAgentCore.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\RDMonitoringAgent_*\Agent\MonAgentHost.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\RDMonitoringAgent_*\Agent\MonAgentLauncher.exe"
mpexclude "C:\Program Files\Microsoft RDInfra\RDMonitoringAgent_*\Agent\MonAgentManager.exe"


# Set page File to Memory Size
function SetPageFile{
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



# Emtpy Recycle Bin
	Clear-RecycleBin -Force -ErrorAction SilentlyContinue

# Clear Branch Cache
	Clear-BCCache -Force -ErrorAction SilentlyContinue

write-host "Reset Windows Search"
# Reset Windows Search
	Get-Service -ServiceName wsearch | Set-Service -StartupType Disabled
	Stop-Service -ServiceName wsearch
	REG ADD "HKLM\SOFTWARE\Microsoft\Windows Search" /v SetupCompletedSuccessfully /t REG_DWORD /d 0 /f
	Remove-Item -Path "$env:ProgramData\Microsoft\Search\Data\" -Recurse -Force  -ErrorAction Ignore
	Get-Service -ServiceName wsearch | Set-Service -StartupType Automatic

write-host "Remove Azure logs and extensions"
# Remove Azure Logs and Extensions
	Remove-Item -Path C:\Packages\ -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\WindowsAzure\Logs -Recurse -Force -ErrorAction Ignore

# empty folders
	Stop-Service -ServiceName wuauserv,bits,msiserver
	Remove-Item -Path C:\Windows\SoftwareDistribution -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path C:\Windows\Panther -Recurse -Force -ErrorAction Ignore
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\Temp\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportArchive\* -Recurse -Force -ErrorAction SilentlyContinue
	Remove-Item -Path $env:ProgramData\Microsoft\Windows\WER\ReportQueue\* -Recurse -Force -ErrorAction SilentlyContinue

# Run Cleanmgr
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Delivery Optimization Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Feedback Hub Archive log files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Internet Cache Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Language Pack" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender" /v StateFlags0001 /t REG_DWORD /d 2 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files" /v StateFlags0001 /t REG_DWORD /d 2 /f
#CleanMgr can take 10+ minutes
#Start-Process -Wait -FilePath "cleanmgr.exe" -ArgumentList "/sagerun:1"


# configure and clear event logs
	wevtutil sl Application /rt:false /ms:67108864
	wevtutil sl System /rt:false /ms:67108864
	wevtutil sl Security /rt:false /ms:67108864
	wevtutil sl Microsoft-FSLogix-Apps/Operational /rt:false /ms:67108864
	wevtutil cl Application
	wevtutil cl System
	wevtutil cl Security
	wevtutil cl Microsoft-FSLogix-Apps/Operational



Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -force
Write-Host "AVD-Optimise Finished"
