# Chawn Limited 2026
# AVD-EntraReg.ps1
# Version 2.0
# Registers Active Directory joined computers as Entra Hybrid joined devices
# Optionally joins MDM / Intune

$ProgressPreference ="SilentlyContinue"
$Logfile = "AVD-EntraReg.log"

Function LogWrite
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

Function CheckEntraID
{
	try {
		$dsregStatus = dsregcmd /status 2>$null
		if (-not $dsregStatus) {
			logwrite ("EntraJoined: NO")
		}
		# Parse AzureAdJoined and DomainJoined values
		$Global:IsEntraJoined = ($dsregStatus | Select-String "AzureAdJoined\s*:\s*(YES|NO)").Matches.Groups[1].Value
		logwrite ("EntraJoined: " + $IsEntraJoined)
	} 
catch {Logwrite("Failed to get Entra Join Status")}
}

Function CheckMDM
{
	try {
		$Global:JoinMDM=(Get-ScheduledTask -TaskPath '\Microsoft\Windows\EnterpriseMgmt\' -ErrorAction SilentlyContinue)
	}
	catch {Logwrite("Failed to find MDM Task")}
}

Function JoinMDM
{
	try{
		# Device Management Wireless Application Protocol (WAP) Push message Routing Service
		Set-Service -Name dmwappushservice -StartupType Manual -ErrorAction SilentlyContinue
		# Declared Configuration(DC) service
		Set-Service -Name dcsvc -StartupType Manual -ErrorAction SilentlyContinue
		$key = 'SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\*'
		$keyinfo = Get-Item "HKLM:$key"
		$url = $keyinfo.name.Split("\")[-1]
		$path = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo\$url"
		New-ItemProperty -LiteralPath $path -Name 'MdmEnrollmentUrl' -Value 'https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc' -PropertyType String -Force -ErrorAction SilentlyContinue
		New-ItemProperty -LiteralPath $path -Name 'MdmTermsOfUseUrl' -Value 'https://portal.manage.microsoft.com/TermsofUse.aspx' -PropertyType String -Force -ErrorAction SilentlyContinue
		New-ItemProperty -LiteralPath $path -Name 'MdmComplianceUrl' -Value 'https://portal.manage.microsoft.com/?portalAction=Compliance' -PropertyType String -Force -ErrorAction SilentlyContinue
		Start-ScheduledTask -InputObject $JoinMDM
		LogWrite("MDM join complete.")
	}
	catch {Logwrite("JoinMDM exited with error code: "+ $_.Exception.Message)}
}	


Logwrite("Starting Up")
CheckEntraID
CheckMDM

%{
	try {
		$i=0
		Do{if($IsEntraJoined -eq "YES"){LogWrite("Already Entra joined. Exit.");exit 0};$i++; $Proc=Start-Process -FilePath dsregcmd.exe -ArgumentList '$(Arg0) $(Arg1) $(Arg2) /Debug' -RedirectStandardOutput AVD-EntraJoin.log -Wait -Passthru; LogWrite("Attempt:" + $i + " - DSRegCmd completed with exit code: " + $Proc.exitcode);CheckEntraID;if($IsEntraJoined -eq "YES"){break};Start-sleep -seconds 90} until ($IsEntraJoined -eq "YES" -or $i -eq 20)

		if ($IsEntraJoined -eq "NO") {LogWrite("AVDEntraReg has NOT joined Entra after " + $i + " attempts.");exit 9999}
		else {LogWrite("AVDEntraReg has joined Entra after " + $i + " attempts. Job completed.");}
		
		if ($JoinMDM) {start-sleep -seconds 15;LogWrite("Joining MDM");JoinMDM;}
	}
	catch {Logwrite("AVD-EntraReg has exited with error code: "+ $_.Exception.Message)}
}
