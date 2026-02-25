# Chawn Limited 2026
# AVD-EntraReg.ps1
# Version 1.0
# Registers Active Directory joined computers as Entra Hybrid joined devices

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
catch {}
}

Logwrite("Starting Up")

	$i=0

	Do{$i++; Start-sleep -seconds 90; $Proc=Start-Process -FilePath dsregcmd.exe -ArgumentList '$(Arg0) $(Arg1) $(Arg2) /Debug' -RedirectStandardOutput AVD-EntraJoin.log -Wait -Passthru; LogWrite("Attempt:" + $i + " - DSRegCmd completed with exit code: " + $Proc.exitcode);CheckEntraID} until ($IsEntraJoined -eq "YES" -or $i -eq 20)

	if ($IsEntraJoined -eq "No") {LogWrite("AVDEntraReg has NOT joined Entra after " + $i + " attempts.");exit 9999}
	else {LogWrite("AVDEntraReg has joined Entra after " + $i + " attempts.");exit 0}