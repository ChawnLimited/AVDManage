# Chawn Limited 2025
# AVD-Turbo.ps1
# Version 1.0
# Rename and Join a VM (created from a snapshot) to Active Directory, installs AVD Agents - way quicker than creating VMs from images

#### Parameters

  param(
	[String]$VMName= "",			# New VMName
	[String]$ADDomain= "",			# Set the domain name in FQDN format
	[String]$OU= "",			# Set the Organisational Unit for the VM
	[String]$ADAdmin= "",			# Set the domain join user account
	[String]$ADAdminPW= "",			# Set the domain join user account password
	[String]$HostPool="",			# Set the WVD HostPool name
	[String]$RG="",				# Set the WVD HostPool Resource Group name
	[String]$ClientID = "",			# Set the AVDJoin Client ID
	[String]$ClientSecret = "",		# Set the AVDJoin Client Secret
	[String]$TenantID = ""			# Set the Azure Tenant ID
	)

#### End of Parameters

$Logfile = "TurboAVD.log"

Function LogWrite
{
   Param ([string]$logstring)
	$d1=get-Date
   Add-content $Logfile -value ($d1.tostring() + " : " + $logstring)
}

LogWrite "Starting up"

	if((gwmi win32_computersystem).partofdomain -eq 0) {
	LogWrite ("Renaming Computer to " + $VMName)
	Rename-Computer -NewName $VMName -Force | Out-File -FilePath $Logfile -Append
	$ADDomainCred = New-Object pscredential -ArgumentList ([pscustomobject]@{
	UserName = $ADAdmin
	Password = (ConvertTo-SecureString -String $ADAdminPW -AsPlainText -Force)[0]})

	LogWrite ("Join Domain " + $ADDomain)
	Add-Computer -DomainName $ADDomain -OUPath $ou -Credential $ADDomainCred -Options JoinWithNewName,AccountCreate -Force -PassThru -Verbose | Out-File -FilePath $Logfile -Append
	}

LogWrite "Install RDS Agents "
	$Procargs="-ExecutionPolicy ByPass -NoProfile -File AVDJoin.ps1 " + $HostPool + " " + $RG + " " + $ClientID  + " " + $ClientSecret + " " + $TenantID
	# Start-Process -FilePath "powershell.exe" -ArgumentList $ProcArgs -Wait
LogWrite "Install RDS Agents completed. View JoinWVD.log for details and troubleshooting"

LogWrite "Schedule a restart and exit"
Start-Process -FilePath shutdown.exe -ArgumentList "-r -t 10"
exit 0

