# AVDManage



AVDManage is a Virtual Desktop image management solution for pooled Azure Virtual Desktop Session Hosts which leverages Azure Virtual Machine Scale Sets to deploy and update a common Golden Image to all AVD Session Hosts.



Azure Virtual Desktop Sessions Hosts may be deployed from Generalized or Specialized Master / Golden images.



Scale Sets may be deployed in Uniform or Flexible Orchestration Modes.



When deploying Session Hosts, AVD-Turbo5.ps1 is downloaded and executed on the Virtual Machine to join Active Directory or Entra ID, and optionally join an Azure Virtual Desktop Host Pool.



The following scripts are supported with AVDManage 2.5.0.0 +



### AVD-Turbo5.ps1

Runs on Specialized Images (no sysprep) and Generalized Images (sysprepped)

* Renames the computer to match the Virtual Machine name (Specialized Image)
* Joins Active Directory (+ Hybrid Entra Join) or Joins Entra ID
* Downloads Microsoft Remote Desktop Broker and Boot Agents
* Retrieves / Generates an AVD Host Pool Token using secretless authentication (Session Hosts inherit a User-Assigned Managed Identity)
* Installs Microsoft Agents and joins the AVD host pool



### AVD-Entrareg.ps1

If the Scale Set is configured to join Active Directory, AVD-EntraReg.ps1 is downloaded with AVD-Turbo5.ps1. AVD-Turbo will create a Scheduled Task to Hybrid Join Entra on the next system restart.



### AVD-Prep.ps1

Downloads and pre-installs the Microsoft Remote Desktop Broker and Boot Agents on a Master / Golden image. Does not join the AVD Host Pool.

This allows AVD-Join and AVD-Turbo to complete 30-40 seconds faster when deploying or updating a Session Host, as the agents do not have to be downloaded and installed.



### AVD-Update.ps1

Updates Windows and primary software on the Master / Golden image.



### AVD-PostUpdate.ps1

Runs maintenance tasks following updates to the Master / Golden image.



### AVD-Optimise.ps1

Applies known optimisations to the Master / Golden image.



### AVD-Seal.ps1

Finalizes and prepares a Generalized Master / Golden image and executes sysprep before image creation.



### AVD-Seal-Special.ps1

Finalizes and prepares a Specialized Master / Golden image before image creation.



### Task Scripts

Template scripts to automate management tasks using AVD-Automate (Automation Account).

* Task-DisableLogons-SSAVD.ps1 - Disables logons on session hosts in Scale Set
* Task-EnableLogons-SSAVD.ps1  - Enables logons on session hosts in Scale Set
* Task-LogOffSessions-SSAVD.ps1 - Logs users out of session hosts in Scale Set
* Task-ReDeploy-SS.ps1 - Redeploys session hosts to a different Azure host
* Task-ReImage-SS.ps1 - Reimages session hosts with the current image
* Task-Restart-SS.ps1 - Restarts session hosts
* Task-Start-SS.ps1 - Starts session hosts
* Task-Stop-SS.ps1 - Stops session hosts
* Task-Update-SS.ps1 - Updates session hosts to the latest image/config
