# AVDManage



AVDManage is a Virtual Desktop image management solution for pooled Azure Virtual Desktop Session Hosts.



Azure Virtual Desktop Sessions Hosts may be deployed from Generalized or Specialized Master / Golden images.



When deploying Session Hosts, AVD-Join3.ps1 and AVD-Turbo3.ps1 are downloaded and executed on the Virtual Machine to join Active Directory and the Azure Virtual Desktop Host Pool.



### AVD-Join3.ps1

Runs on Generalized Images (sysprepped) / Device is pre-joined to Active Directory using JSonADDomainExtension

* Validates the device is AD Joined
* Downloads Microsoft Remote Desktop Broker and Boot Agents
* Retrieves / Generates an AVD Host Pool Token using secretless authentication
* Installs Microsoft Agents and joins the AVD host pool



### AVD-Turbo3.ps1

Runs on Specialized Images (no sysprep)

* Renames the computer to match the Virtual Machine name
* Joins Active Directory
* Downloads Microsoft Remote Desktop Broker and Boot Agents
* Retrieves / Generates an AVD Host Pool Token using secretless authentication
* Installs Microsoft Agents and joins the AVD host pool



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





