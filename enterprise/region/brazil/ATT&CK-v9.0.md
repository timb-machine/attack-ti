threat-crank.py 0.2.1
I: searching for regions that match .* brazil.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v9.0/enterprise-attack/enterprise-attack.json
# Threat groups

* UNC2452

# Validate the following attacks

* Account Discovery - 1
* Additional Cloud Credentials - 1
* Archive via Utility - 1
* Code Signing - 1
* Compromise Software Supply Chain - 1
* Credentials from Password Stores - 1
* DCSync - 1
* Data from Local System - 1
* Deobfuscate/Decode Files or Information - 1
* Disable Windows Event Logging - 1
* Disable or Modify System Firewall - 1
* Disable or Modify Tools - 1
* Domain Trust Discovery - 1
* Domain Trust Modification - 1
* Domains - 2
* Dynamic Resolution - 1
* Exchange Email Delegate Permissions - 1
* Exfiltration Over Asymmetric Encrypted Non-C2 Protocol - 1
* Exploit Public-Facing Application - 1
* External Remote Services - 1
* File Deletion - 1
* File and Directory Discovery - 1
* Indicator Removal on Host - 1
* Ingress Tool Transfer - 1
* Internal Proxy - 1
* Internet Connection Discovery - 1
* Kerberoasting - 1
* Malware - 1
* Masquerade Task or Service - 1
* Masquerading - 1
* Match Legitimate Name or Location - 1
* Obfuscated Files or Information - 1
* Permission Groups Discovery - 1
* PowerShell - 1
* Private Keys - 1
* Process Discovery - 1
* Remote Data Staging - 1
* Remote Email Collection - 1
* Remote System Discovery - 1
* Rundll32 - 1
* SAML Tokens - 1
* Scheduled Task - 1
* System Information Discovery - 1
* Timestomp - 1
* Use Alternate Authentication Material - 1
* Valid Accounts - 1
* Web Cookies - 1
* Web Protocols - 1
* Web Session Cookie - 1
* Windows Command Shell - 1
* Windows Management Instrumentation - 1
* Windows Management Instrumentation Event Subscription - 1
* Windows Remote Management - 1

# Validate the following phases

* collection - 4
* command-and-control - 4
* credential-access - 6
* defense-evasion - 17
* discovery - 8
* execution - 4
* exfiltration - 1
* initial-access - 4
* lateral-movement - 3
* persistence - 6
* privilege-escalation - 4
* resource-development - 3

# Validate the following platforms

* Azure AD - 6
* Containers - 7
* Google Workspace - 7
* IaaS - 8
* Linux - 32
* Network - 1
* Office 365 - 8
* PRE - 3
* SaaS - 7
* Windows - 58
* macOS - 31

# Validate the following defences

* Anti-virus - 5
* Application control - 3
* Application control by file name or path - 3
* Digital Certificate Validation - 1
* File monitoring - 1
* Firewall - 2
* Host forensic analysis - 3
* Host intrusion prevention systems - 5
* Log analysis - 4
* Network intrusion detection system - 2
* Signature-based detection - 3
* System Access Controls - 2
* System access controls - 1
* Windows User Account Control - 1

# Validate the following data sources

* Active Directory: Active Directory Credential Request - 2
* Active Directory: Active Directory Object Access - 1
* Active Directory: Active Directory Object Creation - 1
* Active Directory: Active Directory Object Modification - 2
* Application Log: Application Log Content - 5
* Command: Command Execution - 32
* File: File Access - 7
* File: File Content - 1
* File: File Creation - 4
* File: File Deletion - 2
* File: File Metadata - 6
* File: File Modification - 5
* Firewall: Firewall Disable - 1
* Firewall: Firewall Rule Modification - 1
* Group: Group Enumeration - 1
* Group: Group Metadata - 1
* Group: Group Modification - 1
* Image: Image Metadata - 2
* Instance: Instance Metadata - 1
* Logon Session: Logon Session Creation - 6
* Logon Session: Logon Session Metadata - 1
* Module: Module Load - 2
* Network Traffic: Network Connection Creation - 8
* Network Traffic: Network Traffic Content - 8
* Network Traffic: Network Traffic Flow - 7
* Process: OS API Execution - 6
* Process: Process Access - 1
* Process: Process Creation - 20
* Process: Process Metadata - 2
* Process: Process Termination - 1
* Scheduled Job: Scheduled Job Creation - 1
* Scheduled Job: Scheduled Job Metadata - 2
* Scheduled Job: Scheduled Job Modification - 2
* Script: Script Execution - 3
* Sensor Health: Host Status - 2
* Service: Service Creation - 2
* Service: Service Metadata - 3
* User Account: User Account Authentication - 3
* User Account: User Account Metadata - 1
* User Account: User Account Modification - 2
* WMI: WMI Creation - 1
* Web Credential: Web Credential Creation - 2
* Web Credential: Web Credential Usage - 4
* Windows Registry: Windows Registry Key Deletion - 2
* Windows Registry: Windows Registry Key Modification - 3

# Review the following attack references

* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html - Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://msdn.microsoft.com/en-us/library/aa384426 - Microsoft. (n.d.). Windows Remote Management. Retrieved November 12, 2014.
* http://pages.endgame.com/rs/627-YBU-612/images/EndgameJournal_The%20Masquerade%20Ball_Pages_R2.pdf - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://windowsir.blogspot.com/2013/07/howto-determinedetect-use-of-anti.html - Carvey, H. (2013, July 23). HowTo: Determine/Detect the use of Anti-Forensics Techniques. Retrieved June 3, 2016.
* http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/ - Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* https://adsecurity.org/?p=1588 - Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://adsecurity.org/?p=2293 - Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.
* https://arstechnica.com/information-technology/2014/06/active-malware-operation-let-attackers-sabotage-us-energy-industry/ - Dan Goodin. (2014, June 30). Active malware operation let attackers sabotage US energy industry. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities - Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/ - Lambert, J. (2020, December 13). Important steps for customers to protect themselves from recent nation-state cyberattacks. Retrieved December 17, 2020.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/ - Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/sdk/gcloud/reference/compute/os-login/ssh-keys/add - Google. (n.d.). gcloud compute os-login ssh-keys add. Retrieved October 1, 2020.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://content.fireeye.com/m-trends/rpt-m-trends-2020 - Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.
* https://csrc.nist.gov/glossary/term/Multi_Factor-Authentication - NIST. (n.d.). Multi-Factor Authentication (MFA). Retrieved January 30, 2020.
* https://csrc.nist.gov/glossary/term/authentication - NIST. (n.d.). Authentication. Retrieved January 30, 2020.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/ - Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes - Microsoft. (2020, December 14). Configurable token lifetimes in Microsoft Identity Platform. Retrieved December 22, 2020.
* https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed - Microsoft. (2018, November 28). What is federation with Azure AD?. Retrieved December 30, 2020.
* https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover - Microsoft. (2020, September 29). Prevent dangling DNS entries and avoid subdomain takeover. Retrieved October 12, 2020.
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships - Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/office365/troubleshoot/active-directory/update-federated-domain-office-365 - Microsoft. (2020, September 14). Update or repair the settings of a federated domain in Office 365, Azure, or Intune. Retrieved December 30, 2020.
* https://docs.microsoft.com/en-us/powershell/module/exchange/mailboxes/add-mailboxpermission?view=exchange-ps - Microsoft. (n.d.). Add-Mailbox Permission. Retrieved September 13, 2019.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10) - Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Public-key_cryptography - Wikipedia. (2017, June 29). Public-key cryptography. Retrieved July 5, 2017.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://expel.io/blog/behind-the-scenes-expel-soc-alert-aws/ - S. Lipton, L. Easterly, A. Randazzo and J. Hencinski. (2020, July 28). Behind the scenes in the Expel SOC: Alert-to-fix in AWS. Retrieved October 1, 2020.
* https://expel.io/blog/finding-evil-in-aws/ - A. Randazzo, B. Manahan and S. Lipton. (2020, April 28). Finding Evil in AWS. Retrieved June 25, 2020.
* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml - Microsoft. (2020, December). Azure Sentinel Detections. Retrieved December 30, 2020.
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1 - EmpireProject. (2016, October 31). Invoke-Kerberoast.ps1. Retrieved March 22, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://kasperskycontenthub.com/wp-content/uploads/sites/43/vlpdfs/unveilingthemask_v1.0.pdf - Kaspersky Labs. (2014, February 11). Unveiling “Careto” - The Masked APT. Retrieved July 5, 2017.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://medium.com/threatpunter/detecting-lateral-movement-using-sysmon-and-splunk-318d3be141bc - French, D. (2018, September 30). Detecting Lateral Movement Using Sysmon and Splunk. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/ms677949.aspx - Microsoft. (n.d.). Service Principal Names. Retrieved March 22, 2018.
* https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/ - MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 17, 2020.
* https://nedinthecloud.com/2019/07/16/demystifying-azure-ad-service-principals/ - Bellavance, Ned. (2019, July 16). Demystifying Azure AD Service Principals. Retrieved January 19, 2020.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://redsiege.com/kerberoast-slides - Medin, T. (2014, November). Attacking Kerberos - Kicking the Guard Dog of Hades. Retrieved March 22, 2018.
* https://researchcenter.paloaltonetworks.com/2016/06/unit42-prince-of-persia-game-over/ - Bar, T., Conant, S., Efraim, L. (2016, June 28). Prince of Persia – Game Over. Retrieved July 5, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/ - Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx - Microsoft. (2010, April 13). Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe). Retrieved March 22, 2018.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://speakerdeck.com/tweekfawkes/blue-cloud-of-death-red-teaming-azure-1 - Kunz, Bryce. (2018, May 11). Blue Cloud of Death: Red Teaming Azure. Retrieved October 23, 2019.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/ - Chen, J. et al. (2021, February 3). Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes. Retrieved April 5, 2021.
* https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/ - Chen, Y., Hu, W., Xu, Z., et. al. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa21-008a - CISA. (2021, January 8). Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments. Retrieved January 8, 2021.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://wunderwuzzi23.github.io/blog/passthecookie.html - Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.commandfive.com/papers/C5_APT_SKHack.pdf - Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.
* https://www.crowdstrike.com/blog/hiding-in-plain-sight-using-the-office-365-activities-api-to-investigate-business-email-compromises/ - Crowdstrike. (2018, July 18). Hiding in Plain Sight: Using the Office 365 Activities API to Investigate Business Email Compromises. Retrieved January 19, 2020.
* https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps - Reiner, S. (2017, November 21). Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps. Retrieved December 17, 2020.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html - Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/collateral/en/mtrends-2018.pdf - Mandiant. (2018). Mandiant M-Trends 2018. Retrieved July 9, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/ - Schroeder, W. (2016, November 1). Kerberoasting Without Mimikatz. Retrieved March 23, 2018.
* https://www.icann.org/groups/ssac/documents/sac-007-en - ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.
* https://www.losangeles.va.gov/documents/MI-000120-MW.pdf - Federal Bureau of Investigation, Cyber Division. (2020, March 26). FIN7 Cyber Actors Targeting US Businesses Through USB Keystroke Injection Attacks. Retrieved October 14, 2020.
* https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/ - Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.slideshare.net/DouglasBienstock/shmoocon-2019-becs-and-beyond-investigating-and-defending-office-365 - Bienstock, D.. (2019). BECS and Beyond: Investigating and Defending O365. Retrieved September 13, 2019.
* https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2 - Jacobsen, K. (2014, May 16). Lateral Movement with PowerShell&#91;slides&#93;. Retrieved November 12, 2014.
* https://www.sygnia.co/golden-saml-advisory - Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.
* https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html - Remillano II, A., et al. (2020, June 20). XORDDoS, Kaiji Variants Target Exposed Docker Servers. Retrieved April 5, 2021.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ - Franklin Smith. (n.d.). Windows Security Log Events. Retrieved February 21, 2020.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/ - Cash, D. et al. (2020, December 14). Dark Halo Leverages SolarWinds Compromise to Breach Organizations. Retrieved December 29, 2020.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/ - ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.youtube.com/watch?v=wQ1CuAPnrLM&feature=youtu.be&t=2815 - Kunz, Bruce. (2018, October 14). Blue Cloud of Death: Red Teaming Azure. Retrieved November 21, 2019.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www2.fireeye.com/rs/848-DID-242/images/rpt-apt29-hammertoss.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved September 17, 2015.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* AdFind - 1
* Mimikatz - 1

# Review the following tool references

* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/  - Brian Donohue, Katie Nickels, Paul Michaud, Adina Bodkins, Taylor Chapman, Tony Lambert, Jeff Felling, Kyle Rainey, Mike Haag, Matt Graeber, Aaron Didier.. (2020, October 29). A Bazar start: How one hospital thwarted a Ryuk ransomware outbreak. Retrieved October 30, 2020.
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html - Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html - McKeague, B. et al. (2019, April 5). Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware. Retrieved April 17, 2019.

# Validate the following malware

* Cobalt Strike - 1
* GoldMax - 1
* Raindrop - 1
* SUNBURST - 1
* SUNSPOT - 1
* Sibot - 1
* TEARDROP - 1

# Review the following malware references

* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/ - Sudhakar Ramakrishna . (2021, January 11). New Findings From Our Investigation of SUNBURST. Retrieved January 13, 2021.
* https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware - Symantec Threat Hunter Team. (2021, January 18). Raindrop: New Malware Discovered in SolarWinds Investigation. Retrieved January 19, 2021.
* https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/ - CrowdStrike Intelligence Team. (2021, January 11). SUNSPOT: An Implant in the Build Process. Retrieved January 11, 2021.
* https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html - FireEye. (2020, December 13). Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor. Retrieved January 4, 2021.
* https://www.fireeye.com/blog/threat-research/2021/03/sunshuttle-second-stage-backdoor-targeting-us-based-entity.html - Smith, L., Leathery, J., Read, B. (2021, March 4). New SUNSHUTTLE Second-Stage Backdoor Uncovered Targeting U.S.-Based Entity; Possible Connection to UNC2452. Retrieved March 12, 2021.
* https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/ - MSTIC, CDOC, 365 Defender Research Team. (2021, January 20). Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop . Retrieved January 22, 2021.
* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/ - Nafisi, R., Lelli, A. (2021, March 4). GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM’s layered persistence. Retrieved March 8, 2021.

