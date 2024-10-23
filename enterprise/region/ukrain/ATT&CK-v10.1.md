threat-crank.py 0.2.1
I: searching for regions that match .* ukrain.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v10.1/enterprise-attack/enterprise-attack.json
# Threat groups

* Gamaredon Group
* Silence
* Stolen Pencil
* UNC2452

# Validate the following attacks

* Account Discovery - 1
* Additional Cloud Credentials - 1
* Archive via Utility - 1
* Automated Collection - 1
* Automated Exfiltration - 1
* Binary Padding - 1
* Browser Extensions - 1
* Code Signing - 2
* Compile After Delivery - 1
* Compiled HTML File - 1
* Component Object Model - 1
* Compromise Software Supply Chain - 1
* Credentials In Files - 1
* Credentials from Password Stores - 1
* Credentials from Web Browsers - 1
* DCSync - 1
* Data from Local System - 2
* Data from Network Shared Drive - 1
* Data from Removable Media - 1
* Deobfuscate/Decode Files or Information - 2
* Disable Windows Event Logging - 1
* Disable or Modify System Firewall - 1
* Disable or Modify Tools - 2
* Domain Trust Discovery - 1
* Domain Trust Modification - 1
* Domains - 2
* Dynamic Resolution - 1
* Exchange Email Delegate Permissions - 1
* Exfiltration Over Asymmetric Encrypted Non-C2 Protocol - 1
* Exfiltration Over C2 Channel - 1
* Exploit Public-Facing Application - 1
* External Proxy - 1
* External Remote Services - 1
* File Deletion - 3
* File and Directory Discovery - 2
* Indicator Removal on Host - 1
* Ingress Tool Transfer - 3
* Internal Proxy - 1
* Internal Spearphishing - 1
* Internet Connection Discovery - 1
* JavaScript - 1
* Kerberoasting - 1
* Keylogging - 1
* LSASS Memory - 2
* Local Accounts - 1
* Malicious File - 2
* Malware - 1
* Masquerade Task or Service - 1
* Masquerading - 1
* Match Legitimate Name or Location - 2
* Modify Registry - 2
* Native API - 2
* Network Sniffing - 1
* Non-Standard Port - 1
* Obfuscated Files or Information - 3
* Office Application Startup - 1
* Peripheral Device Discovery - 1
* Permission Groups Discovery - 1
* PowerShell - 2
* Private Keys - 1
* Process Discovery - 1
* Process Injection - 1
* Registry Run Keys / Startup Folder - 2
* Remote Data Staging - 1
* Remote Desktop Protocol - 2
* Remote Email Collection - 1
* Remote System Discovery - 2
* Rundll32 - 2
* SAML Tokens - 1
* Scheduled Task - 3
* Screen Capture - 2
* Service Execution - 1
* Software Deployment Tools - 1
* Spearphishing Attachment - 2
* Spearphishing Link - 1
* System Information Discovery - 2
* System Owner/User Discovery - 1
* Taint Shared Content - 1
* Template Injection - 1
* Timestomp - 1
* Tool - 1
* Use Alternate Authentication Material - 1
* Valid Accounts - 2
* Video Capture - 1
* Visual Basic - 2
* Web Cookies - 1
* Web Protocols - 2
* Web Service - 1
* Web Session Cookie - 1
* Windows Command Shell - 3
* Windows Management Instrumentation - 1
* Windows Management Instrumentation Event Subscription - 1
* Windows Remote Management - 1

# Validate the following phases

* collection - 12
* command-and-control - 10
* credential-access - 12
* defense-evasion - 35
* discovery - 14
* execution - 19
* exfiltration - 3
* initial-access - 9
* lateral-movement - 8
* persistence - 14
* privilege-escalation - 11
* resource-development - 4

# Validate the following platforms

* Azure AD - 7
* Containers - 13
* Google Workspace - 10
* IaaS - 16
* Linux - 82
* Network - 4
* Office 365 - 13
* PRE - 4
* SaaS - 11
* Windows - 134
* macOS - 86

# Validate the following defences

* Anti-virus - 12
* Application control - 9
* Application control by file name or path - 6
* Binary Analysis - 1
* Digital Certificate Validation - 3
* File monitoring - 2
* Firewall - 3
* Host forensic analysis - 9
* Host intrusion prevention systems - 11
* Log analysis - 7
* Network intrusion detection system - 4
* Signature-based detection - 9
* Static File Analysis - 2
* System Access Controls - 2
* System access controls - 2
* Windows User Account Control - 2

# Validate the following data sources

* Active Directory: Active Directory Credential Request - 2
* Active Directory: Active Directory Object Access - 1
* Active Directory: Active Directory Object Creation - 1
* Active Directory: Active Directory Object Modification - 2
* Application Log: Application Log Content - 13
* Command: Command Execution - 73
* Domain Name: Active DNS - 2
* Domain Name: Domain Registration - 2
* Domain Name: Passive DNS - 2
* Driver: Driver Load - 1
* File: File Access - 16
* File: File Creation - 17
* File: File Deletion - 4
* File: File Metadata - 15
* File: File Modification - 13
* Firewall: Firewall Disable - 1
* Firewall: Firewall Rule Modification - 1
* Group: Group Enumeration - 1
* Group: Group Metadata - 1
* Group: Group Modification - 1
* Image: Image Metadata - 3
* Instance: Instance Metadata - 2
* Logon Session: Logon Session Creation - 10
* Logon Session: Logon Session Metadata - 4
* Malware Repository: Malware Content - 1
* Malware Repository: Malware Metadata - 2
* Module: Module Load - 12
* Network Share: Network Share Access - 2
* Network Traffic: Network Connection Creation - 20
* Network Traffic: Network Traffic Content - 21
* Network Traffic: Network Traffic Flow - 21
* Pod: Pod Metadata - 1
* Process: OS API Execution - 21
* Process: Process Access - 5
* Process: Process Creation - 58
* Process: Process Metadata - 3
* Process: Process Modification - 1
* Process: Process Termination - 2
* Scheduled Job: Scheduled Job Creation - 3
* Scheduled Job: Scheduled Job Metadata - 2
* Scheduled Job: Scheduled Job Modification - 2
* Script: Script Execution - 14
* Sensor Health: Host Status - 3
* Service: Service Creation - 3
* Service: Service Metadata - 5
* User Account: User Account Authentication - 5
* User Account: User Account Metadata - 1
* User Account: User Account Modification - 2
* WMI: WMI Creation - 1
* Web Credential: Web Credential Creation - 2
* Web Credential: Web Credential Usage - 4
* Windows Registry: Windows Registry Key Creation - 7
* Windows Registry: Windows Registry Key Deletion - 5
* Windows Registry: Windows Registry Key Modification - 11

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html - Hawkins, J. (2018, July 18). Executing Macros From a DOCX With Remote Template Injection. Retrieved October 12, 2018.
* http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html - Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html - CG. (2014, May 20). Mimikatz Against Virtual Machine Memory Part 1. Retrieved November 12, 2014.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://msdn.microsoft.com/en-us/library/aa384426 - Microsoft. (n.d.). Windows Remote Management. Retrieved November 12, 2014.
* http://msdn.microsoft.com/en-us/library/ms682425 - Microsoft. (n.d.). CreateProcess function. Retrieved December 5, 2014.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://pages.endgame.com/rs/627-YBU-612/images/EndgameJournal_The%20Masquerade%20Ball_Pages_R2.pdf - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://windowsir.blogspot.com/2013/07/howto-determinedetect-use-of-anti.html - Carvey, H. (2013, July 23). HowTo: Determine/Detect the use of Anti-Forensics Techniques. Retrieved June 3, 2016.
* http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html - stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.
* http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/ - Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.
* https://adsecurity.org/?p=1588 - Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://adsecurity.org/?p=2293 - Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.
* https://arstechnica.com/information-technology/2014/06/active-malware-operation-let-attackers-sabotage-us-energy-industry/ - Dan Goodin. (2014, June 30). Active malware operation let attackers sabotage US energy industry. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities - Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.
* https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/ - Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/ - Segura, J. (2017, October 13). Decoy Microsoft Word document delivers malware through a RAT. Retrieved July 21, 2018.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.talosintelligence.com/2017/07/template-injection.html - Baird, S. et al.. (2017, July 7). Attack on Critical Infrastructure Leverages Template Injection. Retrieved July 21, 2018.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://blog.trendmicro.com/phishing-starts-inside/ - Chris Taylor. (2017, October 5). When Phishing Starts from the Inside. Retrieved October 8, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/ - Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.
* https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* https://blogs.microsoft.com/on-the-issues/2020/12/13/customers-protect-nation-state-cyberattacks/ - Lambert, J. (2020, December 13). Important steps for customers to protect themselves from recent nation-state cyberattacks. Retrieved December 17, 2020.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/ - Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.
* https://blogs.technet.microsoft.com/office365security/defending-against-rules-and-forms-injection/ - Koeller, B.. (2018, February 21). Defending Against Rules and Forms Injection. Retrieved November 5, 2019.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/sdk/gcloud/reference/compute/os-login/ssh-keys/add - Google. (n.d.). gcloud compute os-login ssh-keys add. Retrieved October 1, 2020.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://content.fireeye.com/m-trends/rpt-m-trends-2020 - Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.
* https://csrc.nist.gov/glossary/term/Multi_Factor-Authentication - NIST. (n.d.). Multi-Factor Authentication (MFA). Retrieved January 30, 2020.
* https://csrc.nist.gov/glossary/term/authentication - NIST. (n.d.). Authentication. Retrieved January 30, 2020.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/ - Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/documentation/coreservices - Apple. (n.d.). Core Services. Retrieved June 25, 2020.
* https://developer.apple.com/documentation/foundation - Apple. (n.d.). Foundation. Retrieved July 1, 2020.
* https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html - Apple. (2016, June 13). About Mac Scripting. Retrieved April 14, 2021.
* https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/CocoaApplicationLayer/CocoaApplicationLayer.html#//apple_ref/doc/uid/TP40001067-CH274-SW1 - Apple. (2015, September 16). Cocoa Application Layer. Retrieved June 25, 2020.
* https://developer.chrome.com/extensions - Chrome. (n.d.). What are Extensions?. Retrieved November 16, 2017.
* https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1562-impair-defenses/disable-windows-event-logging -  dmcxblue. (n.d.). Disable Windows Event Logging. Retrieved September 10, 2021.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/archive/blogs/gauravseth/the-world-of-jscript-javascript-ecmascript - Microsoft. (2007, August 15). The World of JScript, JavaScript, ECMAScript …. Retrieved June 23, 2020.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-configurable-token-lifetimes - Microsoft. (2020, December 14). Configurable token lifetimes in Microsoft Identity Platform. Retrieved December 22, 2020.
* https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed - Microsoft. (2018, November 28). What is federation with Azure AD?. Retrieved December 30, 2020.
* https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover - Microsoft. (2020, September 29). Prevent dangling DNS entries and avoid subdomain takeover. Retrieved October 12, 2020.
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships - Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8 - Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/office365/securitycompliance/detect-and-remediate-outlook-rules-forms-attack - Fox, C., Vangel, D. (2018, April 22). Detect and Remediate Outlook Rules and Custom Forms Injections Attacks in Office 365. Retrieved February 4, 2019.
* https://docs.microsoft.com/en-us/office365/troubleshoot/active-directory/update-federated-domain-office-365 - Microsoft. (2020, September 14). Update or repair the settings of a federated domain in Office 365, Azure, or Intune. Retrieved December 30, 2020.
* https://docs.microsoft.com/en-us/powershell/module/exchange/mailboxes/add-mailboxpermission?view=exchange-ps - Microsoft. (n.d.). Add-Mailbox Permission. Retrieved September 13, 2019.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10) - Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol - Jason Gerend, et al. (2017, October 16). auditpol. Retrieved September 1, 2021.
* https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata - Microsoft. (2018, April 12). CryptUnprotectData function. Retrieved June 18, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings - Simpson, D. et al. (2017, April 19). Advanced security audit policy settings. Retrieved September 14, 2021.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/audit-policy - Daniel Simpson. (2017, April 19). Audit Policy. Retrieved September 13, 2021.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/api/ - Microsoft. (n.d.). Programming reference for the Win32 API. Retrieved March 15, 2020.
* https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry - Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/previous-versions/office/developer/office-2007/aa338205(v=office.12) - Microsoft. (2014, July 9). Introducing the Office (2007) Open XML File Formats. Retrieved July 20, 2018.
* https://docs.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-1-4-sdk - Microsoft. (2018, May 30). Microsoft HTML Help 1.4. Retrieved October 3, 2018.
* https://docs.microsoft.com/scripting/winscript/windows-script-interfaces - Microsoft. (2017, January 18). Windows Script Interfaces. Retrieved June 23, 2020.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/win32/com/translating-to-jscript - Microsoft. (2018, May 31). Translating to JScript. Retrieved June 23, 2020.
* https://docs.microsoft.com/windows/win32/services/service-control-manager - Microsoft. (2018, May 31). Service Control Manager. Retrieved March 28, 2020.
* https://dotnet.microsoft.com/learn/dotnet/what-is-dotnet-framework - Microsoft. (n.d.). What is .NET Framework?. Retrieved March 15, 2020.
* https://en.wikipedia.org/wiki/Browser_extension - Wikipedia. (2017, October 8). Browser Extension. Retrieved January 11, 2018.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Public-key_cryptography - Wikipedia. (2017, June 29). Public-key cryptography. Retrieved July 5, 2017.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/ - Nelson, M. (2017, January 5). Lateral Movement using the MMC20 Application COM Object. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript/ - Nelson, M. (2017, November 16). Lateral Movement using Outlook's CreateObject Method and DotNetToJScript. Retrieved November 21, 2017.
* https://expel.io/blog/behind-the-scenes-expel-soc-alert-aws/ - S. Lipton, L. Easterly, A. Randazzo and J. Hencinski. (2020, July 28). Behind the scenes in the Expel SOC: Alert-to-fix in AWS. Retrieved October 1, 2020.
* https://expel.io/blog/finding-evil-in-aws/ - A. Randazzo, B. Manahan and S. Lipton. (2020, April 28). Finding Evil in AWS. Retrieved June 25, 2020.
* https://forum.anomali.com/t/credential-harvesting-and-malicious-file-delivery-using-microsoft-office-template-injection/2104 - Intel_Acquisition_Team. (2018, March 1). Credential Harvesting and Malicious File Delivery using Microsoft Office Template Injection. Retrieved July 20, 2018.
* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml - Microsoft. (2020, December). Azure Sentinel Detections. Retrieved December 30, 2020.
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1 - EmpireProject. (2016, October 31). Invoke-Kerberoast.ps1. Retrieved March 22, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/gtworek/PSBits/tree/master/NoRunDll - gtworek. (2019, December 17). NoRunDll. Retrieved August 23, 2021.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/putterpanda/mimikittenz - Jamieson O'Reilly (putterpanda). (2016, July 4). mimikittenz. Retrieved June 20, 2019.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md - redcanaryco. (2021, September 3). T1562.002 - Disable Windows Event Logging. Retrieved September 13, 2021.
* https://github.com/ryhanson/phishery - Hanson, R. (2016, September 24). phishery. Retrieved July 21, 2018.
* https://github.com/sensepost/notruler - SensePost. (2017, September 21). NotRuler - The opposite of Ruler, provides blue teams with the ability to detect Ruler usage against Exchange. Retrieved February 4, 2019.
* https://github.com/sensepost/ruler - SensePost. (2016, August 18). Ruler: A tool to abuse Exchange services. Retrieved February 4, 2019.
* https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html - Forshaw, J. (2018, April 18). Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege. Retrieved May 3, 2018.
* https://isc.sans.edu/forums/diary/BankerGoogleChromeExtensiontargetingBrazil/22722/ - Marinho, R. (n.d.). (Banker(GoogleChromeExtension)).targeting. Retrieved November 18, 2017.
* https://isc.sans.edu/forums/diary/CatchAll+Google+Chrome+Malicious+Extension+Steals+All+Posted+Data/22976/https:/threatpost.com/malicious-chrome-extension-steals-data-posted-to-any-website/128680/) - Marinho, R. (n.d.). "Catch-All" Google Chrome Malicious Extension Steals All Posted Data. Retrieved November 16, 2017.
* https://kasperskycontenthub.com/wp-content/uploads/sites/43/vlpdfs/unveilingthemask_v1.0.pdf - Kaspersky Labs. (2014, February 11). Unveiling “Careto” - The Masked APT. Retrieved July 5, 2017.
* https://kjaer.io/extension-malware/ - Kjaer, M. (2016, July 18). Malware in the browser: how you might get hacked by a Chrome extension. Retrieved November 22, 2017.
* https://kubernetes.io/docs/reference/access-authn-authz/authorization/ - Kubernetes. (n.d.). Authorization Overview. Retrieved June 24, 2021.
* https://labs.ft.com/2013/05/a-sobering-day/?mhq5j=e6 - THE FINANCIAL TIMES. (2019, September 2). A sobering day. Retrieved October 8, 2019.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://malware.news/t/using-outlook-forms-for-lateral-movement-and-persistence/13746 - Parisi, T., et al. (2017, July). Using Outlook Forms for Lateral Movement and Persistence. Retrieved February 5, 2019.
* https://man7.org/linux/man-pages//man7/libc.7.html - Kerrisk, M. (2016, December 12). libc(7) — Linux manual page. Retrieved June 25, 2020.
* https://medium.com/@bwtech789/outlook-today-homepage-persistence-33ea9b505943 - Soutcast. (2018, September 14). Outlook Today Homepage Persistence. Retrieved February 5, 2019.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-lateral-movement-using-sysmon-and-splunk-318d3be141bc - French, D. (2018, September 30). Detecting Lateral Movement Using Sysmon and Splunk. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/ms677949.aspx - Microsoft. (n.d.). Service Principal Names. Retrieved March 22, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/windows/desktop/ms524405 - Microsoft. (n.d.). About the HTML Help Executable Program. Retrieved October 3, 2018.
* https://msdn.microsoft.com/windows/desktop/ms644670 - Microsoft. (n.d.). HTML Help ActiveX Control Overview. Retrieved October 3, 2018.
* https://msitpros.com/?p=3909 - Moe, O. (2017, August 13). Bypassing Device guard UMCI using CHM – CVE-2017-8625. Retrieved October 3, 2018.
* https://msrc-blog.microsoft.com/2020/12/13/customer-guidance-on-recent-nation-state-cyber-attacks/ - MSRC. (2020, December 13). Customer Guidance on Recent Nation-State Cyber Attacks. Retrieved December 17, 2020.
* https://nedinthecloud.com/2019/07/16/demystifying-azure-ad-service-principals/ - Bellavance, Ned. (2019, July 16). Demystifying Azure AD Service Principals. Retrieved January 19, 2020.
* https://nodejs.org/ - OpenJS Foundation. (n.d.). Node.js. Retrieved June 23, 2020.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://objective-see.com/blog/blog_0x25.html - Patrick Wardle. (n.d.). Retrieved March 20, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ - de Plaa, C. (2019, June 19). Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR. Retrieved September 29, 2021.
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8625 - Microsoft. (2017, August 8). CVE-2017-8625 - Internet Explorer Security Feature Bypass Vulnerability. Retrieved October 3, 2018.
* https://posts.specterops.io/head-in-the-clouds-bd038bb69e48 - Maddalena, C.. (2018, September 12). Head in the Clouds. Retrieved October 4, 2019.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5 - Pitt, L. (2020, August 6). Persistent JXA. Retrieved April 14, 2021.
* https://redcanary.com/blog/clipping-silver-sparrows-wings/ - Tony Lambert. (2021, February 18). Clipping Silver Sparrow’s wings: Outing macOS malware before it takes flight. Retrieved April 20, 2021.
* https://redsiege.com/kerberoast-slides - Medin, T. (2014, November). Attacking Kerberos - Kicking the Guard Dog of Hades. Retrieved March 22, 2018.
* https://researchcenter.paloaltonetworks.com/2016/06/unit42-prince-of-persia-game-over/ - Bar, T., Conant, S., Efraim, L. (2016, June 28). Prince of Persia – Game Over. Retrieved July 5, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://rewtin.blogspot.ch/2017/11/abusing-user-shares-for-efficient.html - Routin, D. (2017, November 13). Abusing network shares for efficient lateral movements and privesc (DirSharePivot). Retrieved April 12, 2018.
* https://securelist.com/old-malware-tricks-to-bypass-detection-in-the-age-of-big-data/78010/ - Ishimaru, S.. (2017, April 13). Old Malware Tricks To Bypass Detection in the Age of Big Data. Retrieved May 30, 2019.
* https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/ - Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx - Microsoft. (2010, April 13). Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe). Retrieved March 22, 2018.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://speakerdeck.com/tweekfawkes/blue-cloud-of-death-red-teaming-azure-1 - Kunz, Bryce. (2018, May 11). Blue Cloud of Death: Red Teaming Azure. Retrieved October 23, 2019.
* https://static.googleusercontent.com/media/research.google.com/en//pubs/archive/43824.pdf - Jagpal, N., et al. (2015, August). Trends and Lessons from Three Years Fighting Malicious Extensions. Retrieved November 17, 2017.
* https://strontic.github.io/xcyclopedia/library/auditpol.exe-214E0EA1F7F7C27C82D23F183F9D23F1.html - STRONTIC. (n.d.). auditpol.exe. Retrieved September 9, 2021.
* https://support.apple.com/guide/remote-desktop/set-up-a-computer-running-vnc-software-apdbed09830/mac - Apple Support. (n.d.). Set up a computer running VNC software for Remote Desktop. Retrieved August 18, 2021.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
* https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c - svch0st. (2020, September 30). Event Log Tampering Part 1: Disrupting the EventLog Service. Retrieved September 14, 2021.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://undocumented.ntinternals.net/ - The NTinterlnals.net team. (n.d.). Nowak, T. Retrieved June 25, 2020.
* https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed/ - Chen, J.. (2020, January 29). Attacker's Tactics and Techniques in Unsecured Docker Daemons Revealed. Retrieved March 31, 2021.
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
* https://www.attackify.com/blog/rundll32_execution_order/ - Attackify. (n.d.). Rundll32.exe Obscurity. Retrieved August 23, 2021.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.commandfive.com/papers/C5_APT_SKHack.pdf - Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.
* https://www.coretechnologies.com/blog/windows-services/eventlog/ - Core Technologies. (2021, May 24). Essential Windows Services: EventLog / Windows Event Log. Retrieved September 14, 2021.
* https://www.crowdstrike.com/blog/hiding-in-plain-sight-using-the-office-365-activities-api-to-investigate-business-email-compromises/ - Crowdstrike. (2018, July 18). Hiding in Plain Sight: Using the Office 365 Activities API to Investigate Business Email Compromises. Retrieved January 19, 2020.
* https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.
* https://www.cyberark.com/resources/threat-research-blog/golden-saml-newly-discovered-attack-technique-forges-authentication-to-cloud-apps - Reiner, S. (2017, November 21). Golden SAML: Newly Discovered Attack Technique Forges Authentication to Cloud Apps. Retrieved December 17, 2020.
* https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/ - Gavriel, H. (2018, November 27). Malware Mitigation when Direct System Calls are Used. Retrieved September 29, 2021.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html - Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/blog/threat-research/2017/07/hawkeye-malware-distributed-in-phishing-campaign.html - Swapnil Patil, Yogesh Londhe. (2017, July 25). HawkEye Credential Theft Malware Distributed in Recent Phishing Campaign. Retrieved June 18, 2019.
* https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html - Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.
* https://www.fireeye.com/blog/threat-research/2021/01/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452.html - Mike Burns, Matthew McWhirt, Douglas Bienstock, Nick Bennett. (2021, January 19). Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452. Retrieved September 25, 2021.
* https://www.fireeye.com/content/dam/collateral/en/mtrends-2018.pdf - Mandiant. (2018). Mandiant M-Trends 2018. Retrieved July 9, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html - Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.ghacks.net/2017/09/19/first-chrome-extension-with-javascript-crypto-miner-detected/ - Brinkmann, M. (2017, September 19). First Chrome extension with JavaScript Crypto Miner detected. Retrieved November 16, 2017.
* https://www.gnu.org/software/acct/ - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.
* https://www.gnu.org/software/libc/ - glibc developer community. (2020, February 1). The GNU C Library (glibc). Retrieved June 25, 2020.
* https://www.gnu.org/software/libc/manual/html_node/Creating-a-Process.html - Free Software Foundation, Inc.. (2020, June 18). Creating a Process. Retrieved June 25, 2020.
* https://www.hackingarticles.in/defense-evasion-windows-event-logging-t1562-002/ - Chandel, R. (2021, April 22). Defense Evasion: Windows Event Logging (T1562.002). Retrieved September 14, 2021.
* https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/ - Schroeder, W. (2016, November 1). Kerberoasting Without Mimikatz. Retrieved March 23, 2018.
* https://www.icann.org/groups/ssac/documents/sac-007-en - ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.
* https://www.icebrg.io/blog/malicious-chrome-extensions-enable-criminals-to-impact-over-half-a-million-users-and-global-businesses - De Tore, M., Warner, J. (2018, January 15). MALICIOUS CHROME EXTENSIONS ENABLE CRIMINALS TO IMPACT OVER HALF A MILLION USERS AND GLOBAL BUSINESSES. Retrieved January 17, 2018.
* https://www.kernel.org/doc/html/v4.12/core-api/kernel-api.html - Linux Kernel Organization, Inc. (n.d.). The Linux Kernel API. Retrieved June 25, 2020.
* https://www.losangeles.va.gov/documents/MI-000120-MW.pdf - Federal Bureau of Investigation, Cyber Division. (2020, March 26). FIN7 Cyber Actors Targeting US Businesses Through USB Keystroke Injection Attacks. Retrieved October 14, 2020.
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - MDSec Research. (2020, December). Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams. Retrieved September 29, 2021.
* https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/ - Dominic Chell. (2021, January 1). macOS Post-Exploitation Shenanigans with VSCode Extensions. Retrieved April 20, 2021.
* https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/ - Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.proofpoint.com/us/threat-insight/post/new-vega-stealer-shines-brightly-targeted-campaign - Proofpoint. (2018, May 10). New Vega Stealer shines brightly in targeted campaign . Retrieved June 18, 2019.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/identifying-cobalt-strike-servers/ - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved October 16, 2020.
* https://www.sans.org/reading-room/whitepapers/testing/template-injection-attacks-bypassing-security-controls-living-land-38780 - Wiltse, B.. (2018, November 7). Template Injection Attacks - Bypassing Security Controls by Living off the Land. Retrieved April 10, 2019.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/ - Phil Stokes. (2019, December 5). macOS Red Team: Calling Apple APIs Without Building Binaries. Retrieved July 17, 2020.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.slideshare.net/DouglasBienstock/shmoocon-2019-becs-and-beyond-investigating-and-defending-office-365 - Bienstock, D.. (2019). BECS and Beyond: Investigating and Defending O365. Retrieved September 13, 2019.
* https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2 - Jacobsen, K. (2014, May 16). Lateral Movement with PowerShell&#91;slides&#93;. Retrieved November 12, 2014.
* https://www.sygnia.co/golden-saml-advisory - Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.
* https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage - Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.
* https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html - Remillano II, A., et al. (2020, June 20). XORDDoS, Kaiji Variants Target Exposed Docker Servers. Retrieved April 5, 2021.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ - Franklin Smith. (n.d.). Windows Security Log Events. Retrieved February 21, 2020.
* https://www.virustotal.com/en/faq/ - VirusTotal. (n.d.). VirusTotal FAQ. Retrieved May 23, 2019.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2020/12/14/dark-halo-leverages-solarwinds-compromise-to-breach-organizations/ - Cash, D. et al. (2020, December 14). Dark Halo Leverages SolarWinds Compromise to Breach Organizations. Retrieved December 29, 2020.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2017/07/20/stantinko-massive-adware-campaign-operating-covertly-since-2012/ - Vachon, F., Faou, M. (2017, July 20). Stantinko: A massive adware campaign operating covertly since 2012. Retrieved November 16, 2017.
* https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/ - ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.
* https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/ - Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.xorrior.com/No-Place-Like-Chrome/ - Chris Ross. (2019, February 8). No Place Like Chrome. Retrieved April 27, 2021.
* https://www.youtube.com/watch?v=wQ1CuAPnrLM&feature=youtu.be&t=2815 - Kunz, Bruce. (2018, October 14). Blue Cloud of Death: Red Teaming Azure. Retrieved November 21, 2019.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www2.fireeye.com/rs/848-DID-242/images/rpt-apt29-hammertoss.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved September 17, 2015.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* AdFind - 1
* Empire - 1
* Mimikatz - 2
* PsExec - 1
* SDelete - 1
* Winexe - 1

# Review the following tool references

* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive - Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://github.com/EmpireProject/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/skalkoto/winexe/ - Skalkotos, N. (2013, September 20). WinExe. Retrieved January 22, 2018.
* https://netzpolitik.org/2015/digital-attack-on-german-parliament-investigative-report-on-the-hack-of-the-left-party-infrastructure-in-bundestag/ - Guarnieri, C. (2015, June 19). Digital Attack on German Parliament: Investigative Report on the Hack of the Left Party Infrastructure in Bundestag. Retrieved January 22, 2018.
* https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/  - Brian Donohue, Katie Nickels, Paul Michaud, Adina Bodkins, Taylor Chapman, Tony Lambert, Jeff Felling, Kyle Rainey, Mike Haag, Matt Graeber, Aaron Didier.. (2020, October 29). A Bazar start: How one hospital thwarted a Ryuk ransomware outbreak. Retrieved October 30, 2020.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html - Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html - McKeague, B. et al. (2019, April 5). Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware. Retrieved April 17, 2019.
* https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.

# Validate the following malware

* Cobalt Strike - 1
* GoldMax - 1
* Pteranodon - 1
* Raindrop - 1
* SUNBURST - 1
* SUNSPOT - 1
* Sibot - 1
* TEARDROP - 1

# Review the following malware references

* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://orangematter.solarwinds.com/2021/01/11/new-findings-from-our-investigation-of-sunburst/ - Sudhakar Ramakrishna . (2021, January 11). New Findings From Our Investigation of SUNBURST. Retrieved January 13, 2021.
* https://researchcenter.paloaltonetworks.com/2017/02/unit-42-title-gamaredon-group-toolset-evolution/ - Kasza, A. and Reichel, D. (2017, February 27). The Gamaredon Group Toolset Evolution. Retrieved March 1, 2017.
* https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/solarwinds-raindrop-malware - Symantec Threat Hunter Team. (2021, January 18). Raindrop: New Malware Discovered in SolarWinds Investigation. Retrieved January 19, 2021.
* https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/ - CrowdStrike Intelligence Team. (2021, January 11). SUNSPOT: An Implant in the Build Process. Retrieved January 11, 2021.
* https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html - FireEye. (2020, December 13). Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor. Retrieved January 4, 2021.
* https://www.fireeye.com/blog/threat-research/2021/03/sunshuttle-second-stage-backdoor-targeting-us-based-entity.html - Smith, L., Leathery, J., Read, B. (2021, March 4). New SUNSHUTTLE Second-Stage Backdoor Uncovered Targeting U.S.-Based Entity; Possible Connection to UNC2452. Retrieved March 12, 2021.
* https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/ - MSTIC, CDOC, 365 Defender Research Team. (2021, January 20). Deep dive into the Solorigate second-stage activation: From SUNBURST to TEARDROP and Raindrop . Retrieved January 22, 2021.
* https://www.microsoft.com/security/blog/2021/03/04/goldmax-goldfinder-sibot-analyzing-nobelium-malware/ - Nafisi, R., Lelli, A. (2021, March 4). GoldMax, GoldFinder, and Sibot: Analyzing NOBELIUM’s layered persistence. Retrieved March 8, 2021.

