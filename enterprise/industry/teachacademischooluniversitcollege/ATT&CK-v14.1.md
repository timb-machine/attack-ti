threat-crank.py 0.2.1
I: searching for industries that match .* teach.*|.* academi.*|.* school.*|.* universit.*|.* college.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v14.1/enterprise-attack/enterprise-attack.json
# Threat groups

* APT39
* Leviathan
* Magic Hound
* Metador
* Silent Librarian

# Validate the following attacks

* Account Manipulation - 1
* Additional Email Delegate Permissions - 1
* AppInit DLLs - 1
* Application Layer Protocol - 1
* Archive Collected Data - 1
* Archive via Utility - 2
* BITS Jobs - 2
* Bidirectional Communication - 2
* Binary Padding - 1
* Brute Force - 1
* Clear Command History - 1
* Clipboard Data - 1
* Code Signing - 1
* Code Signing Policy Modification - 1
* Command Obfuscation - 1
* Command and Scripting Interpreter - 1
* Credentials - 2
* Credentials from Password Stores - 1
* DNS - 1
* Data Encrypted for Impact - 1
* Data from Local System - 2
* Default Accounts - 1
* Deobfuscate/Decode Files or Information - 2
* Determine Physical Locations - 1
* Digital Certificates - 1
* Disable Windows Event Logging - 1
* Disable or Modify System Firewall - 1
* Disable or Modify Tools - 1
* Domain Accounts - 1
* Domain Trust Discovery - 1
* Domains - 4
* Drive-by Compromise - 2
* Dynamic Data Exchange - 1
* Dynamic-link Library Injection - 1
* Email Account - 1
* Email Accounts - 5
* Email Addresses - 2
* Email Collection - 2
* Email Forwarding Rule - 1
* Employee Names - 1
* Encrypted Channel - 1
* Exfiltration Over C2 Channel - 2
* Exfiltration Over Web Service - 1
* Exfiltration to Cloud Storage - 1
* Exploit Public-Facing Application - 2
* Exploitation for Client Execution - 1
* External Proxy - 1
* External Remote Services - 1
* File Deletion - 3
* File and Directory Discovery - 2
* Gather Victim Identity Information - 1
* Hidden Window - 1
* IP Addresses - 1
* Impair Defenses - 1
* Ingress Tool Transfer - 4
* Input Capture - 1
* Internal Proxy - 1
* Internal Spearphishing - 1
* Internet Connection Discovery - 1
* Keylogging - 2
* LSASS Memory - 3
* Lateral Tool Transfer - 1
* Link Target - 1
* Local Account - 2
* Local Data Staging - 2
* Local Email Collection - 1
* Malicious File - 3
* Malicious Link - 3
* Malware - 1
* Masquerade Task or Service - 1
* Match Legitimate Name or Location - 2
* Modify Registry - 1
* Multi-hop Proxy - 1
* Network Service Discovery - 2
* Network Share Discovery - 1
* Non-Application Layer Protocol - 1
* Non-Standard Port - 1
* OS Credential Dumping - 2
* Obfuscated Files or Information - 4
* One-Way Communication - 1
* Password Spraying - 1
* PowerShell - 3
* Process Discovery - 1
* Protocol Tunneling - 2
* Proxy - 1
* Python - 1
* Query Registry - 1
* Registry Run Keys / Startup Folder - 3
* Regsvr32 - 1
* Remote Data Staging - 1
* Remote Desktop Protocol - 3
* Remote Email Collection - 1
* Remote System Discovery - 2
* Rundll32 - 1
* SMB/Windows Admin Shares - 1
* SSH - 2
* Scheduled Task - 2
* Screen Capture - 2
* Search Victim-Owned Websites - 1
* Service Execution - 1
* Shortcut Modification - 2
* Social Media Accounts - 3
* Software - 1
* Software Packing - 1
* Spearphishing Attachment - 2
* Spearphishing Link - 5
* Spearphishing via Service - 1
* Steganography - 1
* System Information Discovery - 1
* System Network Configuration Discovery - 1
* System Network Connections Discovery - 1
* System Owner/User Discovery - 2
* Tool - 4
* Valid Accounts - 3
* Visual Basic - 3
* Vulnerability Scanning - 1
* Web Protocols - 3
* Web Services - 1
* Web Shell - 3
* Wi-Fi Discovery - 1
* Windows Command Shell - 2
* Windows Management Instrumentation - 2
* Windows Management Instrumentation Event Subscription - 2

# Validate the following phases

* collection - 19
* command-and-control - 21
* credential-access - 11
* defense-evasion - 35
* discovery - 18
* execution - 23
* exfiltration - 4
* impact - 1
* initial-access - 16
* lateral-movement - 8
* persistence - 25
* privilege-escalation - 18
* reconnaissance - 13
* resource-development - 20

# Validate the following platforms

* Android - 1
* Azure AD - 8
* Containers - 18
* Google Workspace - 19
* IaaS - 19
* Linux - 131
* Network - 36
* Office 365 - 20
* PRE - 33
* SaaS - 14
* Windows - 200
* macOS - 133

# Validate the following defences

* Anti-virus - 12
* Application Control - 10
* Application control - 3
* Digital Certificate Validation - 4
* File monitoring - 2
* Firewall - 7
* Heuristic detection - 1
* Host Forensic Analysis - 4
* Host Intrusion Prevention Systems - 9
* Host forensic analysis - 8
* Host intrusion prevention systems - 2
* Log Analysis - 4
* Log analysis - 4
* Network Intrusion Detection System - 5
* Signature-based Detection - 6
* Signature-based detection - 4
* System Access Controls - 3
* User Mode Signature Validation - 1
* Windows User Account Control - 1

# Validate the following data sources

* Active Directory: Active Directory Object Access - 4
* Active Directory: Active Directory Object Modification - 1
* Application Log: Application Log Content - 28
* Certificate: Certificate Registration - 1
* Cloud Service: Cloud Service Disable - 1
* Cloud Service: Cloud Service Enumeration - 3
* Cloud Service: Cloud Service Modification - 1
* Cloud Storage: Cloud Storage Modification - 1
* Command: Command Execution - 97
* Domain Name: Active DNS - 4
* Domain Name: Domain Registration - 4
* Domain Name: Passive DNS - 4
* Driver: Driver Load - 5
* File: File Access - 19
* File: File Creation - 33
* File: File Deletion - 5
* File: File Metadata - 13
* File: File Modification - 18
* Firewall: Firewall Disable - 2
* Firewall: Firewall Rule Modification - 2
* Group: Group Modification - 2
* Image: Image Metadata - 2
* Internet Scan: Response Content - 4
* Logon Session: Logon Session Creation - 17
* Logon Session: Logon Session Metadata - 8
* Malware Repository: Malware Content - 1
* Malware Repository: Malware Metadata - 5
* Module: Module Load - 16
* Named Pipe: Named Pipe Metadata - 1
* Network Share: Network Share Access - 3
* Network Traffic: Network Connection Creation - 39
* Network Traffic: Network Traffic Content - 58
* Network Traffic: Network Traffic Flow - 53
* Persona: Social Media - 3
* Process: OS API Execution - 34
* Process: Process Access - 9
* Process: Process Creation - 89
* Process: Process Metadata - 8
* Process: Process Modification - 2
* Process: Process Termination - 2
* Scheduled Job: Scheduled Job Creation - 2
* Scheduled Job: Scheduled Job Metadata - 1
* Scheduled Job: Scheduled Job Modification - 1
* Script: Script Execution - 23
* Sensor Health: Host Status - 3
* Service: Service Creation - 2
* Service: Service Metadata - 5
* User Account: User Account Authentication - 8
* User Account: User Account Creation - 2
* User Account: User Account Modification - 3
* WMI: WMI Creation - 8
* Windows Registry: Windows Registry Key Access - 5
* Windows Registry: Windows Registry Key Creation - 11
* Windows Registry: Windows Registry Key Deletion - 3
* Windows Registry: Windows Registry Key Modification - 19

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf - Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29 - Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.
* http://media.blackhat.com/bh-us-10/whitepapers/Ryan/BlackHat-USA-2010-Ryan-Getting-In-Bed-With-Robin-Sage-v1.0.pdf - Ryan, T. (2010). “Getting In Bed with Robin Sage.”. Retrieved March 6, 2017.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/KB/170292 - Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://www.blackhillsinfosec.com/?p=4645 - Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* https://adsecurity.org/?p=1588 - Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/ - Bright, P. (2011, February 15). Anonymous speaks: the inside story of the HBGary hack. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://bashfuscator.readthedocs.io/en/latest/Mutators/command_obfuscators/index.html - LeFevre, A. (n.d.). Bashfuscator Command Obfuscators. Retrieved March 17, 2023.
* https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://blog.compass-security.com/2018/09/hidden-inbox-rules-in-microsoft-exchange/ - Damian Pfammatter. (2018, September 17). Hidden Inbox Rules in Microsoft Exchange. Retrieved October 12, 2021.
* https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/ - Aliz Hammond. (2019, August 15). Hiding Malicious Code with "Module Stomping": Part 1. Retrieved July 14, 2022.
* https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/ - Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/malwarebytes-news/2020/10/silent-librarian-apt-phishing-attack/ - Malwarebytes Threat Intelligence Team. (2020, October 14). Silent Librarian APT right on schedule for 20/21 academic year. Retrieved February 3, 2021.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments - Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.
* https://blog.reversinglabs.com/blog/mining-for-malicious-ruby-gems - Maljic, T. (2020, April 16). Mining for malicious Ruby gems. Retrieved October 15, 2022.
* https://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/ -  Ishaq Mohammed . (2021, January 10). Everything about CSV Injection and CSV Excel Macro Injection. Retrieved February 7, 2022.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A., McKay, K. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal . Retrieved July 29, 2022.
* https://blog.talosintelligence.com/2021/11/kimsuky-abuses-blogs-delivers-malware.html - An, J and Malhotra, A. (2021, November 10). North Korean attackers use malicious blogs to deliver malware to high-profile South Korean targets. Retrieved December 29, 2021.
* https://blog.talosintelligence.com/2022/03/transparent-tribe-new-campaign.html - Malhotra, A., Thattil, J. et al. (2022, March 29). Transparent Tribe campaign uses new bespoke malware to target Indian government officials . Retrieved September 6, 2022.
* https://blog.talosintelligence.com/ipfs-abuse/ - Edmund Brumaghin. (2022, November 9). Threat Spotlight: Cyber Criminal Adoption of IPFS for Phishing, Malware Campaigns. Retrieved March 8, 2023.
* https://blog.trendmicro.com/phishing-starts-inside/ - Chris Taylor. (2017, October 5). When Phishing Starts from the Inside. Retrieved October 8, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/r980-ransomware-disposable-email-service/ - Antazo, F. and Yambao, M. (2016, August 10). R980 Ransomware Found Abusing Disposable Email Address Service. Retrieved October 13, 2020.
* https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices - Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.
* https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://blogs.technet.microsoft.com/timmcmic/2015/06/08/exchange-and-office-365-mail-forwarding-2/ - McMichael, T.. (2015, June 8). Exchange and Office 365 Mail Forwarding. Retrieved October 8, 2019.
* https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16 - Bromiley, M. (2016, December 27). Malware Monday: VBScript and VBE Files. Retrieved March 17, 2023.
* https://cdn.logic-control.com/docs/scadafence/Anatomy-Of-A-Targeted-Ransomware-Attack-WP.pdf - Shaked, O. (2020, January 20). Anatomy of a Targeted Ransomware Attack. Retrieved June 18, 2022.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://community.sophos.com/products/intercept/early-access-program/f/live-discover-response-queries/121529/live-discover---powershell-command-audit - jak. (2020, June 27). Live Discover - PowerShell command audit. Retrieved August 21, 2020.
* https://community.sophos.com/products/malware/b/blog/posts/powershell-command-history-forensics - Vikas, S. (2020, August 26). PowerShell Command History Forensics. Retrieved September 4, 2020.
* https://content.fireeye.com/m-trends/rpt-m-trends-2020 - Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.
* https://csrc.nist.gov/glossary/term/web_bug - NIST Information Technology Laboratory. (n.d.). web bug. Retrieved March 22, 2023.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks - Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection - Apple. (n.d.). Disabling and Enabling System Integrity Protection. Retrieved April 22, 2021.
* https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/NetServices/Introduction.html - Apple Inc. (2013, April 23). Bonjour Overview. Retrieved October 11, 2021.
* https://digital.nhs.uk/cyber-alerts/2020/cc-3681#summary - NHS Digital. (2020, November 26). Egregor Ransomware The RaaS successor to Maze. Retrieved December 29, 2020.
* https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1562-impair-defenses/disable-windows-event-logging -  dmcxblue. (n.d.). Disable Windows Event Logging. Retrieved September 10, 2021.
* https://dnsdumpster.com/ - Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html - Amazon. (n.d.). AWS Account Root User. Retrieved April 5, 2021.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover - Microsoft. (2020, September 29). Prevent dangling DNS entries and avoid subdomain takeover. Retrieved October 12, 2020.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships - Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8 - Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.
* https://docs.microsoft.com/en-us/exchange/email-addresses-and-address-books/address-lists/address-lists?view=exchserver-2019 - Microsoft. (2020, February 7). Address lists in Exchange Server. Retrieved March 26, 2020.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1 - Wheeler, S. et al.. (2019, May 1). About PowerShell.exe. Retrieved October 11, 2019.
* https://docs.microsoft.com/en-us/powershell/module/exchange/email-addresses-and-address-books/get-globaladdresslist - Microsoft. (n.d.). Get-GlobalAddressList. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/powershell/module/exchange/mailboxes/add-mailboxpermission?view=exchange-ps - Microsoft. (n.d.). Add-Mailbox Permission. Retrieved September 13, 2019.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_history?view=powershell-7 - Microsoft. (2020, May 13). About History. Retrieved September 4, 2020.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1 - Microsoft. (2020, August 21). Running Remote Commands. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653559(v=vs.85)?redirectedfrom=MSDN - Microsoft. (2017, June 1). Digital Signatures for Kernel Modules on Windows. Retrieved April 22, 2021.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10) - Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-an-unsigned-driver-during-development-and-test - Microsoft. (2017, April 20). Installing an Unsigned Driver during Development and Test. Retrieved April 22, 2021.
* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option - Microsoft. (2021, February 15). Enable Loading of Test Signed Drivers. Retrieved April 22, 2021.
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol - Jason Gerend, et al. (2017, October 16). auditpol. Retrieved September 1, 2021.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts - Microsoft. (2019, August 23). Active Directory Accounts. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts - Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings - Simpson, D. et al. (2017, April 19). Advanced security audit policy settings. Retrieved September 14, 2021.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720 - Lich, B., Miroshnikov, A. (2017, April 5). 4720(S): A user account was created. Retrieved June 30, 2017.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738 - Lich, B., Miroshnikov, A. (2017, April 5). 4738(S): A user account was changed. Retrieved June 30, 2017.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/audit-policy - Daniel Simpson. (2017, April 19). Audit Policy. Retrieved September 13, 2021.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry - Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/win32/services/service-control-manager - Microsoft. (2018, May 31). Service Control Manager. Retrieved March 28, 2020.
* https://eclecticlight.co/2020/11/16/checks-on-executable-code-in-catalina-and-big-sur-a-first-draft/ - Howard Oakley. (2020, November 16). Checks on executable code in Catalina and Big Sur: a first draft. Retrieved September 21, 2022.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Onion_routing - Wikipedia. (n.d.). Onion Routing. Retrieved October 20, 2020.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.
* https://en.wikipedia.org/wiki/Shared_resource - Wikipedia. (2017, April 15). Shared resource. Retrieved June 30, 2017.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://en.wikipedia.org/wiki/Windows_Registry - Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml - Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.
* https://github.com/danielbohannon/Invoke-DOSfuscation - Bohannon, D. (2018, March 19). Invoke-DOSfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Invoke-Obfuscation - Bohannon, D. (2016, September 24). Invoke-Obfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/dhondta/awesome-executable-packing - Alexandre D'Hondt. (n.d.). Awesome Executable Packing. Retrieved March 11, 2022.
* https://github.com/dxa4481/truffleHog - Dylan Ayrey. (2016, December 31). truffleHog. Retrieved October 19, 2020.
* https://github.com/gentilkiwi/mimikatz/issues/92 - Warren, J. (2017, June 22). lsadump::changentlm and lsadump::setntlm work, but generate Windows events #92. Retrieved December 4, 2017.
* https://github.com/gremwell/o365enum - gremwell. (2020, March 24). Office 365 User Enumeration. Retrieved May 27, 2022.
* https://github.com/gtworek/PSBits/tree/master/NoRunDll - gtworek. (2019, December 17). NoRunDll. Retrieved August 23, 2021.
* https://github.com/hfiref0x/TDL - TDL Project. (2016, February 4). TDL (Turla Driver Loader). Retrieved April 22, 2021.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/michenriksen/gitrob - Michael Henriksen. (2018, June 9). Gitrob: Putting the Open Source in OSINT. Retrieved October 19, 2020.
* https://github.com/nsacyber/Mitigating-Web-Shells -  NSA Cybersecurity Directorate. (n.d.). Mitigating Web Shells. Retrieved July 22, 2021.
* https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh - undefined. (n.d.). Retrieved April 12, 2019.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md - redcanaryco. (2021, September 3). T1562.002 - Disable Windows Event Logging. Retrieved September 13, 2021.
* https://googleblog.blogspot.com/2011/06/ensuring-your-information-is-safe.html - Google. (2011, June 1). Ensuring your information is safe online. Retrieved April 1, 2022.
* https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/ - GrimHacker. (2017, July 24). Office365 ActiveSync Username Enumeration. Retrieved December 9, 2021.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://krebsonsecurity.com/2018/11/that-domain-you-forgot-to-renew-yeah-its-now-stealing-credit-cards/ - Krebs, B. (2018, November 13). That Domain You Forgot to Renew? Yeah, it’s Now Stealing Credit Cards. Retrieved September 20, 2019.
* https://krebsonsecurity.com/2019/02/a-deep-dive-on-the-recent-widespread-dns-hijacking-attacks/ - Brian Krebs. (2019, February 18). A Deep Dive on the Recent Widespread DNS Hijacking Attacks. Retrieved February 14, 2022.
* https://kubernetes.io/docs/concepts/security/service-accounts/ - Kubernetes. (n.d.). Service Accounts. Retrieved July 14, 2023.
* https://labs.detectify.com/2016/04/28/slack-bot-token-leakage-exposing-business-critical-information/ - Detectify. (2016, April 28). Slack bot token leakage exposing business critical information. Retrieved October 19, 2020.
* https://labs.ft.com/2013/05/a-sobering-day/?mhq5j=e6 - THE FINANCIAL TIMES. (2019, September 2). A sobering day. Retrieved October 8, 2019.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules - Microsoft. (2023, February 22). Mail flow rules (transport rules) in Exchange Online. Retrieved March 13, 2023.
* https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/clip - Microsoft, JasonGerend, et al. (2023, February 3). clip. Retrieved June 21, 2022.
* https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedcommand-base64encodedcommand - Microsoft. (2023, February 8). about_PowerShell_exe: EncodedCommand. Retrieved March 17, 2023.
* https://letsencrypt.org/docs/faq/ - Let's Encrypt. (2020, April 23). Let's Encrypt FAQ. Retrieved October 15, 2020.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://lolbas-project.github.io/lolbas/Binaries/Diantz/ - Living Off The Land Binaries, Scripts and Libraries (LOLBAS). (n.d.). Diantz.exe. Retrieved October 25, 2021.
* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/ - LOLBAS. (n.d.). Regsvr32.exe. Retrieved July 31, 2019.
* https://mackeeper.com/blog/find-wi-fi-password-on-mac/ - Ruslana Lishchuk. (2021, March 26). How to Find a Saved Wi-Fi Password on a Mac. Retrieved September 8, 2023.
* https://medium.com/@galolbardes/learn-how-easy-is-to-bypass-firewalls-using-dns-tunneling-and-also-how-to-block-it-3ed652f4a000 - Galobardes, R. (2018, October 30). Learn how easy is to bypass firewalls using DNS tunneling (and also how to block it). Retrieved March 15, 2020.
* https://medium.com/rvrsh3ll/operating-with-empyre-ea764eda3363 - rvrsh3ll. (2016, May 18). Operating with EmPyre. Retrieved July 12, 2017.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://mrd0x.com/browser-in-the-browser-phishing-attack/ - mr.d0x. (2022, March 15). Browser In The Browser (BITB) Attack. Retrieved March 8, 2023.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/dn280412 - Microsoft. (n.d.). AppInit DLLs and Secure Boot. Retrieved July 15, 2015.
* https://msdn.microsoft.com/en-us/library/ms649012 - Microsoft. (n.d.). About the Clipboard. Retrieved March 29, 2016.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://o365blog.com/post/just-looking/ - Dr. Nestori Syynimaa. (2020, June 13). Just looking: Azure Active Directory reconnaissance as an outsider. Retrieved May 27, 2022.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ - de Plaa, C. (2019, June 19). Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR. Retrieved September 29, 2021.
* https://owasp.org/www-community/attacks/CSV_Injection -  Albinowax Timo Goosen. (n.d.). CSV Injection. Retrieved February 7, 2022.
* https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-014_Vulnerability_Scanning - OWASP. (n.d.). OAT-014 Vulnerability Scanning. Retrieved October 20, 2020.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944 - Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://powershellmagazine.com/2014/07/16/investigating-powershell-attacks/ - Hastings, M. (2014, July 16). Investigating PowerShell Attacks. Retrieved December 1, 2021.
* https://practical365.com/clients/office-365-proplus/outlook-cached-mode-ost-file-sizes/ - N. O'Bryan. (2018, May 30). Managing Outlook Cached Mode and OST File Sizes. Retrieved February 19, 2020.
* https://ptylu.github.io/content/report/report.html?report=25 - Heiligenstein, L. (n.d.). REP-25: Disable Windows Event Logging. Retrieved April 7, 2022.
* https://redcanary.com/threat-detection-report/techniques/powershell/ - Red Canary. (n.d.). 2022 Threat Detection Report: PowerShell. Retrieved March 17, 2023.
* https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/ - Check Point. (2022, January 11). APT35 exploits Log4j vulnerability to distribute new modular PowerShell toolkit. Retrieved January 24, 2022.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/ - Gietzen, S. (n.d.). S3 Ransomware Part 1: Attack Vector. Retrieved April 14, 2021.
* https://sarah-edwards-xzkc.squarespace.com/blog/2020/4/30/analysis-of-apple-unified-logs-quarantine-edition-entry-6-working-from-home-remote-logins - Sarah Edwards. (2020, April 30). Analysis of Apple Unified Logs: Quarantine Edition [Entry 6] – Working From Home? Remote Logins. Retrieved August 19, 2021.
* https://sec.okta.com/scatterswine - Okta. (2022, August 25). Detecting Scatter Swine: Insights into a Relentless Phishing Campaign. Retrieved February 24, 2023.
* https://securelist.com/old-malware-tricks-to-bypass-detection-in-the-age-of-big-data/78010/ - Ishimaru, S.. (2017, April 13). Old Malware Tricks To Bypass Detection in the Age of Big Data. Retrieved May 30, 2019.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://securityintelligence.com/posts/brazking-android-malware-upgraded-targeting-brazilian-banks/ - Shahar Tavor. (n.d.). BrazKing Android Malware Upgraded and Targeting Brazilian Banks. Retrieved March 24, 2023.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://strontic.github.io/xcyclopedia/library/auditpol.exe-214E0EA1F7F7C27C82D23F183F9D23F1.html - STRONTIC. (n.d.). auditpol.exe. Retrieved September 9, 2021.
* https://support.apple.com/guide/mail/reply-to-forward-or-redirect-emails-mlhlp1010/mac - Apple. (n.d.). Reply to, forward, or redirect emails in Mail on Mac. Retrieved June 22, 2021.
* https://support.apple.com/guide/remote-desktop/set-up-a-computer-running-vnc-software-apdbed09830/mac - Apple Support. (n.d.). Set up a computer running VNC software for Remote Desktop. Retrieved August 18, 2021.
* https://support.google.com/a/answer/166870?hl=en - Google. (n.d.). Retrieved March 16, 2021.
* https://support.google.com/a/answer/7223765?hl=en - Google. (n.d.). Turn Gmail delegation on or off. Retrieved April 1, 2022.
* https://support.microsoft.com/en-us/kb/197571 - Microsoft. (2006, October). Working with the AppInit_DLLs registry value. Retrieved July 15, 2015.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.office.com/en-us/article/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790 - Microsoft. (n.d.). Introduction to Outlook Data Files (.pst and .ost). Retrieved February 19, 2020.
* https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c - svch0st. (2020, September 30). Event Log Tampering Part 1: Disrupting the EventLog Service. Retrieved September 14, 2021.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-ransomware-attacks-against-microsoft-defender/ba-p/1928947 - Tran, T. (2020, November 24). Demystifying Ransomware Attacks Against Microsoft Defender Solution. Retrieved January 26, 2022.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/cc770880.aspx - Microsoft. (n.d.). Share a Folder or Drive. Retrieved June 30, 2017.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/ - The DFIR Report. (2022, November 8). Emotet Strikes Again – LNK File Leads to Domain Wide Ransomware. Retrieved March 6, 2023.
* https://thehackernews.com/2022/05/avoslocker-ransomware-variant-using-new.html - Lakshmanan, R. (2022, May 2). AvosLocker Ransomware Variant Using New Trick to Disable Antivirus Protection. Retrieved May 17, 2022.
* https://themittenmac.com/what-does-apt-activity-look-like-on-macos/ - Jaron Bradley. (2021, November 14). What does APT Activity Look Like on macOS?. Retrieved January 19, 2022.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/ - Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.
* https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/ - Fisher, D. (2012, October 31). Final Report on DigiNotar Hack Shows Total Compromise of CA Servers. Retrieved March 6, 2017.
* https://tools.cisco.com/security/center/resources/integrity_assurance.html#23 - Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/TheDFIRReport/status/1498657772254240768 - The DFIR Report. (2022, March 1). "Change RDP port" #ContiLeaks. Retrieved March 1, 2022.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://twitter.com/rfackroyd/status/1639136000755765254 - Ackroyd, R. (2023, March 24). Twitter. Retrieved March 24, 2023.
* https://ubuntu.com/server/docs/service-sssd - Ubuntu. (n.d.). SSSD. Retrieved September 23, 2021.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://unit42.paloaltonetworks.com/domain-shadowing/ - Janos Szurdi, Rebekah Houser and Daiping Liu. (2022, September 21). Domain Shadowing: A Stealthy Use of DNS Compromise for Cybercrime. Retrieved March 7, 2023.
* https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/ - Chen, J. et al. (2021, February 3). Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes. Retrieved April 5, 2021.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a - CISA. (2021, May 6). Analysis Report (AR21-126A) FiveHands Ransomware. Retrieved June 7, 2021.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://web.archive.org/web/20160327101330/http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* https://web.archive.org/web/20170923102302/https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://web.archive.org/web/20171223000420/https://www.riskiq.com/blog/labs/lazarus-group-cryptocurrency/ - RISKIQ. (2017, December 20). Mining Insights: Infrastructure Analysis of Lazarus Group Cyber Attacks on the Cryptocurrency Industry. Retrieved July 29, 2022.
* https://web.archive.org/web/20190508170150/https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://web.archive.org/web/20211107115646/https://twitter.com/klinix5/status/1457316029114327040 - Naceri, A. (2021, November 7). Windows Server 2019 file overwrite bug. Retrieved April 7, 2022.
* https://web.archive.org/web/20220527112908/https://www.riskiq.com/blog/labs/ukraine-malware-infrastructure/ - RISKIQ. (2022, March 15). RiskIQ Threat Intelligence Roundup: Campaigns Targeting Ukraine and Global Malware Infrastructure. Retrieved July 29, 2022.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.akamai.com/blog/security/catch-me-if-you-can-javascript-obfuscation - Katz, O. (2020, October 26). Catch Me if You Can—JavaScript Obfuscation. Retrieved March 17, 2023.
* https://www.attackify.com/blog/rundll32_execution_order/ - Attackify. (n.d.). Rundll32.exe Obscurity. Retrieved August 23, 2021.
* https://www.binarydefense.com/resources/blog/emotet-evolves-with-new-wi-fi-spreader/ - Binary Defense. (n.d.). Emotet Evolves With new Wi-Fi Spreader. Retrieved September 8, 2023.
* https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/ - Bullock, B.. (2016, October 3). Attacking Exchange with MailSniper. Retrieved October 6, 2019.
* https://www.blackhillsinfosec.com/bypass-web-proxy-filtering/ - Fehrman, B. (2017, April 13). How to Bypass Web-Proxy Filtering. Retrieved September 20, 2019.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.bleepingcomputer.com/news/security/hackers-steal-wifi-passwords-using-upgraded-agent-tesla-malware/ - Sergiu Gatlan. (2020, April 16). Hackers steal WiFi passwords using upgraded Agent Tesla malware. Retrieved September 8, 2023.
* https://www.bleepingcomputer.com/news/security/new-godlua-malware-evades-traffic-monitoring-via-dns-over-https/ - Gatlan, S. (2019, July 3). New Godlua Malware Evades Traffic Monitoring via DNS over HTTPS. Retrieved March 15, 2020.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/ - Baskin, B. (2020, July 8). TAU Threat Discovery: Conti Ransomware. Retrieved February 17, 2021.
* https://www.circl.lu/services/passive-dns/ - CIRCL Computer Incident Response Center. (n.d.). Passive DNS. Retrieved October 20, 2020.
* https://www.cisa.gov/uscert/ncas/alerts/aa21-200b - CISA. (2021, August 20). Alert (AA21-200B) Chinese State-Sponsored Cyber Operations: Observed TTPs. Retrieved June 21, 2022.
* https://www.cisa.gov/uscert/ncas/alerts/aa22-074a - Cybersecurity and Infrastructure Security Agency. (2022, March 15). Russian State-Sponsored Cyber Actors Gain Network Access by Exploiting Default Multifactor Authentication Protocols and “PrintNightmare” Vulnerability. Retrieved March 16, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_monitor_permit_list_through_show_process_memory.html#wp3599497760 - Cisco. (2022, August 16). show processes - . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_protocols_through_showmon.html#wp2760878733 - Cisco. (2022, August 16). show running-config - Cisco IOS Configuration Fundamentals Command Reference . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html - Cisco. (2023, March 7). Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-t2.html#wp1047035630 - Cisco. (2023, March 6). username - Cisco IOS Security Command Reference: Commands S to Z. Retrieved July 13, 2022.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/ - Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.
* https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/ - Mudge, R. (2017, February 6). High-reputation Redirectors and Domain Fronting. Retrieved July 11, 2022.
* https://www.comparitech.com/blog/vpn-privacy/350-million-customer-records-exposed-online/ - Bischoff, P. (2020, October 15). Broadvoice database of more than 350 million customer records exposed online. Retrieved October 20, 2020.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.coretechnologies.com/blog/windows-services/eventlog/ - Core Technologies. (2021, May 24). Essential Windows Services: EventLog / Windows Event Log. Retrieved September 14, 2021.
* https://www.crowdstrike.com/blog/hiding-in-plain-sight-using-the-office-365-activities-api-to-investigate-business-email-compromises/ - Crowdstrike. (2018, July 18). Hiding in Plain Sight: Using the Office 365 Activities API to Investigate Business Email Compromises. Retrieved January 19, 2020.
* https://www.crowdstrike.com/blog/how-doppelpaymer-hunts-and-kills-windows-processes/ - Hurley, S. (2021, December 7). Critical Hit: How DoppelPaymer Hunts and Kills Windows Processes. Retrieved January 26, 2022.
* https://www.crowdstrike.com/blog/targeted-dharma-ransomware-intrusions-exhibit-consistent-techniques/ - Loui, E. Scheuerman, K. et al. (2020, April 16). Targeted Dharma Ransomware Intrusions Exhibit Consistent Techniques. Retrieved January 26, 2022.
* https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.
* https://www.cynet.com/attack-techniques-hands-on/defense-evasion-techniques/ - Ariel silver. (2022, February 1). Defense Evasion Techniques. Retrieved April 8, 2022.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.elastic.co/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.elastic.co/guide/en/security/7.17/shortcut-file-written-or-modified-for-persistence.html#shortcut-file-written-or-modified-for-persistence - Elastic. (n.d.). Shortcut File Written or Modified for Persistence. Retrieved June 1, 2022.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-2.html - Glyer, C., Kazanciyan, R. (2012, August 22). The “Hikit” Rootkit: Advanced and Persistent Attack Techniques (Part 2). Retrieved May 4, 2020.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html - Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
* https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html - Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.
* https://www.fireeye.com/blog/threat-research/2021/01/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452.html - Mike Burns, Matthew McWhirt, Douglas Bienstock, Nick Bennett. (2021, January 19). Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452. Retrieved September 25, 2021.
* https://www.fireeye.com/content/dam/collateral/en/mtrends-2018.pdf - Mandiant. (2018). Mandiant M-Trends 2018. Retrieved July 9, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.forbes.com/sites/runasandvik/2014/01/14/attackers-scrape-github-for-cloud-service-credentials-hijack-account-to-mine-virtual-currency/#242c479d3196 - Sandvik, R. (2014, January 14). Attackers Scrape GitHub For Cloud Service Credentials, Hijack Account To Mine Virtual Currency. Retrieved October 19, 2020.
* https://www.fortinet.com/blog/psirt-blogs/fg-ir-22-369-psirt-analysis -  Guillaume Lovet and Alex Kong. (2023, March 9). Analysis of FG-IR-22-369. Retrieved May 15, 2023.
* https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html - Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.geeksforgeeks.org/wi-fi-password-connected-networks-windowslinux/ - Geeks for Geeks. (n.d.). Wi-Fi Password of All Connected Networks in Windows/Linux. Retrieved September 8, 2023.
* https://www.hackers-arise.com/email-scraping-and-maltego - Hackers Arise. (n.d.). Email Scraping and Maltego. Retrieved October 20, 2020.
* https://www.hackingarticles.in/defense-evasion-windows-event-logging-t1562-002/ - Chandel, R. (2021, April 22). Defense Evasion: Windows Event Logging (T1562.002). Retrieved September 14, 2021.
* https://www.icann.org/groups/ssac/documents/sac-007-en - ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.
* https://www.intezer.com/blog/malware-analysis/kud-i-enter-your-server-new-vulnerabilities-in-microsoft-azure/ - Paul Litvak. (2020, October 8). Kud I Enter Your Server? New Vulnerabilities in Microsoft Azure. Retrieved August 18, 2022.
* https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection - Red Teaming Experiments. (n.d.). Module Stomping for Shellcode Injection. Retrieved July 14, 2022.
* https://www.malwarebytes.com/blog/news/2020/04/new-agenttesla-variant-steals-wifi-credentials - Hossein Jazi. (2020, April 16). New AgentTesla variant steals WiFi credentials. Retrieved September 8, 2023.
* https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits - Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022.
* https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem - Marvi, A. et al.. (2023, March 16). Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation. Retrieved March 22, 2023.
* https://www.mandiant.com/resources/blog/url-obfuscation-schema-abuse - Nick Simonian. (2023, May 22). Don't @ Me: URL Obfuscation Through Schema Abuse. Retrieved August 4, 2023.
* https://www.mandiant.com/resources/chasing-avaddon-ransomware - Hernandez, A. S. Tarter, P. Ocamp, E. J. (2022, January 19). One Source to Rule Them All: Chasing AVADDON Ransomware. Retrieved January 26, 2022.
* https://www.mandiant.com/resources/supply-chain-analysis-from-quartermaster-to-sunshop - FireEye. (2014). SUPPLY CHAIN ANALYSIS: From Quartermaster to SunshopFireEye. Retrieved March 6, 2017.
* https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/ - MDSec Research. (2017, July). Categorisation is not a Security Boundary. Retrieved September 20, 2019.
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - MDSec Research. (2020, December). Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams. Retrieved September 29, 2021.
* https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/ - Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.
* https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/ - Weizman, Y. (2020, April 2). Threat Matrix for Kubernetes. Retrieved March 30, 2021.
* https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/ - Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.
* https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/ - Microsoft. (2022, March 22). DEV-0537 criminal actor targeting organizations for data exfiltration and destruction. Retrieved March 23, 2022.
* https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ - Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.
* https://www.netskope.com/blog/a-big-catch-cloud-phishing-from-google-app-engine-and-azure-app-service - Ashwin Vamshi. (2020, August 12). A Big Catch: Cloud Phishing from Google App Engine and Azure App Service. Retrieved August 18, 2022.
* https://www.netskope.com/blog/targeted-attacks-abusing-google-cloud-platform-open-redirection - Ashwin Vamshi. (2019, January 24). Targeted Attacks Abusing Google Cloud Platform Open Redirection. Retrieved August 18, 2022.
* https://www.opm.gov/cybersecurity/cybersecurity-incidents/ - Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved October 20, 2020.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling - Palo Alto Networks. (n.d.). What Is DNS Tunneling?. Retrieved March 15, 2020.
* https://www.pcmag.com/news/hackers-try-to-phish-united-nations-staffers-with-fake-login-pages - Kan, M. (2019, October 24). Hackers Try to Phish United Nations Staffers With Fake Login Pages. Retrieved October 20, 2020.
* https://www.prevailion.com/darkwatchman-new-fileless-techniques/ - Smith, S., Stafford, M. (2021, December 14). DarkWatchman: A new evolution in fileless techniques. Retrieved January 10, 2022.
* https://www.proofpoint.com/sites/default/files/threat-reports/pfpt-us-tr-human-factor-report.pdf - Proofpoint. (n.d.). The Human Factor 2023: Analyzing the cyber attack chain. Retrieved July 20, 2023.
* https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain - Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.
* https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta407-silent-librarian - Proofpoint Threat Insight Team. (2019, September 5). Threat Actor Profile: TA407, the Silent Librarian. Retrieved February 3, 2021.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/cobalt-strike-servers/ - Insikt Group. (2019, June 18). A Multi-Method Approach to Identifying Rogue Cobalt Strike Servers. Retrieved October 16, 2020.
* https://www.recordedfuture.com/identifying-cobalt-strike-servers/ - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved October 16, 2020.
* https://www.sec.gov/edgar/search-and-access - U.S. SEC. (n.d.). EDGAR - Search and Access. Retrieved August 27, 2021.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.securityweek.com/iranian-hackers-targeted-us-officials-elaborate-social-media-attack-operation - Lennon, M. (2014, May 29). Iranian Hackers Targeted US Officials in Elaborate Social Media Attack Operation. Retrieved March 1, 2017.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.slideshare.net/DouglasBienstock/shmoocon-2019-becs-and-beyond-investigating-and-defending-office-365 - Bienstock, D.. (2019). BECS and Beyond: Investigating and Defending O365. Retrieved September 13, 2019.
* https://www.splunk.com/en_us/blog/security/tall-tales-of-hunting-with-tls-ssl-certificates.html - Kovar, R. (2017, December 11). Tall Tales of Hunting with TLS/SSL Certificates. Retrieved October 16, 2020.
* https://www.ssh.com/ssh/tunneling - SSH.COM. (n.d.). SSH tunnel. Retrieved March 15, 2020.
* https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage - Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.technologyreview.com/2013/08/21/83143/dropbox-and-similar-services-can-sync-malware/ - David Talbot. (2013, August 21). Dropbox and Similar Services Can Sync Malware. Retrieved May 31, 2023.
* https://www.thepythoncode.com/article/executing-bash-commands-remotely-in-python - Abdou Rockikz. (2020, July). How to Execute Shell Commands in a Remote Machine in Python. Retrieved July 26, 2021.
* https://www.theregister.com/2015/02/28/uber_subpoenas_github_for_hacker_details/ - McCarthy, K. (2015, February 28). FORK ME! Uber hauls GitHub into court to find who hacked database of 50,000 drivers. Retrieved October 19, 2020.
* https://www.theregister.com/2017/09/26/deloitte_leak_github_and_google/ - Thomson, I. (2017, September 26). Deloitte is a sitting duck: Key systems with RDP open, VPN and proxy 'login details leaked'. Retrieved October 19, 2020.
* https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html - Remillano II, A., et al. (2020, June 20). XORDDoS, Kaiji Variants Target Exposed Docker Servers. Retrieved April 5, 2021.
* https://www.trendmicro.com/en_us/research/20/i/tricky-forms-of-phishing.html - Babon, P. (2020, September 3). Tricky 'Forms' of Phishing. Retrieved October 20, 2020.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing - Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.
* https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ - Franklin Smith. (n.d.). Windows Security Log Events. Retrieved February 21, 2020.
* https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4670 - Franklin Smith, R. (n.d.). Windows Security Log Event ID 4670. Retrieved November 4, 2019.
* https://www.us-cert.gov/ncas/alerts/AA18-337A - US-CERT. (2018, December 3). Alert (AA18-337A): SamSam Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.us-cert.gov/ncas/alerts/TA16-091A - US-CERT. (2016, March 31). Alert (TA16-091A): Ransomware and Recent Variants. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-086A - US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.virustotal.com/en/faq/ - VirusTotal. (n.d.). VirusTotal FAQ. Retrieved May 23, 2019.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/ - Lassalle, D., et al. (2017, November 6). OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society. Retrieved November 6, 2017.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/ - Adair, S., Lancaster, T., Volexity Threat Research. (2022, June 15). DriftingCloud: Zero-Day Sophos Firewall Exploitation and an Insidious Breach. Retrieved July 1, 2022.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/ - Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf - Kafka, F. (2018, January). ESET's Guide to Deobfuscating and Devirtualizing FinFisher. Retrieved August 12, 2019.
* https://www.whois.net/ - NTT America. (n.d.). Whois Lookup. Retrieved October 20, 2020.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.wired.com/story/russia-ukraine-cyberattacks-mandiant/ - Greenberg, A. (2022, November 10). Russia’s New Cyberwarfare in Ukraine Is Fast, Dirty, and Relentless. Retrieved March 22, 2023.
* https://www.youtube.com/watch?v=nJ0UsyiUEqQ - French, D., Filar, B.. (2020, March 21). A Chain Is No Stronger Than Its Weakest LNK. Retrieved November 30, 2020.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www.zscaler.com/blogs/security-research/fake-sites-stealing-steam-credentials - ZScaler. (2020, February 11). Fake Sites Stealing Steam Credentials. Retrieved March 8, 2023.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* BITSAdmin - 1
* CrackMapExec - 1
* Empire - 1
* Impacket - 1
* Mimikatz - 2
* NBTscan - 1
* Net - 2
* PowerSploit - 1
* PsExec - 2
* Pupy - 1
* Tor - 1
* Windows Credential Editor - 2
* at - 1
* ftp - 1
* netsh - 1
* pwdump - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* http://www.ampliasecurity.com/research/wcefaq.html - Amplia Security. (n.d.). Windows Credentials Editor (WCE) F.A.Q.. Retrieved December 17, 2015.
* http://www.dtic.mil/dtic/tr/fulltext/u2/a465464.pdf - Roger Dingledine, Nick Mathewson and Paul Syverson. (2004). Tor: The Second-Generation Onion Router. Retrieved December 21, 2017.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ftp - Microsoft. (2021, July 21). ftp. Retrieved February 25, 2022.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (2007, August 9). pwdump. Retrieved June 22, 2016.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference - byt3bl33d3r. (2018, September 8). SMB: Command Reference. Retrieved July 17, 2020.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/n1nj4sec/pupy - Nicolas Verdier. (n.d.). Retrieved January 29, 2018.
* https://linux.die.net/man/1/ftp - N/A. (n.d.). ftp(1) - Linux man page. Retrieved February 25, 2022.
* https://man7.org/linux/man-pages/man1/at.1p.html - IEEE/The Open Group. (2017). at(1p) — Linux manual page. Retrieved February 25, 2022.
* https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html - Bezroutchko, A. (2019, November 19). NBTscan man page. Retrieved March 17, 2021.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://sectools.org/tool/nbtscan/ - SecTools. (2003, June 11). NBTscan. Retrieved March 17, 2021.
* https://technet.microsoft.com/en-us/library/bb490866.aspx - Microsoft. (n.d.). At. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/bb490939.aspx - Microsoft. (n.d.). Using Netsh. Retrieved February 13, 2017.
* https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html - Hawley et al. (2019, January 29). APT39: An Iranian Cyber Espionage Group Focused on Personal Information. Retrieved February 19, 2019.
* https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive/ - Pilkington, M. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://www.secureauth.com/labs/open-source-tools/impacket - SecureAuth. (n.d.).  Retrieved January 15, 2019.
* https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments - Symantec DeepSight Adversary Intelligence Team. (2019, June 20). Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments. Retrieved July 8, 2019.

# Validate the following malware

* ASPXSpy - 1
* BADFLICK - 1
* BLACKCOFFEE - 1
* Cadelspy - 1
* CharmPower - 1
* China Chopper - 1
* Cobalt Strike - 1
* Derusbi - 1
* DownPaper - 1
* HOMEFRY - 1
* MURKYTOP - 1
* Mafalda - 1
* MechaFlounder - 1
* NanHaiShu - 1
* Orz - 1
* PowerLess - 1
* Remexi - 1
* gh0st RAT - 1
* metaMain - 1

# Review the following malware references

* http://www.clearskysec.com/wp-content/uploads/2017/12/Charming_Kitten_2017.pdf - ClearSky Cyber Security. (2017, December). Charming Kitten. Retrieved December 27, 2017.
* https://assets.sentinelone.com/sentinellabs22/metador#page=1 - Ehrlich, A., et al. (2022, September). THE MYSTERY OF METADOR | AN UNATTRIBUTED THREAT HIDING IN TELCOS, ISPS, AND UNIVERSITIES. Retrieved January 23, 2023.
* https://docs.google.com/document/d/1e9ZTW9b71YwFWS_18ZwDAxa-cYbV8q1wUefmKZLYVsA/edit#heading=h.lmnbtht1ikzm - SentinelLabs. (2022, September 22). Metador Technical Appendix. Retrieved April 4, 2023.
* https://paper.seebug.org/papers/APT/APT_CyberCriminal_Campagin/2016/2016.02.29.Turbo_Campaign_Derusbi/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/ - Check Point. (2022, January 11). APT35 exploits Log4j vulnerability to distribute new modular PowerShell toolkit. Retrieved January 24, 2022.
* https://research.nccgroup.com/2018/04/17/decoding-network-data-from-a-gh0st-rat-variant/ - Pantazopoulos, N. (2018, April 17). Decoding network data from a Gh0st RAT variant. Retrieved November 2, 2018.
* https://securelist.com/chafer-used-remexi-malware/89538/ - Legezo, D. (2019, January 30). Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities. Retrieved April 17, 2019.
* https://unit42.paloaltonetworks.com/new-python-based-payload-mechaflounder-used-by-chafer/ - Falcone, R. (2019, March 4). New Python-Based Payload MechaFlounder Used by Chafer. Retrieved May 27, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa21-200a - CISA. (2021, July 19). (AA21-200A) Joint Cybersecurity Advisory – Tactics, Techniques, and Procedures of Indicted APT40 Actors Associated with China’s MSS Hainan State Security Department. Retrieved August 12, 2021.
* https://web.archive.org/web/20210825130434/https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://web.archive.org/web/20230115144216/http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* https://www.accenture.com/us-en/blogs/cyber-defense/mudcarps-focus-on-submarine-technologies - Accenture iDefense Unit. (2019, March 5). Mudcarp's Focus on Submarine Technologies. Retrieved August 24, 2021.
* https://www.arbornetworks.com/blog/asert/musical-chairs-playing-tetris/ - Sabo, S. (2018, February 15). Musical Chairs Playing Tetris. Retrieved February 19, 2018.
* https://www.cybereason.com/blog/research/powerless-trojan-iranian-apt-phosphorus-adds-new-powershell-backdoor-for-espionage - Cybereason Nocturnus. (2022, February 1). PowerLess Trojan: Iranian APT Phosphorus Adds New PowerShell Backdoor for Espionage. Retrieved June 1, 2022.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2015/07/demonstrating_hustle.html - FireEye Threat Intelligence. (2015, July 13). Demonstrating Hustle, Chinese APT Groups Quickly Use Zero-Day Vulnerability (CVE-2015-5119) Following Hacking Team Leak. Retrieved January 25, 2016.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.rapid7.com/blog/post/2021/03/23/defending-against-the-zero-day-analyzing-attacker-behavior-post-exploitation-of-microsoft-exchange/ - Eoin Miller. (2021, March 23). Defending Against the Zero Day: Analyzing Attacker Behavior Post-Exploitation of Microsoft Exchange. Retrieved October 27, 2022.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/connect/blogs/iran-based-attackers-use-back-door-threats-spy-middle-eastern-targets - Symantec Security Response. (2015, December 7). Iran-based attackers use back door threats to spy on Middle Eastern targets. Retrieved April 17, 2019.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.
