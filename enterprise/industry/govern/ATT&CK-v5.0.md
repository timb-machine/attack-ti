threat-crank.py 0.2.1
I: searching for industries that match .* govern.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v5.0/enterprise-attack/enterprise-attack.json
# Threat groups

* APT12
* APT17
* APT18
* APT29
* APT30
* APT32
* Axiom
* BRONZE BUTLER
* DarkHydrus
* Deep Panda
* Dragonfly 2.0
* Gallmaker
* Gamaredon Group
* Gorgon Group
* Lazarus Group
* Leafminer
* Leviathan
* Lotus Blossom
* Magic Hound
* MuddyWater
* OilRig
* PLATINUM
* Patchwork
* Sandworm Team
* Scarlet Mimic
* Sowbug
* Stealth Falcon
* Taidoor
* The White Company
* Threat Group-3390
* Tropic Trooper
* Turla
* menuPass

# Validate the following attacks

* Access Token Manipulation - 2
* Accessibility Features - 3
* Account Discovery - 6
* Account Manipulation - 2
* Application Deployment Software - 1
* Application Window Discovery - 1
* Automated Collection - 3
* BITS Jobs - 2
* Binary Padding - 4
* Bootkit - 1
* Brute Force - 5
* Bypass User Account Control - 5
* CMSTP - 1
* Code Signing - 1
* Command-Line Interface - 15
* Commonly Used Port - 8
* Compile After Delivery - 1
* Compiled HTML File - 2
* Connection Proxy - 4
* Create Account - 2
* Credential Dumping - 16
* Credentials in Files - 2
* Custom Command and Control Protocol - 3
* Custom Cryptographic Protocol - 2
* DLL Search Order Hijacking - 2
* DLL Side-Loading - 5
* Data Compressed - 10
* Data Destruction - 1
* Data Encoding - 3
* Data Encrypted - 7
* Data Obfuscation - 1
* Data Staged - 6
* Data Transfer Size Limits - 1
* Data from Local System - 8
* Data from Network Shared Drive - 3
* Data from Removable Media - 2
* Deobfuscate/Decode Files or Information - 9
* Disabling Security Tools - 5
* Disk Content Wipe - 1
* Disk Structure Wipe - 1
* Distributed Component Object Model - 1
* Domain Fronting - 1
* Drive-by Compromise - 8
* Dynamic Data Exchange - 3
* Email Collection - 3
* Execution through API - 2
* Exfiltration Over Alternative Protocol - 3
* Exfiltration Over Command and Control Channel - 4
* Exploit Public-Facing Application - 1
* Exploitation for Client Execution - 10
* Exploitation for Privilege Escalation - 3
* Exploitation of Remote Services - 1
* External Remote Services - 4
* Fallback Channels - 2
* File Deletion - 12
* File Permissions Modification - 1
* File and Directory Discovery - 11
* Forced Authentication - 2
* Hidden Files and Directories - 3
* Hooking - 1
* Indicator Removal from Tools - 4
* Indicator Removal on Host - 3
* Input Capture - 7
* Masquerading - 9
* Modify Existing Service - 1
* Modify Registry - 6
* Mshta - 2
* Multi-Stage Channels - 1
* Multi-hop Proxy - 1
* Multiband Communication - 1
* NTFS File Attributes - 1
* Network Service Scanning - 6
* Network Share Connection Removal - 1
* Network Share Discovery - 3
* New Service - 4
* Obfuscated Files or Information - 15
* Office Application Startup - 1
* Pass the Hash - 1
* Pass the Ticket - 3
* Password Policy Discovery - 1
* Peripheral Device Discovery - 1
* Permission Groups Discovery - 2
* PowerShell - 17
* Process Discovery - 8
* Process Hollowing - 3
* Process Injection - 6
* Query Registry - 7
* Redundant Access - 3
* Registry Run Keys / Startup Folder - 13
* Regsvr32 - 3
* Remote Desktop Protocol - 7
* Remote File Copy - 16
* Remote Services - 3
* Remote System Discovery - 8
* Resource Hijacking - 1
* Rundll32 - 2
* Scheduled Task - 10
* Screen Capture - 5
* Scripting - 18
* Security Software Discovery - 4
* Service Execution - 1
* Service Stop - 1
* Shortcut Modification - 5
* Signed Script Proxy Execution - 1
* Software Packing - 4
* Spearphishing Attachment - 19
* Spearphishing Link - 8
* Spearphishing via Service - 1
* Standard Application Layer Protocol - 11
* Standard Cryptographic Protocol - 6
* Standard Non-Application Layer Protocol - 2
* System Information Discovery - 12
* System Network Configuration Discovery - 10
* System Network Connections Discovery - 5
* System Owner/User Discovery - 10
* System Service Discovery - 2
* System Time Discovery - 4
* Template Injection - 3
* Timestomp - 2
* Trusted Relationship - 1
* Uncommonly Used Port - 4
* User Execution - 18
* Valid Accounts - 7
* Virtualization/Sandbox Evasion - 1
* Web Service - 6
* Web Shell - 6
* Windows Admin Shares - 4
* Windows Management Instrumentation - 10
* Windows Management Instrumentation Event Subscription - 3
* Windows Remote Management - 1
* Winlogon Helper DLL - 2

# Validate the following phases

* collection - 37
* command-and-control - 72
* credential-access - 35
* defense-evasion - 155
* discovery - 102
* execution - 116
* exfiltration - 25
* impact - 5
* initial-access - 49
* lateral-movement - 38
* persistence - 75
* privilege-escalation - 49

# Validate the following platforms

* Android - 1
* Linux - 454
* Windows - 813
* macOS - 459

# Validate the following defences

* Anti-virus - 62
* Application whitelisting - 23
* Binary Analysis - 7
* Data Execution Prevention - 18
* Digital Certificate Validation - 10
* Exploit Prevention - 18
* File monitoring - 5
* File system access controls - 1
* Firewall - 15
* Heuristic detection - 4
* Host forensic analysis - 43
* Host intrusion prevention systems - 44
* Log analysis - 33
* Network intrusion detection system - 19
* Process whitelisting - 59
* Signature-based detection - 43
* Static File Analysis - 5
* System access controls - 7
* Whitelisting by file name or path - 27
* Windows User Account Control - 6

# Validate the following data sources

* API monitoring - 74
* Access tokens - 2
* Anti-virus - 47
* Application logs - 5
* Authentication logs - 69
* Binary file metadata - 72
* DLL monitoring - 30
* DNS records - 8
* Data loss prevention - 3
* Detonation chamber - 27
* Email gateway - 45
* Environment variable - 15
* File monitoring - 277
* Host network interface - 11
* Kernel drivers - 10
* Loaded DLLs - 26
* MBR - 2
* Mail server - 27
* Malware reverse engineering - 41
* Named Pipes - 6
* Netflow/Enclave netflow - 101
* Network device logs - 12
* Network intrusion detection system - 50
* Network protocol analysis - 74
* Packet capture - 122
* PowerShell logs - 33
* Process command-line parameters - 351
* Process monitoring - 480
* Process use of network - 132
* SSL/TLS inspection - 45
* Services - 5
* System calls - 15
* Third-party application logs - 1
* User interface - 7
* VBR - 1
* WMI Objects - 3
* Web application firewall logs - 1
* Web logs - 4
* Web proxy - 17
* Windows Error Reporting - 4
* Windows Registry - 81
* Windows event logs - 51

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.crowdstrike.com/registry-analysis-with-crowdresponse/ - Tilbury, C. (2014, August 28). Registry Analysis with CrowdResponse. Retrieved November 12, 2014.
* http://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos - Deply, B. (2014, January 13). Pass the ticket. Retrieved June 2, 2016.
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/ - Wrightson, T. (2012, January 2). CAPTURING WINDOWS 7 CREDENTIALS AT LOGON USING CUSTOM CREDENTIAL PROVIDER. Retrieved November 12, 2014.
* http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html - Hawkins, J. (2018, July 18). Executing Macros From a DOCX With Remote Template Injection. Retrieved October 12, 2018.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/jepayne/archive/2015/11/24/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem.aspx - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* http://blogs.technet.com/b/jepayne/archive/2015/11/27/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts.aspx - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* http://blogs.technet.com/b/msrc/archive/2010/08/21/microsoft-security-advisory-2269637-released.aspx - Microsoft. (2010, August 22). Microsoft Security Advisory 2269637 Released. Retrieved December 5, 2014.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html - CG. (2014, May 20). Mimikatz Against Virtual Machine Memory Part 1. Retrieved November 12, 2014.
* http://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf - Campbell, C. (2014). The Secret Life of Krbtgt. Retrieved December 4, 2014.
* http://en.wikipedia.org/wiki/Executable_compression - Executable compression. (n.d.). Retrieved December 4, 2014.
* http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29 - Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.
* http://hick.org/code/skape/papers/needle.txt - skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.
* http://journeyintoir.blogspot.com/2012/12/extracting-zeroaccess-from-ntfs.html - Harrell, C. (2012, December 11). Extracting ZeroAccess from NTFS Extended Attributes. Retrieved June 3, 2016.
* http://msdn.microsoft.com/en-US/library/ms682586 - Microsoft. (n.d.). Dynamic-Link Library Search Order. Retrieved November 30, 2014.
* http://msdn.microsoft.com/en-US/library/ms682600 - Microsoft. (n.d.). Dynamic-Link Library Redirection. Retrieved December 5, 2014.
* http://msdn.microsoft.com/en-us/library/aa364404 - Microsoft. (n.d.). File Streams. Retrieved December 2, 2014.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://msdn.microsoft.com/en-us/library/aa384426 - Microsoft. (n.d.). Windows Remote Management. Retrieved November 12, 2014.
* http://msdn.microsoft.com/en-us/library/ms682425 - Microsoft. (n.d.). CreateProcess function. Retrieved December 5, 2014.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://phrack.org/issues/51/8.html - halflife. (1997, September 1). Shared Library Redirection Techniques. Retrieved December 20, 2017.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/KB/170292 - Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://vxer.org/lib/vrn00.html - O'Neill, R. (2009, May). Modern Day ELF Runtime infection via GOT poisoning. Retrieved December 20, 2017.
* http://windowsir.blogspot.com/2013/07/howto-determinedetect-use-of-anti.html - Carvey, H. (2013, July 23). HowTo: Determine/Detect the use of Anti-Forensics Techniques. Retrieved June 3, 2016.
* http://www.autosectools.com/process-hollowing.pdf - Leitch, J. (n.d.). Process Hollowing. Retrieved November 12, 2014.
* http://www.blackhillsinfosec.com/?p=4645 - Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.
* http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html - stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.
* http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/ - Seetharaman, N. (2018, July 7). Detecting CMSTP-Enabled Code Execution and UAC Bypass With Sysmon.. Retrieved August 6, 2018.
* http://www.gmer.net/ - GMER. (n.d.). GMER. Retrieved December 12, 2017.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.hexacorn.com/blog/2014/04/16/beyond-good-ol-run-key-part-10/ - Hexacorn. (2014, April 16). Beyond good ol’ Run key, Part 10. Retrieved July 3, 2017.
* http://www.hexacorn.com/blog/2017/04/19/beyond-good-ol-run-key-part-62/ - Hexacorn. (2017, April 17). Beyond good ol’ Run key, Part 62. Retrieved July 3, 2017.
* http://www.icir.org/vern/papers/meek-PETS-2015.pdf - David Fifield, Chang Lan, Rod Hynes, Percy Wegmann, and Vern Paxson. (2015). Blocking-resistant communication through domain fronting. Retrieved November 20, 2017.
* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html - Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.metasploit.com - Metasploit. (n.d.). Retrieved December 4, 2014.
* http://www.netsec.colostate.edu/~zhang/DetectingEncryptedBotnetTraffic.pdf - Zhang, H., Papadopoulos, C., & Massey, D. (2013, April). Detecting encrypted botnet traffic. Retrieved August 19, 2015.
* http://www.pretentiousname.com/misc/win7_uac_whitelist2.html - Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* http://www.symantec.com/connect/blogs/are-mbr-infections-back-fashion - Lau, H. (2011, August 8). Are MBR Infections Back in Fashion? (Infographic). Retrieved November 13, 2014.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://access.redhat.com/documentation/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://adsecurity.org/?p=556 - Metcalf, S. (2014, November 22). Mimikatz and Active Directory Kerberos Attacks. Retrieved June 2, 2016.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/ - Mudge, R. (n.d.). Windows Access Tokens and Alternate Credentials. Retrieved April 21, 2017.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order - Langendorf, S. (2013, September 24). Windows Registry Persistence, Part 2: The Run Keys and Search-Order. Retrieved April 11, 2018.
* https://blog.didierstevens.com/2017/11/13/webdav-traffic-to-malicious-sites/ - Stevens, D. (2017, November 13). WebDAV Traffic To Malicious Sites. Retrieved December 21, 2017.
* https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows - Liberman, T. (2016, October 27). ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWS. Retrieved December 8, 2017.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/101/2015/07/introduction-to-alternate-data-streams/ - Arntz, P. (2015, July 22). Introduction to Alternate Data Streams. Retrieved March 21, 2018.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/ - Segura, J. (2017, October 13). Decoy Microsoft Word document delivers malware through a RAT. Retrieved July 21, 2018.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.talosintelligence.com/2017/07/template-injection.html - Baird, S. et al.. (2017, July 7). Attack on Critical Infrastructure Leverages Template Injection. Retrieved July 21, 2018.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/plead-targeted-attacks-against-taiwanese-government-agencies-2/ - Alintanahin, K.. (2014, May 23). PLEAD Targeted Attacks Against Taiwanese Government Agencies. Retrieved April 22, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/ - Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askcore/2010/08/25/ntfs-file-attributes/ - Hughes, J. (2010, August 25). NTFS File Attributes. Retrieved March 21, 2018.
* https://blogs.technet.microsoft.com/askcore/2013/03/24/alternate-data-streams-in-ntfs/ - Marlin, J. (2013, March 24). Alternate Data Streams in NTFS. Retrieved March 21, 2018.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://cert.europa.eu/static/WhitePapers/UPDATED%20-%20CERT-EU_Security_Whitepaper_2014-007_Kerberos_Golden_Ticket_Protection_v1_4.pdf - Abolins, D., Boldea, C., Socha, K., Soria-Machado, M. (2016, April 26). Kerberos Golden Ticket Protection. Retrieved July 13, 2017.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://docs.microsoft.com/en-us/office365/securitycompliance/detect-and-remediate-outlook-rules-forms-attack - Fox, C., Vangel, D. (2018, April 22). Detect and Remediate Outlook Rules and Custom Forms Injections Attacks in Office 365. Retrieved February 4, 2019.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749211(v=ws.10) - Microsoft. (2008, July 25). Credential Security Service Provider and SSO for Terminal Services Logon. Retrieved April 11, 2018.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/windows/desktop/com/dcom-security-enhancements-in-windows-xp-service-pack-2-and-windows-server-2003-service-pack-1 - Microsoft. (n.d.). DCOM Security Enhancements in Windows XP Service Pack 2 and Windows Server 2003 Service Pack 1. Retrieved November 22, 2017.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts - Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.
* https://docs.microsoft.com/powershell/module/microsoft.powershell.management/clear-eventlog - Microsoft. (n.d.). Clear-EventLog. Retrieved July 2, 2018.
* https://docs.microsoft.com/powershell/module/microsoft.powershell.security/set-acl - Microsoft. (n.d.). Set-Acl. Retrieved August 19, 2018.
* https://docs.microsoft.com/previous-versions/office/developer/office-2007/aa338205(v=office.12) - Microsoft. (2014, July 9). Introducing the Office (2007) Open XML File Formats. Retrieved July 20, 2018.
* https://docs.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-1-4-sdk - Microsoft. (2018, May 30). Microsoft HTML Help 1.4. Retrieved October 3, 2018.
* https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc786431(v=ws.10) - Microsoft. (2009, October 8). How Connection Manager Works. Retrieved April 11, 2018.
* https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc753662(v=ws.11) - Microsoft. (2013, February 22). Set up Recovery Actions to Take Place When a Service Fails. Retrieved April 9, 2018.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
* https://docs.microsoft.com/windows-server/administration/windows-commands/attrib - Plett, C. et al.. (2017, October 15). attrib. Retrieved August 19, 2018.
* https://docs.microsoft.com/windows-server/administration/windows-commands/icacls - Plett, C. et al.. (2017, October 17). icacls. Retrieved August 19, 2018.
* https://docs.microsoft.com/windows-server/administration/windows-commands/takeown - Plett, C. et al.. (2017, October 15). takeown. Retrieved August 19, 2018.
* https://docs.microsoft.com/windows-server/administration/windows-commands/wevtutil - Plett, C. et al.. (2017, October 16). wevtutil. Retrieved July 2, 2018.
* https://docs.microsoft.com/windows/desktop/fileio/file-security-and-access-rights - Microsoft. (2018, May 30). File Security and Access Rights. Retrieved August 19, 2018.
* https://docs.microsoft.com/windows/desktop/secauthz/dacls-and-aces - Microsoft. (2018, May 30). DACLs and ACEs. Retrieved August 19, 2018.
* https://docs.microsoft.com/windows/device-security/auditing/event-4720 - Lich, B., Miroshnikov, A. (2017, April 5). 4720(S): A user account was created. Retrieved June 30, 2017.
* https://docs.microsoft.com/windows/device-security/auditing/event-4738 - Lich, B., Miroshnikov, A. (2017, April 5). 4738(S): A user account was changed. Retrieved June 30, 2017.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697 - Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection - Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.
* https://en.wikipedia.org/wiki/Active_Directory - Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Binary-to-text_encoding - Wikipedia. (2016, December 26). Binary-to-text encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Character_encoding - Wikipedia. (2017, February 19). Character Encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Command-line_interface - Wikipedia. (2016, June 26). Command-line interface. Retrieved June 27, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/HTML_Application - Wikipedia. (2017, October 14). HTML Application. Retrieved October 27, 2017.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Password_cracking - Wikipedia. (n.d.). Password cracking. Retrieved December 23, 2015.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://en.wikipedia.org/wiki/Shared_resource - Wikipedia. (2017, April 15). Shared resource. Retrieved June 30, 2017.
* https://en.wikipedia.org/wiki/Windows_Registry - Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.
* https://enigma0x3.net/2014/01/23/maintaining-access-with-normal-dotm/comment-page-1/ - Nelson, M. (2014, January 23). Maintaining Access with normal.dotm. Retrieved July 3, 2017.
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/ - Nelson, M. (2017, January 5). Lateral Movement using the MMC20 Application COM Object. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/ - Nelson, M. (2017, January 23). Lateral Movement via DCOM: Round 2. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/08/03/wsh-injection-a-case-study/ - Nelson, M. (2017, August 3). WSH INJECTION: A CASE STUDY. Retrieved April 9, 2018.
* https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/ - Nelson, M. (2017, September 11). Lateral Movement using Excel.Application and DCOM. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript/ - Nelson, M. (2017, November 16). Lateral Movement using Outlook's CreateObject Method and DotNetToJScript. Retrieved November 21, 2017.
* https://eyeofrablog.wordpress.com/2017/06/27/windows-keylogger-part-2-defense-against-user-land/ - Eye of Ra. (2017, June 27). Windows Keylogger Part 2: Defense against user-land. Retrieved December 12, 2017.
* https://forum.anomali.com/t/credential-harvesting-and-malicious-file-delivery-using-microsoft-office-template-injection/2104 - Intel_Acquisition_Team. (2018, March 1). Credential Harvesting and Malicious File Delivery using Microsoft Office Template Injection. Retrieved July 20, 2018.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/api0cradle/UltimateAppLockerByPassList - Moe, O. (2018, March 1). Ultimate AppLocker Bypass List. Retrieved April 10, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/issues/92 - Warren, J. (2017, June 22). lsadump::changentlm and lsadump::setntlm work, but generate Windows events #92. Retrieved December 4, 2017.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/hob0/hashjacking - Dunning, J. (2016, August 1). Hashjacking. Retrieved December 21, 2017.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/jay/gethooks - Satiro, J. (2011, September 14). GetHooks. Retrieved December 12, 2017.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://github.com/prekageo/winhook - Prekas, G. (2011, July 11). Winhook. Retrieved December 12, 2017.
* https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh - undefined. (n.d.). Retrieved April 12, 2019.
* https://github.com/ryhanson/phishery - Hanson, R. (2016, September 24). phishery. Retrieved July 21, 2018.
* https://github.com/sensepost/notruler - SensePost. (2017, September 21). NotRuler - The opposite of Ruler, provides blue teams with the ability to detect Ruler usage against Exchange. Retrieved February 4, 2019.
* https://github.com/sensepost/ruler - SensePost. (2016, August 18). Ruler: A tool to abuse Exchange services. Retrieved February 4, 2019.
* https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html - Forshaw, J. (2018, April 18). Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege. Retrieved May 3, 2018.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://labs.mwrinfosecurity.com/blog/add-in-opportunities-for-office-persistence/ - Knowles, W. (2017, April 21). Add-In Opportunities for Office Persistence. Retrieved July 3, 2017.
* https://linux.die.net/man/1/chmod - MacKenzie, D. & Meyering, J. (n.d.). chmod(1) - Linux man page. Retrieved August 19, 2018.
* https://linux.die.net/man/1/chown - MacKenzie, D. & Meyering, J. (n.d.). chown(1) - Linux man page. Retrieved August 19, 2018.
* https://malware.news/t/using-outlook-forms-for-lateral-movement-and-persistence/13746 - Parisi, T., et al. (2017, July). Using Outlook Forms for Lateral Movement and Persistence. Retrieved February 5, 2019.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180722/Report_Shamoon_StoneDrill_final.pdf - Kaspersky Lab. (2017, March 7). From Shamoon to StoneDrill: Wipers attacking Saudi organizations and beyond. Retrieved March 14, 2019.
* https://medium.com/@bwtech789/outlook-today-homepage-persistence-33ea9b505943 - Soutcast. (2018, September 14). Outlook Today Homepage Persistence. Retrieved February 5, 2019.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-US/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved December 5, 2014.
* https://msdn.microsoft.com/en-us/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved June 3, 2016.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms687317(v=vs.85).aspx - Microsoft. (n.d.). Setting Process-Wide Security Through the Registry. Retrieved November 21, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms694331(v=vs.85).aspx - Microsoft. (n.d.). Registry Values for System-Wide Security. Retrieved November 21, 2017.
* https://msdn.microsoft.com/en-us/vba/office-shared-vba/articles/getting-started-with-vba-in-office - Austin, J. (2017, June 6). Getting Started with VBA in Office. Retrieved July 3, 2017.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc422924.aspx - Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://msdn.microsoft.com/library/system.diagnostics.eventlog.clear.aspx - Microsoft. (n.d.). EventLog.Clear Method (). Retrieved July 2, 2018.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms644959.aspx - Microsoft. (n.d.). Hooks Overview. Retrieved December 12, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms649053.aspx - Microsoft. (n.d.). About Atom Tables. Retrieved December 8, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms681951.aspx - Microsoft. (n.d.). Asynchronous Procedure Calls. Retrieved December 8, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms686701.aspx - Microsoft. (n.d.). Taking a Snapshot and Viewing Processes. Retrieved December 12, 2017.
* https://msdn.microsoft.com/ms724961.aspx - Microsoft. (n.d.). System Time. Retrieved November 25, 2016.
* https://msdn.microsoft.com/windows/desktop/ms524405 - Microsoft. (n.d.). About the HTML Help Executable Program. Retrieved October 3, 2018.
* https://msdn.microsoft.com/windows/desktop/ms644670 - Microsoft. (n.d.). HTML Help ActiveX Control Overview. Retrieved October 3, 2018.
* https://msitpros.com/?p=3909 - Moe, O. (2017, August 13). Bypassing Device guard UMCI using CHM – CVE-2017-8625. Retrieved October 3, 2018.
* https://msitpros.com/?p=3960 - Moe, O. (2017, August 15). Research on CMSTP.exe. Retrieved April 11, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2017-0176 - National Vulnerability Database. (2017, June 22). CVE-2017-0176 Detail. Retrieved April 3, 2018.
* https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html - Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.
* https://oddvar.moe/2018/01/14/putting-data-in-alternate-data-streams-and-how-to-execute-it/ - Moe, O. (2018, January 14). Putting Data in Alternate Data Streams and How to Execute It. Retrieved June 30, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/ - Moe, O. (2018, April 11). Putting Data in Alternate Data Streams and How to Execute It - Part 2. Retrieved June 30, 2018.
* https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved March 2, 2016.
* https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ - Malith, O. (2017, March 24). Places of Interest in Stealing NetNTLM Hashes. Retrieved January 26, 2018.
* https://pentestlab.blog/2017/04/03/token-manipulation/ - netbiosX. (2017, April 3). Token Manipulation. Retrieved April 21, 2017.
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8625 - Microsoft. (2017, August 8). CVE-2017-8625 - Internet Explorer Security Feature Bypass Vulnerability. Retrieved October 3, 2018.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/host-based-threat-modeling-indicator-design-a9dbbb53d5ea - Atkinson, J. (2017, July 18). Host-based Threat Modeling & Indicator Design. Retrieved March 21, 2018.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/ - Bryan Lee and Rob Downs. (2016, February 12). A Look Into Fysbis: Sofacy’s Linux Backdoor. Retrieved September 10, 2017.
* https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/ - Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/ - Falcone, R., et al. (2018, September 04). OilRig Targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE. Retrieved September 24, 2018.
* https://resources.infosecinstitute.com/spoof-using-right-to-left-override-rtlo-technique-2/ - Security Ninja. (2015, April 16). Spoof Using Right to Left Override (RTLO) Technique. Retrieved April 22, 2019.
* https://securelist.com/lazarus-under-the-hood/77908/ - GReAT. (2017, April 3). Lazarus Under the Hood. Retrieved April 17, 2019.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securelist.com/zero-day-vulnerability-in-telegram/83800/ - Firsh, A.. (2018, February 13). Zero-day vulnerability in Telegram - Cybercriminals exploited Telegram flaw to launch multipurpose attacks. Retrieved April 22, 2019.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/stopping-malware-fake-virtual-machine/ - Roccia, T. (2017, January 19). Stopping Malware With a Fake Virtual Machine. Retrieved April 17, 2019.
* https://security.stackexchange.com/questions/17904/what-are-the-methods-to-find-hooked-functions-and-apis - Stack Exchange - Security. (2012, July 31). What are the methods to find hooked functions and APIs?. Retrieved December 12, 2017.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://sensepost.com/blog/2017/outlook-forms-and-shells/ - Stalmans, E. (2017, April 28). Outlook Forms and Shells. Retrieved February 4, 2019.
* https://sensepost.com/blog/2017/outlook-home-page-another-ruler-vector/ - Stalmans, E. (2017, October 11). Outlook Home Page – Another Ruler Vector. Retrieved February 4, 2019.
* https://silentbreaksecurity.com/malicious-outlook-rules/ - Landers, N. (2015, December 4). Malicious Outlook Rules. Retrieved February 4, 2019.
* https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://skanthak.homepage.t-online.de/verifier.html - Kanthak, S. (2017). Application Verifier Provider. Retrieved February 13, 2017.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://summit.fireeye.com/content/dam/fireeye-www/summit/cds-2018/presentations/cds18-technical-s03-youve-got-mail.pdf - Caban, D. and Hirani, M. (2018, October 3). You’ve Got Mail! Enterprise Email Compromise. Retrieved April 22, 2019.
* https://superuser.com/questions/150675/how-to-display-password-policy-information-for-a-user-ubuntu - Matutiae, M. (2014, August 6). How to display password policy information for a user (Ubuntu)?. Retrieved April 5, 2018.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
* https://support.office.com/article/Add-or-remove-add-ins-0af570c4-5cf3-4fa9-9b88-403625a0b460 - Microsoft. (n.d.). Add or remove add-ins. Retrieved July 3, 2017.
* https://support.office.com/article/Change-the-Normal-template-Normal-dotm-06de294b-d216-47f6-ab77-ccb5166f98ea - Microsoft. (n.d.). Change the Normal template (Normal.dotm). Retrieved July 3, 2017.
* https://technet.microsoft.com/bb490717.aspx - Microsoft. (n.d.). Net Use. Retrieved November 25, 2016.
* https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx - Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.
* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works - Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/bb490994.aspx - Microsoft TechNet. (n.d.). Runas. Retrieved April 21, 2017.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc772408.aspx - Microsoft. (n.d.). Services. Retrieved June 7, 2016.
* https://technet.microsoft.com/en-us/library/cc785125.aspx - Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing - Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/cc770880.aspx - Microsoft. (n.d.). Share a Folder or Drive. Retrieved June 30, 2017.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://technet.microsoft.com/windows-server-docs/identity/ad-ds/get-started/windows-time-service/windows-time-service-tools-and-settings - Mathers, B. (2016, September 30). Windows Time Service Tools and Settings. Retrieved November 25, 2016.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/ItsReallyNick/status/958789644165894146 - Carr, N. (2018, January 31). Here is some early bad cmstp.exe... Retrieved April 11, 2018.
* https://twitter.com/NickTyrer/status/958450014111633408 - Tyrer, N. (2018, January 30). CMSTP.exe - remote .sct execution applocker bypass. Retrieved April 11, 2018.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://twitter.com/r0wdy_/status/936365549553991680 - The Cyber (@r0wdy_). (2017, November 30). Service Recovery Parameters. Retrieved April 9, 2018.
* https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/ - Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.
* https://unit42.paloaltonetworks.com/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/ - Falcone, R., Lee, B.. (2018, November 20). Sofacy Continues Global Attacks and Wheels Out New ‘Cannon’ Trojan. Retrieved April 23, 2019.
* https://unit42.paloaltonetworks.com/ups-observations-on-cve-2015-3113-prior-zero-days-and-the-pirpi-payload/ - Falcone, R., Wartell, R.. (2015, July 27). UPS: Observations on CVE-2015-3113, Prior Zero-Days and the Pirpi Payload. Retrieved April 23, 2019.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://volatility-labs.blogspot.com/2012/09/movp-31-detecting-malware-hooks-in.html - Volatility Labs. (2012, September 24). MoVP 3.1 Detecting Malware Hooks in the Windows GUI Subsystem. Retrieved December 12, 2017.
* https://web.archive.org/web/20161128183535/https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html - Smith, C. (2016, April 19). Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files). Retrieved June 30, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.adlice.com/userland-rootkits-part-1-iat-hooks/ - Tigzy. (2014, October 15). Userland Rootkits: Part 1, IAT hooks. Retrieved December 12, 2017.
* https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation.pdf - Atkinson, J., Winchester, R. (2017, December 7). A Process is No One: Hunting for Token Manipulation. Retrieved December 21, 2017.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/ - Gavriel, H. & Erbesfeld, B. (2018, April 11). New ‘Early Bird’ Code Injection Technique Discovered. Retrieved May 24, 2018.
* https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom - Tsukerman, P. (2017, November 8). Leveraging Excel DDE for lateral movement via DCOM. Retrieved November 21, 2017.
* https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf - Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.
* https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.
* https://www.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf - Cylance. (2015, April 13). Redirect to SMB. Retrieved December 21, 2017.
* https://www.datawire.io/code-injection-on-linux-and-macos/ - Turner-Trauring, I. (2017, April 18). “This will only hurt for a moment”: code injection on Linux and macOS with LD_PRELOAD. Retrieved December 20, 2017.
* https://www.defcon.org/images/defcon-22/dc-22-presentations/Kazanciyan-Hastings/DEFCON-22-Ryan-Kazanciyan-Matt-Hastings-Investigating-Powershell-Attacks.pdf - Kazanciyan, R. & Hastings, M. (2014). Defcon 22 Presentation. Investigating PowerShell Attacks &#91;slides&#93;. Retrieved November 3, 2014.
* https://www.endgame.com/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.eventtracker.com/tech-articles/monitoring-file-permission-changes-windows-security-log/ - Netsurion. (2014, February 19). Monitoring File Permission Changes with the Windows Security Log. Retrieved August 19, 2018.
* https://www.exploit-db.com/docs/17802.pdf - Mariani, B. (2011, September 6). Inline Hooking in Windows. Retrieved December 12, 2017.
* https://www.f-secure.com/documents/996508/1030745/CozyDuke - F-Secure Labs. (2015, April 22). CozyDuke: Malware Analysis. Retrieved December 10, 2015.
* https://www.f-secure.com/documents/996508/1030745/cosmicduke_whitepaper.pdf - F-Secure Labs. (2014, July). COSMICDUKE Cosmu with a twist of MiniDuke. Retrieved July 3, 2014.
* https://www.fidelissecurity.com/sites/default/files/FTA_1018_looking_at_the_sky_for_a_dark_comet.pdf - Fidelis Cybersecurity. (2015, August 4). Looking at the Sky for a DarkComet. Retrieved April 5, 2016.
* https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html - Glyer, C., Kazanciyan, R. (2012, August 20). THE “HIKIT” ROOTKIT: ADVANCED AND PERSISTENT ATTACK TECHNIQUES (PART 1). Retrieved June 6, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html - FireEye. (2016, November 30). FireEye Responds to Wave of Destructive Cyber Attacks in Gulf Region. Retrieved January 11, 2017.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html - Berry, A., Galang, L., Jiang, G., Leathery, J., Mohandas, R. (2017, April 11). CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler. Retrieved October 27, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/blog/threat-research/2017/11/ursnif-variant-malicious-tls-callback-technique.html - Vaish, A. & Nemes, S. (2017, November 28). Newly Observed Ursnif Variant Employs Malicious TLS Callback Technique to Achieve Process Injection. Retrieved December 18, 2017.
* https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html - Matsuda, A., Muhammad I. (2018, September 13). APT10 Targeting Japanese Corporations Using Updated TTPs. Retrieved September 17, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Stewart, A. (2014). DLL SIDE-LOADING: A Thorn in the Side of the Anti-Virus Industry. Retrieved November 12, 2014.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/regional/fr_FR/offers/pdfs/ig-mtrends-2016.pdf - Mandiant. (2016, February). M-Trends 2016. Retrieved January 4, 2017.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.gnu.org/software/acct/ - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.
* https://www.hybrid-analysis.com/sample/22dab012c3e20e3d9291bce14a2bfc448036d3b966c6e78167f4626f5f9e38d6?environmentId=110 - Hybrid Analysis. (2018, May 30). 2a8efbfadd798f6111340f7c1c956bee.dll. Retrieved August 19, 2018.
* https://www.hybrid-analysis.com/sample/ef0d2628823e8e0a0de3b08b8eacaf41cf284c086a948bdfd67f4e4373c14e4d?environmentId=100 - Hybrid Analysis. (2018, June 12). c9b65b764985dfd7a11d3faf599c56b8.exe. Retrieved August 19, 2018.
* https://www.iad.gov/iad/library/reports/spotting-the-adversary-with-windows-event-log-monitoring.cfm - National Security Agency/Central Security Service Information Assurance Directorate. (2015, August 7). Spotting the Adversary with Windows Event Log Monitoring. Retrieved September 6, 2018.
* https://www.jamf.com/jamf-nation/discussions/18574/user-password-policies-on-non-ad-machines - Holland, J. (2016, January 25). User password policies on non AD machines. Retrieved April 5, 2018.
* https://www.justice.gov/opa/press-release/file/1092091/download - Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.
* https://www.mandiant.com/blog/dll-search-order-hijacking-revisited/ - Mandiant. (2010, August 31). DLL Search Order Hijacking Revisited. Retrieved December 5, 2014.
* https://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/4beddb35-0cba-424c-8b9b-a5832ad8e208.mspx - Microsoft. (n.d.). Managing WebDAV Security (IIS 6.0). Retrieved December 21, 2017.
* https://www.mwrinfosecurity.com/our-thinking/dynamic-hooking-techniques-user-mode/ - Hillman, M. (2015, August 8). Dynamic Hooking Techniques: User Mode. Retrieved December 20, 2017.
* https://www.offensive-security.com/metasploit-unleashed/fun-incognito/ - Offensive Security. (n.d.). What is Incognito. Retrieved April 21, 2017.
* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.
* https://www.owasp.org/index.php/Binary_planting - OWASP. (2013, January 30). Binary planting. Retrieved June 7, 2016.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf - Claud Xiao. (n.d.). WireLurker: A New Era in iOS and OS X Malware. Retrieved July 10, 2017.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.rsaconference.com/writable/presentations/file_upload/ht-209_rivner_schwartz.pdf - Rivner, U., Schwartz, E. (2012). They’re Inside… Now What?. Retrieved November 25, 2016.
* https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667 - Keragala, D. (2016, January 16). Detecting Malware and Sandbox Evasion Techniques. Retrieved April 17, 2019.
* https://www.sans.org/reading-room/whitepapers/testing/template-injection-attacks-bypassing-security-controls-living-land-38780 - Wiltse, B.. (2018, November 7). Template Injection Attacks - Bypassing Security Controls by Living off the Land. Retrieved April 10, 2019.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.secureworks.com/research/wcry-ransomware-analysis - Counter Threat Unit Research Team. (2017, May 18). WCry Ransomware Analysis. Retrieved March 26, 2019.
* https://www.slideshare.net/DennisMaldonado5/sticky-keys-to-the-kingdom - Maldonado, D., McGuffin, T. (2016, August 6). Sticky Keys to the Kingdom. Retrieved July 5, 2017.
* https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2 - Jacobsen, K. (2014, May 16). Lateral Movement with PowerShell&#91;slides&#93;. Retrieved November 12, 2014.
* https://www.symantec.com/avcenter/reference/windows.rootkit.overview.pdf - Symantec. (n.d.). Windows Rootkit Overview. Retrieved December 21, 2017.
* https://www.symantec.com/connect/articles/what-you-need-know-about-alternate-data-streams-windows-your-data-secure-can-you-restore - Pravs. (2009, May 25). What you need to know about alternate data streams in windows? Is your Data secure? Can you restore that?. Retrieved March 21, 2018.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.symantec.com/connect/blogs/shamoon-attacks - Symantec. (2012, August 16). The Shamoon Attacks. Retrieved March 14, 2019.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing - Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.
* https://www.tutorialspoint.com/unix/unix-file-permission.htm - Tutorials Point. (n.d.). Unix / Linux - File Permission / Access Modes. Retrieved August 19, 2018.
* https://www.uperesia.com/analyzing-malicious-office-documents - Felix. (2016, September). Analyzing Malicious Office Documents. Retrieved April 11, 2018.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.us-cert.gov/ncas/alerts/TA17-293A - US-CERT. (2017, October 20). Alert (TA17-293A): Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved November 2, 2017.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.). Retrieved December 4, 2014.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2016/03/30/meet-remaiten-a-linux-bot-on-steroids-targeting-routers-and-potentially-other-iot-devices/ - Michal Malik AND Marc-Etienne M.Léveillé. (2016, March 30). Meet Remaiten – a Linux bot on steroids targeting routers and potentially other IoT devices. Retrieved September 7, 2017.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.
* https://zairon.wordpress.com/2006/12/06/any-application-defined-hook-procedure-on-my-machine/ - Felici, M. (2006, December 6). Any application-defined hook procedure on my machine?. Retrieved December 12, 2017.

# Validate the following tools

* Arp - 2
* BITSAdmin - 1
* Cobalt Strike - 4
* Empire - 1
* FTP - 1
* HTRAN - 1
* Havij - 1
* Impacket - 3
* LaZagne - 3
* Mimikatz - 12
* Net - 9
* Ping - 2
* PowerSploit - 2
* PsExec - 7
* Pupy - 1
* QuasarRAT - 3
* RawDisk - 1
* Reg - 3
* Remcos - 1
* SDelete - 1
* Systeminfo - 2
* Tasklist - 3
* Tor - 1
* Windows Credential Editor - 3
* at - 2
* certutil - 3
* cmd - 3
* gsecdump - 2
* ipconfig - 3
* meek - 1
* nbtstat - 1
* netsh - 3
* netstat - 2
* pwdump - 2
* schtasks - 1
* sqlmap - 1

# Review the following tool references

* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://sqlmap.org/ - Damele, B., Stampar, M. (n.d.). sqlmap. Retrieved March 19, 2018.
* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* http://www.ampliasecurity.com/research/wcefaq.html - Amplia Security. (n.d.). Windows Credentials Editor (WCE) F.A.Q.. Retrieved December 17, 2015.
* http://www.dtic.mil/dtic/tr/fulltext/u2/a465464.pdf - Roger Dingledine, Nick Mathewson and Paul Syverson. (2004). Tor: The Second-Generation Onion Router. Retrieved December 21, 2017.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://blog.checkpoint.com/2015/05/14/analysis-havij-sql-injection-tool/ - Ganani, M. (2015, May 14). Analysis of the Havij SQL Injection tool. Retrieved March 19, 2018.
* https://blog.talosintelligence.com/2018/08/picking-apart-remcos.html - Brumaghin, E., Unterbrink, H. (2018, August 22). Picking Apart Remcos Botnet-In-A-Box. Retrieved November 6, 2018.
* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive - Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf - Lunghi, D., et al. (2017, December). Untangling the Patchwork Cyberespionage Group. Retrieved July 10, 2018.
* https://en.wikipedia.org/wiki/File_Transfer_Protocol - Wikipedia. (2016, June 15). File Transfer Protocol. Retrieved July 20, 2016.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (1985, June 22). pwdump. Retrieved June 22, 2016.
* https://github.com/AlessandroZ/LaZagne - Zanni, A. (n.d.). The LaZagne Project !!!. Retrieved December 14, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/n1nj4sec/pupy - Nicolas Verdier. (n.d.). Retrieved January 29, 2018.
* https://github.com/quasar/QuasarRAT - MaxXor. (n.d.). QuasarRAT. Retrieved July 10, 2018.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved March 2, 2016.
* https://s3.eu-west-1.amazonaws.com/ncsc-content/files/Joint%20report%20on%20publicly%20available%20hacking%20tools%20%28NCSC%29.pdf - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://technet.microsoft.com/en-us/library/bb490864.aspx - Microsoft. (n.d.). Arp. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490866.aspx - Microsoft. (n.d.). At. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/bb490880.aspx - Microsoft. (n.d.). Cmd. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/bb490886.aspx - Microsoft. (n.d.). Copy. Retrieved April 26, 2016.
* https://technet.microsoft.com/en-us/library/bb490921.aspx - Microsoft. (n.d.). Ipconfig. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490947.aspx - Microsoft. (n.d.). Netstat. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490968.aspx - Microsoft. (n.d.). Ping. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/bb491007.aspx - Microsoft. (n.d.). Systeminfo. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/bb491010.aspx - Microsoft. (n.d.). Tasklist. Retrieved December 23, 2015.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc755121.aspx - Microsoft. (n.d.). Dir. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/cc771049.aspx - Microsoft. (n.d.). Del. Retrieved April 22, 2016.
* https://technet.microsoft.com/en-us/library/cc940106.aspx - Microsoft. (n.d.). Nbtstat. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/bb490939.aspx - Microsoft. (n.d.). Using Netsh. Retrieved February 13, 2017.
* https://technet.microsoft.com/library/cc732443.aspx - Microsoft. (2012, November 14). Certutil. Retrieved July 3, 2017.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-operation-quantum-entanglement.pdf - Haq, T., Moran, N., Vashisht, S., Scott, M. (2014, September). OPERATION QUANTUM ENTANGLEMENT. Retrieved November 4, 2015.
* https://www.fortinet.com/blog/threat-research/remcos-a-new-rat-in-the-wild-2.html - Bacurio, F., Salvio, J. (2017, February 14). REMCOS: A New RAT In The Wild. Retrieved November 6, 2018.
* https://www.itprotoday.com/windows-78/eldos-provides-raw-disk-access-vista-and-xp - Edwards, M. (2007, March 14). EldoS Provides Raw Disk Access for Vista and XP. Retrieved March 26, 2019.
* https://www.riskiq.com/blog/labs/spear-phishing-turkish-defense-contractors/ - Klijnsma, Y. (2018, January 23). Espionage Campaign Leverages Spear Phishing, RATs Against Turkish Defense Contractors. Retrieved November 6, 2018.
* https://www.secureauth.com/labs/open-source-tools/impacket - SecureAuth. (n.d.).  Retrieved January 15, 2019.
* https://www.truesec.se/sakerhet/verktyg/saakerhet/gsecdump_v2.0b5 - TrueSec. (n.d.). gsecdump v2.0b5. Retrieved September 29, 2015.
* https://www.volexity.com/blog/2018/06/07/patchwork-apt-group-targets-us-think-tanks/ - Meltzer, M, et al. (2018, June 07). Patchwork APT Group Targets US Think Tanks. Retrieved July 16, 2018.

# Validate the following malware

* ASPXSpy - 1
* AuditCred - 1
* AutoIt backdoor - 1
* BACKSPACE - 1
* BADCALL - 1
* BADNEWS - 1
* BLACKCOFFEE - 2
* BONDUPDATER - 1
* Bankshot - 1
* BlackEnergy - 1
* CallMe - 1
* Carbon - 1
* ChChes - 1
* China Chopper - 2
* CloudDuke - 1
* ComRAT - 1
* CosmicDuke - 1
* CozyCar - 1
* Daserf - 1
* Denis - 1
* Derusbi - 3
* Dipsind - 1
* Elise - 1
* Emissary - 1
* Epic - 1
* EvilGrab - 1
* FALLCHILL - 1
* FLASHFLOOD - 1
* FakeM - 1
* Felismus - 1
* Gazer - 1
* GeminiDuke - 1
* HAMMERTOSS - 1
* HARDRAIN - 1
* HOMEFRY - 1
* HOPLIGHT - 1
* HTTPBrowser - 2
* Helminth - 1
* Hikit - 1
* Hydraq - 1
* HyperBro  - 1
* ISMInjector - 1
* Ixeshe - 1
* JPIN - 1
* KEYMARBLE - 1
* KOMPROGO - 1
* Kazuar - 1
* KeyBoy - 1
* LightNeuron - 1
* MURKYTOP - 1
* MiniDuke - 1
* Mivast - 1
* Mosquito - 1
* NDiskMonitor - 1
* NETEAGLE - 1
* NETWIRE - 1
* NanHaiShu - 1
* NanoCore - 1
* OSX_OCEANLOTUS.D - 1
* OnionDuke - 1
* OopsIE - 1
* Orz - 1
* OwaAuth - 1
* PHOREAL - 1
* POSHSPY - 1
* POWERSTATS - 1
* POWRUNER - 1
* PinchDuke - 1
* Pisloader - 1
* PlugX - 2
* PoisonIvy - 2
* PowerDuke - 1
* PowerStallion - 1
* Proxysvc - 1
* Psylo - 1
* Pteranodon - 1
* QUADAGENT - 1
* RATANKBA - 1
* RGDoor - 1
* RIPTIDE - 1
* RedLeaves - 1
* Revenge RAT - 1
* RogueRobin - 1
* SEASHARPEE - 1
* SHIPSHAPE - 1
* SNUGRIDE - 1
* SOUNDBITE - 1
* SPACESHIP - 1
* Sakula - 1
* SeaDuke - 1
* Starloader - 1
* StreamEx - 1
* TINYTYPHON - 1
* TYPEFRAME - 1
* UPPERCUT - 1
* Unknown Logger - 1
* Uroburos - 1
* Volgmer - 1
* WINDSHIELD - 1
* WannaCry - 1
* Yahoyah - 1
* adbupd - 1
* gh0st RAT - 1
* hcdLoader - 1
* njRAT - 1

# Review the following malware references

* http://blog.jpcert.or.jp/2017/02/chches-malware--93d6.html - Nakamura, Y.. (2017, February 17). ChChes - Malware that Communicates with C&C Servers Using Cookie Headers. Retrieved March 1, 2017.
* http://blog.trendmicro.com/trendlabs-security-intelligence/redbaldknight-bronze-butler-daserf-backdoor-now-using-steganography/ - Chen, J. and Hsieh, M. (2017, November 7). REDBALDKNIGHT/BRONZE BUTLER’s Daserf Backdoor Now Using Steganography. Retrieved December 27, 2017.
* http://circl.lu/assets/files/tr-12/tr-12-circl-plugx-analysis-v1.pdf - Computer Incident Response Center Luxembourg. (2013, March 29). Analysis of a PlugX variant. Retrieved November 5, 2018.
* http://labs.lastline.com/an-analysis-of-plugx - Vasilenko, R. (2013, December 17). An Analysis of PlugX Malware. Retrieved November 24, 2015.
* http://researchcenter.paloaltonetworks.com/2015/04/unit-42-identifies-new-dragonok-backdoor-malware-deployed-against-japanese-targets/ - Miller-Osborn, J., Grunzweig, J.. (2015, April). Unit 42 Identifies New DragonOK Backdoor Malware Deployed Against Japanese Targets. Retrieved November 4, 2015.
* http://researchcenter.paloaltonetworks.com/2015/12/attack-on-french-diplomat-linked-to-operation-lotus-blossom/ - Falcone, R. and Miller-Osborn, J.. (2015, December 18). Attack on French Diplomat Linked to Operation Lotus Blossom. Retrieved February 15, 2016.
* http://researchcenter.paloaltonetworks.com/2016/01/scarlet-mimic-years-long-espionage-targets-minority-activists/ - Falcone, R. and Miller-Osborn, J.. (2016, January 24). Scarlet Mimic: Years-Long Espionage Campaign Targets Minority Activists. Retrieved February 10, 2016.
* http://researchcenter.paloaltonetworks.com/2016/05/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/ - Falcone, R. and Lee, B.. (2016, May 26). The OilRig Campaign: Attacks on Saudi Arabian Organizations Deliver Helminth Backdoor. Retrieved May 3, 2017.
* http://researchcenter.paloaltonetworks.com/2016/05/unit42-new-wekby-attacks-use-dns-requests-as-command-and-control-mechanism/ - Grunzweig, J., et al. (2016, May 24). New Wekby Attacks Use DNS Requests As Command and Control Mechanism. Retrieved August 17, 2016.
* http://researchcenter.paloaltonetworks.com/2017/02/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/ - Miller-Osborn, J. and Grunzweig, J.. (2017, February 16). menuPass Returns with New Malware and New Attacks Against Japanese Academics and Organizations. Retrieved March 1, 2017.
* http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* http://www.secureworks.com/cyber-threat-intelligence/threats/sakula-malware-family/ - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, July 30). Sakula Malware Family. Retrieved January 26, 2016.
* http://www.secureworks.com/resources/blog/where-you-at-indicators-of-lateral-movement-using-at-exe-on-windows-7-systems/ - Carvey, H.. (2014, September 2). Where you AT?: Indicators of lateral movement using at.exe on Windows 7 systems. Retrieved January 25, 2016.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-black-vine-cyberespionage-group.pdf - DiMaggio, J.. (2015, August 6). The Black Vine cyberespionage group. Retrieved January 26, 2016.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/waterbug-attack-group.pdf - Symantec. (2015, January 26). The Waterbug attack group. Retrieved April 10, 2015.
* http://www.symantec.com/security_response/writeup.jsp?docid=2015-020623-0740-99&tabid=2 - Stama, D.. (2015, February 6). Backdoor.Mivast. Retrieved February 15, 2016.
* https://blog.rapid7.com/2013/06/07/keyboy-targeted-attacks-against-vietnam-and-india/ - Guarnieri, C., Schloesser M. (2013, June 7). KeyBoy, Targeted Attacks against Vietnam and India. Retrieved June 14, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/autoit-compiled-worm-affecting-removable-media-delivers-fileless-version-of-bladabindi-njrat-backdoor/ - Pascual, C. (2018, November 27). AutoIt-Compiled Worm Affecting Removable Media Delivers Fileless Version of BLADABINDI/njRAT Backdoor. Retrieved June 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-campaign-targeting-cryptocurrencies-reveals-remote-controller-tool-evolved-ratankba/ - Lei, C., et al. (2018, January 24). Lazarus Campaign Targeting Cryptocurrencies Reveals Remote Controller Tool, an Evolved RATANKBA, and More. Retrieved May 22, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-continues-heists-mounts-attacks-on-financial-organizations-in-latin-america/ - Trend Micro. (2018, November 20). Lazarus Continues Heists, Mounts Attacks on Financial Organizations in Latin America. Retrieved December 3, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/new-macos-backdoor-linked-to-oceanlotus-found/ - Horejsi, J. (2018, April 04). New MacOS Backdoor Linked to OceanLotus Found. Retrieved November 13, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/ratankba-watering-holes-against-enterprises/ - Trend Micro. (2017, February 27). RATANKBA: Delving into Large-scale Watering Holes against Enterprises. Retrieved May 22, 2018.
* https://blogs.forcepoint.com/security-labs/playing-cat-mouse-introducing-felismus-malware - Somerville, L. and Toro, A. (2017, March 30). Playing Cat & Mouse: Introducing the Felismus Malware. Retrieved November 16, 2017.
* https://citizenlab.ca/2016/11/parliament-keyboy/ - Hulcoop, A., et al. (2016, November 17). It’s Parliamentary KeyBoy and the targeting of the Tibetan Community. Retrieved June 13, 2019.
* https://cofense.com/nanocore-rat-resurfaced-sewers/ - Patel, K. (2018, March 02). The NanoCore RAT Has Resurfaced From the Sewers. Retrieved November 9, 2018.
* https://cofense.com/upgrades-delivery-support-infrastructure-revenge-rat-malware-bigger-threat/ - Gannon, M. (2019, February 11). With Upgrades in Delivery and Support Infrastructure, Revenge RAT Malware is a Bigger Threat. Retrieved May 1, 2019.
* https://community.softwaregrp.com/t5/Security-Research/9002-RAT-a-second-building-on-the-left/ba-p/228686#.WosBVKjwZPZ - Petrovsky, O. (2016, August 30). “9002 RAT” -- a second building on the left. Retrieved February 20, 2018.
* https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf - Lunghi, D., et al. (2017, December). Untangling the Patchwork Cyberespionage Group. Retrieved July 10, 2018.
* https://download.microsoft.com/download/2/2/5/225BFE3E-E1DE-4F5B-A77B-71200928D209/Platinum%20feature%20article%20-%20Targeted%20attacks%20in%20South%20and%20Southeast%20Asia%20April%202016.pdf - Windows Defender Advanced Threat Hunting Team. (2016, April 29). PLATINUM: Targeted attacks in South and Southeast Asia. Retrieved February 15, 2018.
* https://logrhythm.com/blog/a-technical-analysis-of-wannacry-ransomware/ - Noerenberg, E., Costis, A., and Quist, N. (2017, May 16). A Technical Analysis of WannaCry Ransomware. Retrieved March 25, 2019.
* https://researchcenter.paloaltonetworks.com/2015/09/chinese-actors-use-3102-malware-in-attacks-on-us-government-and-eu-media/ - Falcone, R. & Miller-Osborn, J. (2015, September 23). Chinese Actors Use ‘3102’ Malware in Attacks on US Government and EU Media. Retrieved March 19, 2018.
* https://researchcenter.paloaltonetworks.com/2016/02/nanocorerat-behind-an-increase-in-tax-themed-phishing-e-mails/ - Kasza, A., Halfpop, T. (2016, February 09). NanoCoreRAT Behind an Increase in Tax-Themed Phishing E-mails. Retrieved November 9, 2018.
* https://researchcenter.paloaltonetworks.com/2017/02/unit-42-title-gamaredon-group-toolset-evolution/ - Kasza, A. and Reichel, D.. (2017, February 27). The Gamaredon Group Toolset Evolution. Retrieved March 1, 2017.
* https://researchcenter.paloaltonetworks.com/2017/05/unit42-kazuar-multiplatform-espionage-backdoor-api-access/ - Levene, B, et al. (2017, May 03). Kazuar: Multiplatform Espionage Backdoor with API Access. Retrieved July 17, 2018.
* https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/ - Falcone, R. and Lee, B. (2017, October 9). OilRig Group Steps Up Attacks with New Delivery Documents and New Injector Trojan. Retrieved January 8, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/ - Lancaster, T.. (2017, November 14). Muddying the Water: Targeted Attacks in the Middle East. Retrieved March 15, 2018.
* https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/ - Falcone, R. (2018, January 25). OilRig uses RGDoor IIS Backdoor on Targets in the Middle East. Retrieved July 6, 2018.
* https://researchcenter.paloaltonetworks.com/2018/02/unit42-oopsie-oilrig-uses-threedollars-deliver-new-trojan/ - Lee, B., Falcone, R. (2018, February 23). OopsIE! OilRig Uses ThreeDollars to Deliver New Trojan. Retrieved July 16, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-oilrig-targets-technology-service-provider-government-agency-quadagent/ - Lee, B., Falcone, R. (2018, July 25). OilRig Targets Technology Service Provider and Government Agency with QUADAGENT. Retrieved August 9, 2018.
* https://researchcenter.paloaltonetworks.com/2018/08/unit42-gorgon-group-slithering-nation-state-cybercrime/ - Falcone, R., et al. (2018, August 02). The Gorgon Group: Slithering Between Nation State and Cybercrime. Retrieved August 7, 2018.
* https://researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/ - Falcone, R., et al. (2018, September 04). OilRig Targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE. Retrieved September 24, 2018.
* https://securelist.com/introducing-whitebear/81638/ - Kaspersky Lab's Global Research & Analysis Team. (2017, August 30). Introducing WhiteBear. Retrieved September 21, 2017.
* https://securelist.com/luckymouse-hits-national-data-center/86083/ - Legezo, D. (2018, June 13). LuckyMouse hits national data center to organize country-level waterholing campaign. Retrieved August 18, 2018.
* https://securelist.com/minidionis-one-more-apt-with-a-usage-of-cloud-drives/71443/ - Lozhkin, S.. (2015, July 16). Minidionis – one more APT with a usage of cloud drives. Retrieved April 5, 2017.
* https://securelist.com/shedding-skin-turlas-fresh-faces/88069/ - Kaspersky Lab's Global Research & Analysis Team. (2018, October 04). Shedding Skin – Turla’s Fresh Faces. Retrieved November 7, 2018.
* https://securelist.com/the-epic-turla-operation/65545/ - Kaspersky Lab's Global Research and Analysis Team. (2014, August 7). The Epic Turla Operation: Solving some of the mysteries of Snake/Uroburos. Retrieved December 11, 2014.
* https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/ - Sherstobitoff, R., Malhotra, A. (2018, April 24). Analyzing Operation GhostSecret: Attack Seeks to Steal Data Worldwide. Retrieved May 16, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/ - Sherstobitoff, R. (2018, March 08). Hidden Cobra Targets Turkish Financial Sector With New Bankshot Implant. Retrieved May 18, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/netwire-rat-behind-recent-targeted-attacks/ - McAfee. (2015, March 2). Netwire RAT Behind Recent Targeted Attacks. Retrieved February 15, 2018.
* https://thehackernews.com/2018/06/chinese-watering-hole-attack.html - Khandelwal, S. (2018, June 14). Chinese Hackers Carried Out Country-Level Watering Hole Attack. Retrieved August 18, 2018.
* https://twitter.com/ItsReallyNick/status/850105140589633536 - Carr, N.. (2017, April 6). Retrieved June 29, 2017.
* https://unit42.paloaltonetworks.com/darkhydrus-delivers-new-trojan-that-can-use-google-drive-for-c2-communications/ - Lee, B., Falcone, R. (2019, January 18). DarkHydrus delivers new Trojan that can use Google Drive for C2 communications. Retrieved April 17, 2019.
* https://unit42.paloaltonetworks.com/emissary-panda-attacks-middle-east-government-sharepoint-servers/ - Falcone, R. and Lancaster, T.. (2019, May 28). Emissary Panda Attacks Middle East Government Sharepoint Servers. Retrieved July 9, 2019.
* https://unit42.paloaltonetworks.com/unit42-oilrig-uses-updated-bondupdater-target-middle-eastern-government/ - Wilhoit, K. and Falcone, R. (2018, September 12). OilRig Uses Updated BONDUPDATER to Target Middle Eastern Government. Retrieved February 18, 2019.
* https://www.accenture.com/t20180127T003755Z_w_/us-en/_acnmedia/PDF-46/Accenture-Security-Dragonfish-Threat-Analysis.pdf - Accenture Security. (2018, January 27). DRAGONFISH DELIVERS NEW FORM OF ELISE MALWARE TARGETING ASEAN DEFENCE MINISTERS’ MEETING AND ASSOCIATES. Retrieved November 14, 2018.
* https://www.arbornetworks.com/blog/asert/musical-chairs-playing-tetris/ - Sabo, S. (2018, February 15). Musical Chairs Playing Tetris. Retrieved February 19, 2018.
* https://www.arbornetworks.com/blog/asert/wp-content/uploads/2016/01/ASERT-Threat-Intelligence-Brief-2015-08-Uncovering-the-Seven-Point-Dagger.pdf - ASERT. (2015, August). ASERT Threat Intelligence Report – Uncovering the Seven Pointed Dagger. Retrieved March 19, 2018.
* https://www.brighttalk.com/webcast/10703/275683 - Davis, S. and Carr, N. (2017, September 21). APT33: New Insights into Iranian Cyber Espionage Group. Retrieved February 15, 2018.
* https://www.brighttalk.com/webcast/10703/296317/apt34-new-targeted-attack-in-the-middle-east - Davis, S. and Caban, D. (2017, December 19). APT34 - New Targeted Attack in the Middle East. Retrieved December 20, 2017.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.cybereason.com/blog/operation-cobalt-kitty-apt - Dahan, A. (2017, May 24). OPERATION COBALT KITTY: A LARGE-SCALE APT IN ASIA CARRIED OUT BY THE OCEANLOTUS GROUP. Retrieved November 5, 2018.
* https://www.cylance.com/content/dam/cylance-web/en-us/resources/knowledge-center/resource-library/reports/WhiteCompanyOperationShaheenReport.pdf?_ga=2.161661948.1943296560.1555683782-1066572390.1555511517 - Livelli, K, et al. (2018, November 12). Operation Shaheen. Retrieved May 1, 2019.
* https://www.cylance.com/shell-crew-variants-continue-to-fly-under-big-avs-radar - Cylance SPEAR Team. (2017, February 9). Shell Crew Variants Continue to Fly Under Big AV’s Radar. Retrieved February 15, 2017.
* https://www.digitrustgroup.com/nanocore-not-your-average-rat/ - The DigiTrust Group. (2017, January 01). NanoCore Is Not Your Average RAT. Retrieved November 9, 2018.
* https://www.f-secure.com/documents/996508/1030745/blackenergy_whitepaper.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf - F-Secure Labs. (2015, September 17). The Dukes: 7 years of Russian cyberespionage. Retrieved December 10, 2015.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fidelissecurity.com/sites/default/files/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://www.fireeye.com/blog/threat-research/2013/05/ready-for-summer-the-sunshop-campaign.html - Moran, N. (2013, May 20). Ready for Summer: The Sunshop Campaign. Retrieved March 19, 2018.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2013/08/njw0rm-brother-from-the-same-mother.html - Dawda, U. and Villeneuve, N. (2013, August 30). Njw0rm - Brother From the Same Mother. Retrieved June 4, 2019.
* https://www.fireeye.com/blog/threat-research/2013/08/survival-of-the-fittest-new-york-times-attackers-evolve-quickly.html - Moran, N., & Villeneuve, N. (2013, August 12). Survival of the Fittest: New York Times Attackers Evolve Quickly &#91;Blog&#93;. Retrieved November 12, 2014.
* https://www.fireeye.com/blog/threat-research/2013/11/operation-ephemeral-hydra-ie-zero-day-linked-to-deputydog-uses-diskless-method.html - Moran, N. et al.. (2013, November 10). Operation Ephemeral Hydra: IE Zero-Day Linked to DeputyDog Uses Diskless Method. Retrieved March 19, 2018.
* https://www.fireeye.com/blog/threat-research/2014/06/clandestine-fox-part-deux.html - Scott, M.. (2014, June 10). Clandestine Fox, Part Deux. Retrieved January 14, 2016.
* https://www.fireeye.com/blog/threat-research/2014/09/darwins-favorite-apt-group-2.html - Moran, N., Oppenheim, M., Engle, S., & Wartell, R.. (2014, September 3). Darwin’s Favorite APT Group &#91;Blog&#93;. Retrieved November 12, 2014.
* https://www.fireeye.com/blog/threat-research/2015/07/demonstrating_hustle.html - FireEye Threat Intelligence. (2015, July 13). Demonstrating Hustle, Chinese APT Groups Quickly Use Zero-Day Vulnerability (CVE-2015-5119) Following Hacking Team Leak. Retrieved January 25, 2016.
* https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html - Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html - FireEye iSIGHT Intelligence. (2017, April 6). APT10 (MenuPass Group): New Tools, Global Campaign Latest Manifestation of Longstanding Threat. Retrieved June 29, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/cyber-espionage-apt32.html - Carr, N.. (2017, May 14). Cyber Espionage is Alive and Well: APT32 and the Threat to Global Corporations. Retrieved June 18, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html - Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html - O'Leary, J., et al. (2017, September 20). Insights into Iranian Cyber Espionage: APT33 Targets Aerospace and Energy Sectors and has Ties to Destructive Malware. Retrieved February 15, 2018.
* https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html - Sardiwal, M, et al. (2017, December 7). New Targeted Attack in the Middle East by APT34, a Suspected Iranian Threat Group, Using CVE-2017-11882 Exploit. Retrieved December 20, 2017.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html - Matsuda, A., Muhammad I. (2018, September 13). APT10 Targeting Japanese Corporations Using Updated TTPs. Retrieved September 17, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved November 12, 2014.
* https://www.forcepoint.com/sites/default/files/resources/files/forcepoint-security-labs-monsoon-analysis-report.pdf - Settle, A., et al. (2016, August 8). MONSOON - Analysis Of An APT Campaign. Retrieved September 22, 2016.
* https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/april/decoding-network-data-from-a-gh0st-rat-variant/ - Pantazopoulos, N. (2018, April 17). Decoding network data from a Gh0st RAT variant. Retrieved November 2, 2018.
* https://www.nsec.io/wp-content/uploads/2015/05/uroburos-actors-tools-1.1.pdf - Rascagneres, P. (2015, May). Tools used by the Uroburos actors. Retrieved August 18, 2016.
* https://www.paloaltonetworks.com/resources/research/unit42-operation-lotus-blossom.html - Falcone, R., et al.. (2015, June 16). Operation Lotus Blossom. Retrieved February 15, 2016.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.proofpoint.com/us/threat-insight/post/operation-rat-cook-chinese-apt-actors-use-fake-game-thrones-leaks-lures - Huss, D. & Mesa, M. (2017, August 25). Operation RAT Cook: Chinese APT actors use fake Game of Thrones leaks as lures. Retrieved March 19, 2018.
* https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf - PwC and BAE Systems. (2017, April). Operation Cloud Hopper: Technical Annex. Retrieved April 13, 2017.
* https://www.pwc.co.uk/issues/cyber-security-data-privacy/research/the-keyboys-are-back-in-town.html - Parys, B. (2017, February 11). The KeyBoys are back in town. Retrieved June 13, 2019.
* https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses - Counter Threat Unit Research Team. (2017, October 12). BRONZE BUTLER Targets Japanese Enterprises. Retrieved January 4, 2018.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.secureworks.com/research/wcry-ransomware-analysis - Counter Threat Unit Research Team. (2017, May 18). WCry Ransomware Analysis. Retrieved March 26, 2019.
* https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group - Symantec DeepSight Adversary Intelligence Team. (2018, December 10). Seedworm: Group Compromises Government Agencies, Oil & Gas, NGOs, Telecoms, and IT Firms. Retrieved December 14, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/connect/blogs/sowbug-cyber-espionage-group-targets-south-american-and-southeast-asian-governments - Symantec Security Response. (2017, November 7). Sowbug: Cyber espionage group targets South American and Southeast Asian governments. Retrieved November 16, 2017.
* https://www.symantec.com/connect/blogs/trojanhydraq-incident - Symantec Security Response. (2010, January 18). The Trojan.Hydraq Incident. Retrieved February 20, 2018.
* https://www.symantec.com/security-center/writeup/2014-081811-3237-99?tabid=2 - Yagi, J. (2014, August 24). Trojan.Volgmer. Retrieved July 16, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www.threatminer.org/_reports/2013/fta-1009---njrat-uncovered-1.pdf - Fidelis Cybersecurity. (2013, June 28). Fidelis Threat Advisory #1009: "njRAT" Uncovered. Retrieved June 4, 2019.
* https://www.threatstream.com/blog/evasive-maneuvers-the-wekby-group-attempts-to-evade-analysis-via-custom-rop - Shelmire, A.. (2015, July 6). Evasive Maneuvers. Retrieved January 22, 2016.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-operation-tropic-trooper.pdf - Alintanahin, K. (2015). Operation Tropic Trooper: Relying on Tried-and-Tested Flaws to Infiltrate Secret Keepers. Retrieved June 14, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-132A - US-CERT. (2017, May 12). Alert (TA17-132A): Indicators Associated With WannaCry Ransomware. Retrieved March 25, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-318A - US-CERT. (2017, November 22). Alert (TA17-318A): HIDDEN COBRA – North Korean Remote Administration Tool: FALLCHILL. Retrieved December 7, 2017.
* https://www.us-cert.gov/ncas/alerts/TA17-318B - US-CERT. (2017, November 22). Alert (TA17-318B): HIDDEN COBRA – North Korean Trojan: Volgmer. Retrieved December 7, 2017.
* https://www.us-cert.gov/ncas/analysis-reports/AR18-165A - US-CERT. (2018, June 14). MAR-10135536-12 – North Korean Trojan: TYPEFRAME. Retrieved July 13, 2018.
* https://www.us-cert.gov/ncas/analysis-reports/AR18-221A - US-CERT. (2018, August 09). MAR-10135536-17 – North Korean Trojan: KEYMARBLE. Retrieved August 16, 2018.
* https://www.us-cert.gov/ncas/analysis-reports/AR19-100A - US-CERT. (2019, April 10). MAR-10135536-8 – North Korean Trojan: HOPLIGHT. Retrieved April 19, 2019.
* https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-D_WHITE_S508C.PDF - US-CERT. (2017, November 01). Malware Analysis Report (MAR) - 10135536-D. Retrieved July 16, 2018.
* https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-F.pdf - US-CERT. (2018, February 05). Malware Analysis Report (MAR) - 10135536-F. Retrieved June 11, 2018.
* https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF - US-CERT. (2018, February 06). Malware Analysis Report (MAR) - 10135536-G. Retrieved June 7, 2018.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.washingtonpost.com/business/economy/more-than-150-countries-affected-by-massive-cyberattack-europol-says/2017/05/14/5091465e-3899-11e7-9e48-c4f199710b69_story.html?utm_term=.7fa16b41cad4 - Dwoskin, E. and Adam, K. (2017, May 14). More than 150 countries affected by massive cyberattack, Europol says. Retrieved March 25, 2019.
* https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/ - ESET. (2017, March 30). Carbon Paper: Peering into Turla’s second stage backdoor. Retrieved November 7, 2018.
* https://www.welivesecurity.com/2019/05/29/turla-powershell-usage/ - Faou, M. and Dumont R.. (2019, May 29). A dive into Turla PowerShell usage. Retrieved June 14, 2019.
* https://www.welivesecurity.com/wp-content/uploads/2017/08/eset-gazer.pdf - ESET. (2017, August). Gazing at Gazer: Turla’s new second stage backdoor. Retrieved September 14, 2017.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf - ESET, et al. (2018, January). Diplomats in Eastern Europe bitten by a Turla mosquito. Retrieved July 3, 2018.
* https://www.welivesecurity.com/wp-content/uploads/2019/05/ESET-LightNeuron.pdf - Faou, M. (2019, May). Turla LightNeuron: One email away from remote code execution. Retrieved June 24, 2019.
* https://www2.fireeye.com/rs/848-DID-242/images/rpt-apt29-hammertoss.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved September 17, 2015.
* https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.
* https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf - FireEye Labs. (2015, April). APT30 AND THE MECHANICS OF A LONG-RUNNING CYBER ESPIONAGE OPERATION. Retrieved May 1, 2015.

