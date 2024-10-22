threat-crank.py 0.2.1
I: searching for industries that match .* transport.*|.* rail.*|.* train.*|.* car.*|.* vehicle.*|.* road.*|.* automotiv.*|.* boat.*|.* tanker.*|.* plane.*|.* airport.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v4.0/enterprise-attack/enterprise-attack.json
# Threat groups

* APT33
* Carbanak
* Cobalt Group
* Dark Caracal
* DarkHydrus
* FIN5
* FIN6
* FIN7
* Leviathan
* OilRig
* Tropic Trooper

# Validate the following attacks

* Account Discovery - 2
* Application Shimming - 1
* Automated Collection - 3
* BITS Jobs - 2
* Binary Padding - 1
* Brute Force - 2
* Bypass User Account Control - 1
* CMSTP - 1
* Code Signing - 2
* Command-Line Interface - 4
* Commonly Used Port - 3
* Compiled HTML File - 2
* Credential Dumping - 5
* Custom Command and Control Protocol - 1
* Data Compressed - 2
* Data Encoding - 1
* Data Encrypted - 1
* Data Staged - 3
* Data from Local System - 1
* Deobfuscate/Decode Files or Information - 3
* Disabling Security Tools - 1
* Drive-by Compromise - 1
* Dynamic Data Exchange - 2
* Execution Guardrails - 1
* Exfiltration Over Alternative Protocol - 2
* Exploitation for Client Execution - 4
* Exploitation for Privilege Escalation - 3
* External Remote Services - 2
* Fallback Channels - 1
* File Deletion - 3
* File and Directory Discovery - 1
* Forced Authentication - 1
* Hidden Files and Directories - 1
* Indicator Removal from Tools - 1
* Indicator Removal on Host - 1
* Input Capture - 1
* Logon Scripts - 1
* Masquerading - 3
* Mshta - 1
* Network Service Scanning - 3
* Network Sniffing - 1
* New Service - 3
* Obfuscated Files or Information - 7
* Password Policy Discovery - 1
* Permission Groups Discovery - 2
* PowerShell - 7
* Process Discovery - 2
* Process Injection - 2
* Query Registry - 1
* Redundant Access - 3
* Registry Run Keys / Startup Folder - 6
* Regsvr32 - 2
* Remote Access Tools - 2
* Remote Desktop Protocol - 4
* Remote File Copy - 5
* Remote Services - 2
* Remote System Discovery - 2
* Rundll32 - 1
* Scheduled Task - 5
* Screen Capture - 3
* Scripting - 7
* Security Software Discovery - 2
* Service Execution - 1
* Shortcut Modification - 2
* Signed Binary Proxy Execution - 1
* Software Packing - 1
* Spearphishing Attachment - 6
* Spearphishing Link - 4
* Spearphishing via Service - 1
* Standard Application Layer Protocol - 6
* Standard Cryptographic Protocol - 5
* System Information Discovery - 1
* System Network Configuration Discovery - 1
* System Network Connections Discovery - 1
* System Owner/User Discovery - 1
* System Service Discovery - 1
* Template Injection - 2
* Uncommonly Used Port - 1
* User Execution - 7
* Valid Accounts - 6
* Video Capture - 1
* Virtualization/Sandbox Evasion - 1
* Web Service - 4
* Web Shell - 2
* Windows Management Instrumentation - 2
* Windows Management Instrumentation Event Subscription - 1
* Winlogon Helper DLL - 1
* XSL Script Processing - 1

# Validate the following phases

* collection - 12
* command-and-control - 29
* credential-access - 10
* defense-evasion - 62
* discovery - 23
* execution - 48
* exfiltration - 5
* initial-access - 20
* lateral-movement - 12
* persistence - 36
* privilege-escalation - 23

# Validate the following platforms

* Android - 1
* Linux - 152
* Windows - 282
* macOS - 157

# Validate the following defences

* Anti-virus - 24
* Anti-virus, Host forensic analysis, Signature-based detection, Static File Analysis - 1
* Anti-virus,Host forensic analysis - 1
* Application whitelisting - 14
* Binary Analysis - 4
* Data Execution Prevention - 7
* Digital Certificate Validation - 8
* Exploit Prevention - 7
* File monitoring - 1
* Firewall - 12
* Heuristic detection - 1
* Host forensic analysis - 13
* Host intrusion prevention systems - 19
* Log analysis - 14
* Network intrusion detection system - 12
* Process whitelisting - 24
* Signature-based detection - 14
* Static File Analysis - 3
* System access controls - 6
* Whitelisting by file name or path - 10
* Windows User Account Control - 3

# Validate the following data sources

* API monitoring - 22
* Anti-virus - 18
* Application logs - 3
* Authentication logs - 24
* Binary file metadata - 25
* DLL monitoring - 12
* DNS records - 4
* Data loss prevention - 3
* Detonation chamber - 10
* Email gateway - 19
* Environment variable - 7
* File monitoring - 89
* Host network interface - 6
* Kernel drivers - 1
* Loaded DLLs - 10
* Mail server - 10
* Malware reverse engineering - 20
* Named Pipes - 2
* Netflow/Enclave netflow - 40
* Network device logs - 3
* Network intrusion detection system - 19
* Network protocol analysis - 31
* Packet capture - 47
* PowerShell logs - 12
* Process command-line parameters - 103
* Process monitoring - 158
* Process use of network - 47
* SSL/TLS inspection - 22
* Services - 1
* System calls - 6
* User interface - 2
* WMI Objects - 1
* Web logs - 2
* Web proxy - 6
* Windows Error Reporting - 3
* Windows Registry - 28
* Windows event logs - 21

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/ - Wrightson, T. (2012, January 2). CAPTURING WINDOWS 7 CREDENTIALS AT LOGON USING CUSTOM CREDENTIAL PROVIDER. Retrieved November 12, 2014.
* http://blog.redxorblue.com/2018/07/executing-macros-from-docx-with-remote.html - Hawkins, J. (2018, July 18). Executing Macros From a DOCX With Remote Template Injection. Retrieved October 12, 2018.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://en.wikipedia.org/wiki/Executable_compression - Executable compression. (n.d.). Retrieved December 4, 2014.
* http://hick.org/code/skape/papers/needle.txt - skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://phrack.org/issues/51/8.html - halflife. (1997, September 1). Shared Library Redirection Techniques. Retrieved December 20, 2017.
* http://vxer.org/lib/vrn00.html - O'Neill, R. (2009, May). Modern Day ELF Runtime infection via GOT poisoning. Retrieved December 20, 2017.
* http://www.blackhillsinfosec.com/?p=4645 - Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.
* http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html - stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.
* http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/ - Seetharaman, N. (2018, July 7). Detecting CMSTP-Enabled Code Execution and UAC Bypass With Sysmon.. Retrieved August 6, 2018.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html - Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.metasploit.com - Metasploit. (n.d.). Retrieved December 4, 2014.
* http://www.netsec.colostate.edu/~zhang/DetectingEncryptedBotnetTraffic.pdf - Zhang, H., Papadopoulos, C., & Massey, D. (2013, April). Detecting encrypted botnet traffic. Retrieved August 19, 2015.
* http://www.pretentiousname.com/misc/win7_uac_whitelist2.html - Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://access.redhat.com/documentation/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.crysys.hu/2013/03/teamspy/ - CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.
* https://blog.cylance.com/windows-registry-persistence-part-2-the-run-keys-and-search-order - Langendorf, S. (2013, September 24). Windows Registry Persistence, Part 2: The Run Keys and Search-Order. Retrieved April 11, 2018.
* https://blog.didierstevens.com/2017/11/13/webdav-traffic-to-malicious-sites/ - Stevens, D. (2017, November 13). WebDAV Traffic To Malicious Sites. Retrieved December 21, 2017.
* https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows - Liberman, T. (2016, October 27). ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWS. Retrieved December 8, 2017.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/10/decoy-microsoft-word-document-delivers-malware-through-rat/ - Segura, J. (2017, October 13). Decoy Microsoft Word document delivers malware through a RAT. Retrieved July 21, 2018.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.talosintelligence.com/2017/07/template-injection.html - Baird, S. et al.. (2017, July 7). Attack on Critical Infrastructure Leverages Template Injection. Retrieved July 21, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/attack-using-windows-installer-msiexec-exe-leads-lokibot/ - Co, M. and Sison, G. (2018, February 8). Attack Using Windows Installer msiexec.exe leads to LokiBot. Retrieved April 18, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/backdoor-carrying-emails-set-sights-on-russian-speaking-businesses/ - Bermejo, L., Giagone, R., Wu, R., and Yarochkin, F. (2017, August 7). Backdoor-carrying Emails Set Sights on Russian-speaking Businesses. Retrieved March 7, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/cobalt-spam-runs-use-macros-cve-2017-8759-exploit/ - Giagone, R., Bermejo, L., and Yarochkin, F. (2017, November 20). Cobalt Strikes Again: Spam Runs Use Macros and CVE-2017-8759 Exploit Against Russian Banks. Retrieved March 7, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/plead-targeted-attacks-against-taiwanese-government-agencies-2/ - Alintanahin, K.. (2014, May 23). PLEAD Targeted Attacks Against Taiwanese Government Agencies. Retrieved April 22, 2019.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://docs.microsoft.com/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script - Wenzel, M. et al. (2017, March 30). XSLT Stylesheet Scripting Using <msxsl:script>. Retrieved July 3, 2018.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749211(v=ws.10) - Microsoft. (2008, July 25). Credential Security Service Provider and SSO for Terminal Services Logon. Retrieved April 11, 2018.
* https://docs.microsoft.com/en-us/sql/odbc/odbcconf-exe?view=sql-server-2017 - Microsoft. (2017, January 18). ODBCCONF.EXE. Retrieved March 7, 2019.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts - Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.
* https://docs.microsoft.com/powershell/module/microsoft.powershell.management/clear-eventlog - Microsoft. (n.d.). Clear-EventLog. Retrieved July 2, 2018.
* https://docs.microsoft.com/previous-versions/office/developer/office-2007/aa338205(v=office.12) - Microsoft. (2014, July 9). Introducing the Office (2007) Open XML File Formats. Retrieved July 20, 2018.
* https://docs.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-1-4-sdk - Microsoft. (2018, May 30). Microsoft HTML Help 1.4. Retrieved October 3, 2018.
* https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc786431(v=ws.10) - Microsoft. (2009, October 8). How Connection Manager Works. Retrieved April 11, 2018.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
* https://docs.microsoft.com/windows-server/administration/windows-commands/wevtutil - Plett, C. et al.. (2017, October 16). wevtutil. Retrieved July 2, 2018.
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
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.
* https://en.wikipedia.org/wiki/Windows_Registry - Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://forum.anomali.com/t/credential-harvesting-and-malicious-file-delivery-using-microsoft-office-template-injection/2104 - Intel_Acquisition_Team. (2018, March 1). Credential Harvesting and Malicious File Delivery using Microsoft Office Template Injection. Retrieved July 20, 2018.
* https://github.com/Genetic-Malware/Ebowla/blob/master/Eko_2016_Morrow_Pitts_Master.pdf - Morrow, T., Pitts, J. (2016, October 28). Genetic Malware: Designing Payloads for Specific Targets. Retrieved January 18, 2019.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/api0cradle/UltimateAppLockerByPassList - Moe, O. (2018, March 1). Ultimate AppLocker Bypass List. Retrieved April 10, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/hob0/hashjacking - Dunning, J. (2016, August 1). Hashjacking. Retrieved December 21, 2017.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/nccgroup/demiguise/blob/master/examples/virginkey.js - Warren, R. (2017, August 2). Demiguise: virginkey.js. Retrieved January 17, 2019.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh - undefined. (n.d.). Retrieved April 12, 2019.
* https://github.com/ryhanson/phishery - Hanson, R. (2016, September 24). phishery. Retrieved July 21, 2018.
* https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf - CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://lolbas-project.github.io/lolbas/Binaries/Msiexec/ - LOLBAS. (n.d.). Msiexec.exe. Retrieved April 18, 2019.
* https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/ - LOLBAS. (n.d.). Odbcconf.exe. Retrieved March 7, 2019.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/20134940/kaspersky-lab-gauss.pdf - Kaspersky Lab. (2012, August). Gauss: Abnormal Distribution. Retrieved January 17, 2019.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc422924.aspx - Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://msdn.microsoft.com/library/system.diagnostics.eventlog.clear.aspx - Microsoft. (n.d.). EventLog.Clear Method (). Retrieved July 2, 2018.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms649053.aspx - Microsoft. (n.d.). About Atom Tables. Retrieved December 8, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms681951.aspx - Microsoft. (n.d.). Asynchronous Procedure Calls. Retrieved December 8, 2017.
* https://msdn.microsoft.com/windows/desktop/ms524405 - Microsoft. (n.d.). About the HTML Help Executable Program. Retrieved October 3, 2018.
* https://msdn.microsoft.com/windows/desktop/ms644670 - Microsoft. (n.d.). HTML Help ActiveX Control Overview. Retrieved October 3, 2018.
* https://msitpros.com/?p=3909 - Moe, O. (2017, August 13). Bypassing Device guard UMCI using CHM – CVE-2017-8625. Retrieved October 3, 2018.
* https://msitpros.com/?p=3960 - Moe, O. (2017, August 15). Research on CMSTP.exe. Retrieved April 11, 2018.
* https://objective-see.com/blog/blog_0x25.html - Patrick Wardle. (n.d.). Retrieved March 20, 2018.
* https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html - Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://osandamalith.com/2017/03/24/places-of-interest-in-stealing-netntlm-hashes/ - Malith, O. (2017, March 24). Places of Interest in Stealing NetNTLM Hashes. Retrieved January 26, 2018.
* https://pdfs.semanticscholar.org/2721/3d206bc3c1e8c229fb4820b6af09e7f975da.pdf - Song, C., et al. (2012, August 7). Impeding Automated Malware Analysis with Environment-sensitive Malware. Retrieved January 18, 2019.
* https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/ - netbiosX. (2017, July 6). AppLocker Bypass – MSXSL. Retrieved July 3, 2018.
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8625 - Microsoft. (2017, August 8). CVE-2017-8625 - Internet Explorer Security Feature Bypass Vulnerability. Retrieved October 3, 2018.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://reaqta.com/2018/03/spear-phishing-campaign-leveraging-msxsl/ - Admin. (2018, March 2). Spear-phishing campaign leveraging on MSXSL. Retrieved July 3, 2018.
* https://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/ - Bryan Lee and Rob Downs. (2016, February 12). A Look Into Fysbis: Sofacy’s Linux Backdoor. Retrieved September 10, 2017.
* https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/ - Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://researchcenter.paloaltonetworks.com/2018/06/unit42-rancor-targeted-attacks-south-east-asia-using-plaintee-ddkong-malware-families/ - Ash, B., et al. (2018, June 26). RANCOR: Targeted Attacks in South East Asia Using PLAINTEE and DDKONG Malware Families. Retrieved July 2, 2018.
* https://researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/ - Falcone, R., et al. (2018, September 04). OilRig Targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE. Retrieved September 24, 2018.
* https://resources.infosecinstitute.com/spoof-using-right-to-left-override-rtlo-technique-2/ - Security Ninja. (2015, April 16). Spoof Using Right to Left Override (RTLO) Technique. Retrieved April 22, 2019.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securelist.com/zero-day-vulnerability-in-telegram/83800/ - Firsh, A.. (2018, February 13). Zero-day vulnerability in Telegram - Cybercriminals exploited Telegram flaw to launch multipurpose attacks. Retrieved April 22, 2019.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/stopping-malware-fake-virtual-machine/ - Roccia, T. (2017, January 19). Stopping Malware With a Fake Virtual Machine. Retrieved April 17, 2019.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html - Smith, C. (2018, April 17). WMIC.EXE Whitelisting Bypass - Hacking with Style, Stylesheets. Retrieved July 3, 2018.
* https://superuser.com/questions/150675/how-to-display-password-policy-information-for-a-user-ubuntu - Matutiae, M. (2014, August 6). How to display password policy information for a user (Ubuntu)?. Retrieved April 5, 2018.
* https://support.apple.com/de-at/HT2420 - Apple. (2011, June 1). Mac OS X: Creating a login hook. Retrieved July 17, 2017.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
* https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx - Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.
* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works - Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/cc758918(v=ws.10).aspx - Microsoft. (2005, January 21). Creating logon scripts. Retrieved April 27, 2016.
* https://technet.microsoft.com/en-us/library/cc772408.aspx - Microsoft. (n.d.). Services. Retrieved June 7, 2016.
* https://technet.microsoft.com/en-us/library/cc785125.aspx - Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/ItsReallyNick/status/958789644165894146 - Carr, N. (2018, January 31). Here is some early bad cmstp.exe... Retrieved April 11, 2018.
* https://twitter.com/NickTyrer/status/958450014111633408 - Tyrer, N. (2018, January 30). CMSTP.exe - remote .sct execution applocker bypass. Retrieved April 11, 2018.
* https://twitter.com/dez_/status/986614411711442944 - Desimone, J. (2018, April 18). Status Update. Retrieved July 3, 2018.
* https://twitter.com/gn3mes1s/status/941315826107510784 - Giuseppe. (2017, December 14). gN3mes1s Status Update. Retrieved April 10, 2018.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://twitter.com/monoxgas/status/895045566090010624 - Landers, N. (2017, August 8). monoxgas Status Update. Retrieved April 10, 2018.
* https://unit42.paloaltonetworks.com/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/ - Falcone, R., Lee, B.. (2018, November 20). Sofacy Continues Global Attacks and Wheels Out New ‘Cannon’ Trojan. Retrieved April 23, 2019.
* https://unit42.paloaltonetworks.com/ups-observations-on-cve-2015-3113-prior-zero-days-and-the-pirpi-payload/ - Falcone, R., Wartell, R.. (2015, July 27). UPS: Observations on CVE-2015-3113, Prior Zero-Days and the Pirpi Payload. Retrieved April 23, 2019.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://web.archive.org/web/20161128183535/https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html - Smith, C. (2016, April 19). Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files). Retrieved June 30, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf - Pierce, Sean. (2015, November). Defending Against Malicious Application Compatibility Shims. Retrieved June 22, 2017.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/ - Gavriel, H. & Erbesfeld, B. (2018, April 11). New ‘Early Bird’ Code Injection Technique Discovered. Retrieved May 24, 2018.
* https://www.cyberscoop.com/kevin-mandia-fireeye-u-s-malware-nice/ - Shoorbajee, Z. (2018, June 1). Playing nice? FireEye CEO says U.S. malware is more restrained than adversaries'. Retrieved January 17, 2019.
* https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf - Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.
* https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.
* https://www.cylance.com/content/dam/cylance/pdfs/white_papers/RedirectToSMB.pdf - Cylance. (2015, April 13). Redirect to SMB. Retrieved December 21, 2017.
* https://www.datawire.io/code-injection-on-linux-and-macos/ - Turner-Trauring, I. (2017, April 18). “This will only hurt for a moment”: code injection on Linux and macOS with LD_PRELOAD. Retrieved December 20, 2017.
* https://www.defcon.org/images/defcon-22/dc-22-presentations/Kazanciyan-Hastings/DEFCON-22-Ryan-Kazanciyan-Matt-Hastings-Investigating-Powershell-Attacks.pdf - Kazanciyan, R. & Hastings, M. (2014). Defcon 22 Presentation. Investigating PowerShell Attacks &#91;slides&#93;. Retrieved November 3, 2014.
* https://www.endgame.com/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.f-secure.com/documents/996508/1030745/CozyDuke - F-Secure Labs. (2015, April 22). CozyDuke: Malware Analysis. Retrieved December 10, 2015.
* https://www.fidelissecurity.com/sites/default/files/FTA_1018_looking_at_the_sky_for_a_dark_comet.pdf - Fidelis Cybersecurity. (2015, August 4). Looking at the Sky for a DarkComet. Retrieved April 5, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html - Berry, A., Galang, L., Jiang, G., Leathery, J., Mohandas, R. (2017, April 11). CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler. Retrieved October 27, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/blog/threat-research/2017/11/ursnif-variant-malicious-tls-callback-technique.html - Vaish, A. & Nemes, S. (2017, November 28). Newly Observed Ursnif Variant Employs Malicious TLS Callback Technique to Achieve Process Injection. Retrieved December 18, 2017.
* https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html - Matsuda, A., Muhammad I. (2018, September 13). APT10 Targeting Japanese Corporations Using Updated TTPs. Retrieved September 17, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.gnu.org/software/acct/ - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.
* https://www.jamf.com/jamf-nation/discussions/18574/user-password-policies-on-non-ad-machines - Holland, J. (2016, January 25). User password policies on non AD machines. Retrieved April 5, 2018.
* https://www.microsoft.com/download/details.aspx?id=21714 - Microsoft. (n.d.). Command Line Transformation Utility (msxsl.exe). Retrieved July 3, 2018.
* https://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/4beddb35-0cba-424c-8b9b-a5832ad8e208.mspx - Microsoft. (n.d.). Managing WebDAV Security (IIS 6.0). Retrieved December 21, 2017.
* https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/august/smuggling-hta-files-in-internet-exploreredge/ - Warren, R. (2017, August 8). Smuggling HTA files in Internet Explorer/Edge. Retrieved January 16, 2019.
* https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf - Claud Xiao. (n.d.). WireLurker: A New Era in iOS and OS X Malware. Retrieved July 10, 2017.
* https://www.proofpoint.com/us/threat-insight/post/home-routers-under-attack-malvertising-windows-android-devices - Kafeine. (2016, December 13). Home Routers Under Attack via Malvertising on Windows, Android Devices. Retrieved January 16, 2019.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667 - Keragala, D. (2016, January 16). Detecting Malware and Sandbox Evasion Techniques. Retrieved April 17, 2019.
* https://www.sans.org/reading-room/whitepapers/testing/template-injection-attacks-bypassing-security-controls-living-land-38780 - Wiltse, B.. (2018, November 7). Template Injection Attacks - Bypassing Security Controls by Living off the Land. Retrieved April 10, 2019.
* https://www.schneier.com/academic/paperfiles/paper-clueless-agents.pdf - Riordan, J., Schneier, B. (1998, June 18). Environmental Key Generation towards Clueless Agents. Retrieved January 18, 2019.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf - Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing - Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.
* https://www.uperesia.com/analyzing-malicious-office-documents - Felix. (2016, September). Analyzing Malicious Office Documents. Retrieved April 11, 2018.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.us-cert.gov/ncas/alerts/TA17-293A - US-CERT. (2017, October 20). Alert (TA17-293A): Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved November 2, 2017.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.). Retrieved December 4, 2014.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2016/03/30/meet-remaiten-a-linux-bot-on-steroids-targeting-routers-and-potentially-other-iot-devices/ - Michal Malik AND Marc-Etienne M.Léveillé. (2016, March 30). Meet Remaiten – a Linux bot on steroids targeting routers and potentially other IoT devices. Retrieved September 7, 2017.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* BITSAdmin - 1
* Cobalt Strike - 4
* Empire - 1
* FTP - 2
* LaZagne - 2
* Mimikatz - 5
* Net - 3
* PoshC2 - 1
* PowerSploit - 1
* PsExec - 5
* Pupy - 1
* Reg - 1
* Ruler - 1
* SDelete - 2
* Systeminfo - 1
* Tasklist - 1
* Windows Credential Editor - 3
* at - 1
* certutil - 1
* ipconfig - 1
* netsh - 1
* netstat - 1
* pwdump - 1

# Review the following tool references

* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* http://www.ampliasecurity.com/research/wcefaq.html - Amplia Security. (n.d.). Windows Credentials Editor (WCE) F.A.Q.. Retrieved December 17, 2015.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive - Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://en.wikipedia.org/wiki/File_Transfer_Protocol - Wikipedia. (2016, June 15). File Transfer Protocol. Retrieved July 20, 2016.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (1985, June 22). pwdump. Retrieved June 22, 2016.
* https://github.com/AlessandroZ/LaZagne - Zanni, A. (n.d.). The LaZagne Project !!!. Retrieved December 14, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/n1nj4sec/pupy - Nicolas Verdier. (n.d.). Retrieved January 29, 2018.
* https://github.com/nettitude/PoshC2 - Nettitude. (2016, June 8). PoshC2: Powershell C2 Server and Implants. Retrieved April 23, 2019.
* https://github.com/sensepost/notruler - SensePost. (2017, September 21). NotRuler - The opposite of Ruler, provides blue teams with the ability to detect Ruler usage against Exchange. Retrieved February 4, 2019.
* https://github.com/sensepost/ruler - SensePost. (2016, August 18). Ruler: A tool to abuse Exchange services. Retrieved February 4, 2019.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://s3.eu-west-1.amazonaws.com/ncsc-content/files/Joint%20report%20on%20publicly%20available%20hacking%20tools%20%28NCSC%29.pdf - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://technet.microsoft.com/en-us/library/bb490866.aspx - Microsoft. (n.d.). At. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/bb490921.aspx - Microsoft. (n.d.). Ipconfig. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490947.aspx - Microsoft. (n.d.). Netstat. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb491007.aspx - Microsoft. (n.d.). Systeminfo. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/bb491010.aspx - Microsoft. (n.d.). Tasklist. Retrieved December 23, 2015.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/bb490939.aspx - Microsoft. (n.d.). Using Netsh. Retrieved February 13, 2017.
* https://technet.microsoft.com/library/cc732443.aspx - Microsoft. (2012, November 14). Certutil. Retrieved July 3, 2017.

# Validate the following malware

* AutoIt backdoor - 1
* BLACKCOFFEE - 1
* BONDUPDATER - 1
* Bandook - 1
* Carbanak - 2
* China Chopper - 1
* CrossRAT - 1
* Derusbi - 1
* FLIPSIDE - 1
* FinFisher - 1
* HALFBAKED - 1
* HOMEFRY - 1
* Helminth - 1
* ISMInjector - 1
* LockerGoga  - 1
* MURKYTOP - 1
* More_eggs - 1
* NETWIRE - 1
* NanHaiShu - 1
* NanoCore - 1
* OopsIE - 1
* Orz - 1
* POWERSOURCE - 1
* POWERTON - 1
* POWRUNER - 1
* PoisonIvy - 1
* QUADAGENT - 1
* RGDoor - 1
* RawPOS - 1
* RogueRobin - 1
* SEASHARPEE - 1
* Shamoon - 1
* TEXTMATE - 1
* TURNEDUP - 1

# Review the following malware references

* http://blog.talosintelligence.com/2017/03/dnsmessenger.html - Brumaghin, E. and Grady, C.. (2017, March 2). Covert Channels and Poor Decisions: The Tale of DNSMessenger. Retrieved March 8, 2017.
* http://download.microsoft.com/download/E/B/0/EB0F50CC-989C-4B66-B7F6-68CD3DC90DE3/Microsoft_Security_Intelligence_Report_Volume_21_English.pdf - Anthe, C. et al. (2016, December 14). Microsoft Security Intelligence Report Volume 21. Retrieved November 27, 2017.
* http://researchcenter.paloaltonetworks.com/2016/05/the-oilrig-campaign-attacks-on-saudi-arabian-organizations-deliver-helminth-backdoor/ - Falcone, R. and Lee, B.. (2016, May 26). The OilRig Campaign: Attacks on Saudi Arabian Organizations Deliver Helminth Backdoor. Retrieved May 3, 2017.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://sjc1-te-ftp.trendmicro.com/images/tex/pdf/RawPOS%20Technical%20Brief.pdf - TrendLabs Security Intelligence Blog. (2015, April). RawPOS Technical Brief. Retrieved October 4, 2017.
* http://www.finfisher.com/FinFisher/index.html - FinFisher. (n.d.). Retrieved December 20, 2017.
* http://www.kroll.com/CMSPages/GetAzureFile.aspx?path=~%5Cmedia%5Cfiles%5Cintelligence-center%5Ckroll_malware-analysis-report.pdf&hash=d5b5d2697118f30374b954f28a08c0ba69836c0ffd99566aa7ec62d1fc72b105 - Nesbit, B. and Ackerman, D. (2017, January). Malware Analysis Report - RawPOS Malware: Deconstructing an Intruder’s Toolkit. Retrieved October 4, 2017.
* http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://blog.talosintelligence.com/2018/07/multiple-cobalt-personality-disorder.html - Svajcer, V. (2018, July 31). Multiple Cobalt Personality Disorder. Retrieved September 5, 2018.
* https://cloudblogs.microsoft.com/microsoftsecure/2018/03/01/finfisher-exposed-a-researchers-tale-of-defeating-traps-tricks-and-complex-virtual-machines/ - Allievi, A.,Flori, E. (2018, March 01). FinFisher exposed: A researcher’s tale of defeating traps, tricks, and complex virtual machines. Retrieved July 9, 2018.
* https://cofense.com/nanocore-rat-resurfaced-sewers/ - Patel, K. (2018, March 02). The NanoCore RAT Has Resurfaced From the Sewers. Retrieved November 9, 2018.
* https://github.com/DiabloHorn/mempdump - DiabloHorn. (2015, March 22). mempdump. Retrieved October 6, 2017.
* https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf - Blaich, A., et al. (2018, January 18). Dark Caracal: Cyber-espionage at a Global Scale. Retrieved April 11, 2018.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf - Kaspersky Lab's Global Research and Analysis Team. (2015, February). CARBANAK APT THE GREAT BANK ROBBERY. Retrieved August 23, 2018.
* https://researchcenter.paloaltonetworks.com/2016/02/nanocorerat-behind-an-increase-in-tax-themed-phishing-e-mails/ - Kasza, A., Halfpop, T. (2016, February 09). NanoCoreRAT Behind an Increase in Tax-Themed Phishing E-mails. Retrieved November 9, 2018.
* https://researchcenter.paloaltonetworks.com/2017/10/unit42-oilrig-group-steps-attacks-new-delivery-documents-new-injector-trojan/ - Falcone, R. and Lee, B. (2017, October 9). OilRig Group Steps Up Attacks with New Delivery Documents and New Injector Trojan. Retrieved January 8, 2018.
* https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/ - Falcone, R. (2018, January 25). OilRig uses RGDoor IIS Backdoor on Targets in the Middle East. Retrieved July 6, 2018.
* https://researchcenter.paloaltonetworks.com/2018/02/unit42-oopsie-oilrig-uses-threedollars-deliver-new-trojan/ - Lee, B., Falcone, R. (2018, February 23). OopsIE! OilRig Uses ThreeDollars to Deliver New Trojan. Retrieved July 16, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-oilrig-targets-technology-service-provider-government-agency-quadagent/ - Lee, B., Falcone, R. (2018, July 25). OilRig Targets Technology Service Provider and Government Agency with QUADAGENT. Retrieved August 9, 2018.
* https://researchcenter.paloaltonetworks.com/2018/08/unit42-gorgon-group-slithering-nation-state-cybercrime/ - Falcone, R., et al. (2018, August 02). The Gorgon Group: Slithering Between Nation State and Cybercrime. Retrieved August 7, 2018.
* https://researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/ - Falcone, R., et al. (2018, September 04). OilRig Targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE. Retrieved September 24, 2018.
* https://securelist.com/blackoasis-apt-and-new-targeted-attacks-leveraging-zero-day-exploit/82732/ - Kaspersky Lab's Global Research & Analysis Team. (2017, October 16). BlackOasis APT and new targeted attacks leveraging zero-day exploit. Retrieved February 15, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/netwire-rat-behind-recent-targeted-attacks/ - McAfee. (2015, March 2). Netwire RAT Behind Recent Targeted Attacks. Retrieved February 15, 2018.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M.. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://unit42.paloaltonetworks.com/darkhydrus-delivers-new-trojan-that-can-use-google-drive-for-c2-communications/ - Lee, B., Falcone, R. (2019, January 18). DarkHydrus delivers new Trojan that can use Google Drive for C2 communications. Retrieved April 17, 2019.
* https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/ - Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.
* https://unit42.paloaltonetworks.com/unit42-oilrig-uses-updated-bondupdater-target-middle-eastern-government/ - Wilhoit, K. and Falcone, R. (2018, September 12). OilRig Uses Updated BONDUPDATER to Target Middle Eastern Government. Retrieved February 18, 2019.
* https://usa.visa.com/dam/VCOM/download/merchants/alert-rawpos.pdf - Visa. (2015, March). Visa Security Alert: "RawPOS" Malware Targeting Lodging Merchants. Retrieved October 6, 2017.
* https://www.brighttalk.com/webcast/10703/275683 - Davis, S. and Carr, N. (2017, September 21). APT33: New Insights into Iranian Cyber Espionage Group. Retrieved February 15, 2018.
* https://www.brighttalk.com/webcast/10703/296317/apt34-new-targeted-attack-in-the-middle-east - Davis, S. and Caban, D. (2017, December 19). APT34 - New Targeted Attack in the Middle East. Retrieved December 20, 2017.
* https://www.carbonblack.com/2019/03/22/tau-threat-intelligence-notification-lockergoga-ransomware/ - undefined. (2019, March 22). TAU Threat Intelligence Notification – LockerGoga Ransomware. Retrieved April 16, 2019.
* https://www.darkreading.com/analytics/prolific-cybercrime-gang-favors-legit-login-credentials/d/d-id/1322645? - Higgins, K. (2015, October 13). Prolific Cybercrime Gang Favors Legit Login Credentials. Retrieved October 4, 2017.
* https://www.digitrustgroup.com/nanocore-not-your-average-rat/ - The DigiTrust Group. (2017, January 01). NanoCore Is Not Your Average RAT. Retrieved November 9, 2018.
* https://www.eff.org/files/2016/08/03/i-got-a-letter-from-the-government.pdf - Galperin, E., Et al.. (2016, August). I Got a Letter From the Government the Other Day.... Retrieved April 25, 2018.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fidelissecurity.com/sites/default/files/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html - FireEye. (2016, November 30). FireEye Responds to Wave of Destructive Cyber Attacks in Gulf Region. Retrieved January 11, 2017.
* https://www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html - Miller, S., et al. (2017, March 7). FIN7 Spear Phishing Campaign Targets Personnel Involved in SEC Filings. Retrieved March 8, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html - Bennett, J., Vengerik, B. (2017, June 12). Behind the CARBANAK Backdoor. Retrieved June 11, 2018.
* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html - O'Leary, J., et al. (2017, September 20). Insights into Iranian Cyber Espionage: APT33 Targets Aerospace and Energy Sectors and has Ties to Destructive Malware. Retrieved February 15, 2018.
* https://www.fireeye.com/blog/threat-research/2017/09/zero-day-used-to-distribute-finspy.html - Jiang, G., et al. (2017, September 12). FireEye Uncovers CVE-2017-8759: Zero-Day Used in the Wild to Distribute FINSPY. Retrieved February 15, 2018.
* https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html - Sardiwal, M, et al. (2017, December 7). New Targeted Attack in the Middle East by APT34, a Suspected Iranian Threat Group, Using CVE-2017-11882 Exploit. Retrieved December 20, 2017.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html - Ackerman, G., et al. (2018, December 21). OVERRULED: Containing a Potentially Destructive Adversary. Retrieved January 17, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved November 12, 2014.
* https://www.forcepoint.com/sites/default/files/resources/files/forcepoint-security-labs-monsoon-analysis-report.pdf - Settle, A., et al. (2016, August 8). MONSOON - Analysis Of An APT Campaign. Retrieved September 22, 2016.
* https://www.fox-it.com/en/about-fox-it/corporate/news/anunak-aka-carbanak-update/ - Prins, R. (2015, February 16). Anunak (aka Carbanak) Update. Retrieved January 20, 2017.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/connect/blogs/shamoon-attacks - Symantec. (2012, August 16). The Shamoon Attacks. Retrieved March 14, 2019.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www.youtube.com/watch?v=fevGZs0EQu8 - Bromiley, M. and Lewis, P. (2016, October 7). Attacking the Hospitality and Gaming Industries: Tracking an Attacker Around the World in 7 Years. Retrieved October 6, 2017.
* https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.

