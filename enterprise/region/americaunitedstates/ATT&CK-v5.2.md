threat-crank.py 0.2.1
I: searching for regions that match .* america.*|.* united states.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v5.2/enterprise-attack/enterprise-attack.json
# Threat groups

* APT33
* Dust Storm
* FIN10
* Gorgon Group
* Lazarus Group
* Leviathan
* Molerats
* MuddyWater
* Orangeworm
* Sowbug

# Validate the following attacks

* Access Token Manipulation - 1
* Account Manipulation - 1
* Application Window Discovery - 1
* BITS Jobs - 1
* Binary Padding - 1
* Bootkit - 1
* Brute Force - 2
* Bypass User Account Control - 1
* CMSTP - 1
* Code Signing - 2
* Command-Line Interface - 5
* Commonly Used Port - 2
* Compile After Delivery - 1
* Compiled HTML File - 1
* Connection Proxy - 2
* Credential Dumping - 6
* Credentials in Files - 1
* Custom Cryptographic Protocol - 1
* Data Compressed - 4
* Data Destruction - 1
* Data Encoding - 2
* Data Encrypted - 1
* Data Staged - 2
* Data from Local System - 2
* Data from Network Shared Drive - 1
* Deobfuscate/Decode Files or Information - 3
* Disabling Security Tools - 2
* Disk Content Wipe - 1
* Disk Structure Wipe - 1
* Distributed Component Object Model - 1
* Drive-by Compromise - 1
* Dynamic Data Exchange - 1
* Execution Guardrails - 1
* Execution through API - 1
* Exfiltration Over Alternative Protocol - 2
* Exfiltration Over Command and Control Channel - 1
* Exploitation for Client Execution - 3
* Exploitation for Privilege Escalation - 1
* Fallback Channels - 1
* File Deletion - 2
* File and Directory Discovery - 4
* Hidden Files and Directories - 1
* Input Capture - 2
* Masquerading - 2
* Modify Registry - 1
* Mshta - 1
* Multi-Stage Channels - 1
* Multiband Communication - 1
* Network Share Discovery - 1
* Network Sniffing - 1
* New Service - 1
* Obfuscated Files or Information - 5
* PowerShell - 5
* Process Discovery - 3
* Process Hollowing - 1
* Process Injection - 2
* Query Registry - 1
* Registry Run Keys / Startup Folder - 6
* Regsvr32 - 1
* Remote Desktop Protocol - 3
* Remote File Copy - 6
* Remote Services - 1
* Resource Hijacking - 1
* Rundll32 - 1
* Scheduled Task - 2
* Screen Capture - 1
* Scripting - 5
* Security Software Discovery - 1
* Service Stop - 1
* Shortcut Modification - 3
* Spearphishing Attachment - 4
* Spearphishing Link - 2
* Standard Application Layer Protocol - 3
* Standard Cryptographic Protocol - 2
* System Information Discovery - 3
* System Network Configuration Discovery - 2
* System Owner/User Discovery - 3
* System Time Discovery - 1
* Timestomp - 1
* Uncommonly Used Port - 3
* User Execution - 5
* Valid Accounts - 3
* Web Service - 1
* Web Shell - 1
* Windows Admin Shares - 2
* Windows Management Instrumentation - 3
* Windows Management Instrumentation Event Subscription - 1

# Validate the following phases

* collection - 8
* command-and-control - 25
* credential-access - 13
* defense-evasion - 42
* discovery - 21
* execution - 35
* exfiltration - 8
* impact - 5
* initial-access - 10
* lateral-movement - 13
* persistence - 21
* privilege-escalation - 12

# Validate the following platforms

* Android - 1
* Linux - 132
* Windows - 238
* macOS - 134

# Validate the following defences

* Anti-virus - 17
* Application whitelisting - 9
* Binary Analysis - 2
* Data Execution Prevention - 5
* Digital Certificate Validation - 4
* Exploit Prevention - 5
* File monitoring - 2
* Firewall - 5
* Host forensic analysis - 12
* Host intrusion prevention systems - 14
* Log analysis - 8
* Network intrusion detection system - 6
* Process whitelisting - 17
* Signature-based detection - 14
* Static File Analysis - 2
* System access controls - 3
* Whitelisting by file name or path - 8
* Windows User Account Control - 3

# Validate the following data sources

* API monitoring - 24
* Access tokens - 1
* Anti-virus - 11
* Application logs - 1
* Authentication logs - 18
* Binary file metadata - 18
* DLL monitoring - 9
* DNS records - 2
* Detonation chamber - 6
* Email gateway - 11
* Environment variable - 5
* File monitoring - 76
* Host network interface - 2
* Kernel drivers - 4
* Loaded DLLs - 6
* MBR - 2
* Mail server - 6
* Malware reverse engineering - 14
* Named Pipes - 2
* Netflow/Enclave netflow - 33
* Network device logs - 4
* Network intrusion detection system - 10
* Network protocol analysis - 19
* Packet capture - 34
* PowerShell logs - 11
* Process command-line parameters - 94
* Process monitoring - 140
* Process use of network - 37
* SSL/TLS inspection - 11
* Services - 2
* System calls - 4
* User interface - 3
* VBR - 1
* WMI Objects - 1
* Web proxy - 3
* Windows Error Reporting - 1
* Windows Registry - 24
* Windows event logs - 14

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/ - Wrightson, T. (2012, January 2). CAPTURING WINDOWS 7 CREDENTIALS AT LOGON USING CUSTOM CREDENTIAL PROVIDER. Retrieved November 12, 2014.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/jepayne/archive/2015/11/24/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem.aspx - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* http://blogs.technet.com/b/jepayne/archive/2015/11/27/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts.aspx - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html - CG. (2014, May 20). Mimikatz Against Virtual Machine Memory Part 1. Retrieved November 12, 2014.
* http://hick.org/code/skape/papers/needle.txt - skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://msdn.microsoft.com/en-us/library/ms682425 - Microsoft. (n.d.). CreateProcess function. Retrieved December 5, 2014.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://phrack.org/issues/51/8.html - halflife. (1997, September 1). Shared Library Redirection Techniques. Retrieved December 20, 2017.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://vxer.org/lib/vrn00.html - O'Neill, R. (2009, May). Modern Day ELF Runtime infection via GOT poisoning. Retrieved December 20, 2017.
* http://windowsir.blogspot.com/2013/07/howto-determinedetect-use-of-anti.html - Carvey, H. (2013, July 23). HowTo: Determine/Detect the use of Anti-Forensics Techniques. Retrieved June 3, 2016.
* http://www.autosectools.com/process-hollowing.pdf - Leitch, J. (n.d.). Process Hollowing. Retrieved November 12, 2014.
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
* http://www.symantec.com/connect/blogs/are-mbr-infections-back-fashion - Lau, H. (2011, August 8). Are MBR Infections Back in Fashion? (Infographic). Retrieved November 13, 2014.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://access.redhat.com/documentation/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.cobaltstrike.com/2015/12/16/windows-access-tokens-and-alternate-credentials/ - Mudge, R. (n.d.). Windows Access Tokens and Alternate Credentials. Retrieved April 21, 2017.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows - Liberman, T. (2016, October 27). ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWS. Retrieved December 8, 2017.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/plead-targeted-attacks-against-taiwanese-government-agencies-2/ - Alintanahin, K.. (2014, May 23). PLEAD Targeted Attacks Against Taiwanese Government Agencies. Retrieved April 22, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/ - Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749211(v=ws.10) - Microsoft. (2008, July 25). Credential Security Service Provider and SSO for Terminal Services Logon. Retrieved April 11, 2018.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/windows/desktop/com/dcom-security-enhancements-in-windows-xp-service-pack-2-and-windows-server-2003-service-pack-1 - Microsoft. (n.d.). DCOM Security Enhancements in Windows XP Service Pack 2 and Windows Server 2003 Service Pack 1. Retrieved November 22, 2017.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts - Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.
* https://docs.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-1-4-sdk - Microsoft. (2018, May 30). Microsoft HTML Help 1.4. Retrieved October 3, 2018.
* https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc786431(v=ws.10) - Microsoft. (2009, October 8). How Connection Manager Works. Retrieved April 11, 2018.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
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
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/ - Nelson, M. (2017, January 5). Lateral Movement using the MMC20 Application COM Object. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/01/23/lateral-movement-via-dcom-round-2/ - Nelson, M. (2017, January 23). Lateral Movement via DCOM: Round 2. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/09/11/lateral-movement-using-excel-application-and-dcom/ - Nelson, M. (2017, September 11). Lateral Movement using Excel.Application and DCOM. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript/ - Nelson, M. (2017, November 16). Lateral Movement using Outlook's CreateObject Method and DotNetToJScript. Retrieved November 21, 2017.
* https://github.com/Genetic-Malware/Ebowla/blob/master/Eko_2016_Morrow_Pitts_Master.pdf - Morrow, T., Pitts, J. (2016, October 28). Genetic Malware: Designing Payloads for Specific Targets. Retrieved January 18, 2019.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/api0cradle/UltimateAppLockerByPassList - Moe, O. (2018, March 1). Ultimate AppLocker Bypass List. Retrieved April 10, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/issues/92 - Warren, J. (2017, June 22). lsadump::changentlm and lsadump::setntlm work, but generate Windows events #92. Retrieved December 4, 2017.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/nccgroup/demiguise/blob/master/examples/virginkey.js - Warren, R. (2017, August 2). Demiguise: virginkey.js. Retrieved January 17, 2019.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh - undefined. (n.d.). Retrieved April 12, 2019.
* https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html - Forshaw, J. (2018, April 18). Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege. Retrieved May 3, 2018.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180722/Report_Shamoon_StoneDrill_final.pdf - Kaspersky Lab. (2017, March 7). From Shamoon to StoneDrill: Wipers attacking Saudi organizations and beyond. Retrieved March 14, 2019.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/20134940/kaspersky-lab-gauss.pdf - Kaspersky Lab. (2012, August). Gauss: Abnormal Distribution. Retrieved January 17, 2019.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms687317(v=vs.85).aspx - Microsoft. (n.d.). Setting Process-Wide Security Through the Registry. Retrieved November 21, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/ms694331(v=vs.85).aspx - Microsoft. (n.d.). Registry Values for System-Wide Security. Retrieved November 21, 2017.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc422924.aspx - Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms649053.aspx - Microsoft. (n.d.). About Atom Tables. Retrieved December 8, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms681951.aspx - Microsoft. (n.d.). Asynchronous Procedure Calls. Retrieved December 8, 2017.
* https://msdn.microsoft.com/ms724961.aspx - Microsoft. (n.d.). System Time. Retrieved November 25, 2016.
* https://msdn.microsoft.com/windows/desktop/ms524405 - Microsoft. (n.d.). About the HTML Help Executable Program. Retrieved October 3, 2018.
* https://msdn.microsoft.com/windows/desktop/ms644670 - Microsoft. (n.d.). HTML Help ActiveX Control Overview. Retrieved October 3, 2018.
* https://msitpros.com/?p=3909 - Moe, O. (2017, August 13). Bypassing Device guard UMCI using CHM – CVE-2017-8625. Retrieved October 3, 2018.
* https://msitpros.com/?p=3960 - Moe, O. (2017, August 15). Research on CMSTP.exe. Retrieved April 11, 2018.
* https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html - Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved March 2, 2016.
* https://pdfs.semanticscholar.org/2721/3d206bc3c1e8c229fb4820b6af09e7f975da.pdf - Song, C., et al. (2012, August 7). Impeding Automated Malware Analysis with Environment-sensitive Malware. Retrieved January 18, 2019.
* https://pentestlab.blog/2017/04/03/token-manipulation/ - netbiosX. (2017, April 3). Token Manipulation. Retrieved April 21, 2017.
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8625 - Microsoft. (2017, August 8). CVE-2017-8625 - Internet Explorer Security Feature Bypass Vulnerability. Retrieved October 3, 2018.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/ - Bryan Lee and Rob Downs. (2016, February 12). A Look Into Fysbis: Sofacy’s Linux Backdoor. Retrieved September 10, 2017.
* https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/ - Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://resources.infosecinstitute.com/spoof-using-right-to-left-override-rtlo-technique-2/ - Security Ninja. (2015, April 16). Spoof Using Right to Left Override (RTLO) Technique. Retrieved April 22, 2019.
* https://securelist.com/lazarus-under-the-hood/77908/ - GReAT. (2017, April 3). Lazarus Under the Hood. Retrieved April 17, 2019.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securelist.com/zero-day-vulnerability-in-telegram/83800/ - Firsh, A.. (2018, February 13). Zero-day vulnerability in Telegram - Cybercriminals exploited Telegram flaw to launch multipurpose attacks. Retrieved April 22, 2019.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://skanthak.homepage.t-online.de/verifier.html - Kanthak, S. (2017). Application Verifier Provider. Retrieved February 13, 2017.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
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
* https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/ - Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://web.archive.org/web/20161128183535/https://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html - Smith, C. (2016, April 19). Bypass Application Whitelisting Script Protections - Regsvr32.exe & COM Scriptlets (.sct files). Retrieved June 30, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation.pdf - Atkinson, J., Winchester, R. (2017, December 7). A Process is No One: Hunting for Token Manipulation. Retrieved December 21, 2017.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/ - Gavriel, H. & Erbesfeld, B. (2018, April 11). New ‘Early Bird’ Code Injection Technique Discovered. Retrieved May 24, 2018.
* https://www.cybereason.com/blog/leveraging-excel-dde-for-lateral-movement-via-dcom - Tsukerman, P. (2017, November 8). Leveraging Excel DDE for lateral movement via DCOM. Retrieved November 21, 2017.
* https://www.cyberscoop.com/kevin-mandia-fireeye-u-s-malware-nice/ - Shoorbajee, Z. (2018, June 1). Playing nice? FireEye CEO says U.S. malware is more restrained than adversaries'. Retrieved January 17, 2019.
* https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf - Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.
* https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.
* https://www.datawire.io/code-injection-on-linux-and-macos/ - Turner-Trauring, I. (2017, April 18). “This will only hurt for a moment”: code injection on Linux and macOS with LD_PRELOAD. Retrieved December 20, 2017.
* https://www.defcon.org/images/defcon-22/dc-22-presentations/Kazanciyan-Hastings/DEFCON-22-Ryan-Kazanciyan-Matt-Hastings-Investigating-Powershell-Attacks.pdf - Kazanciyan, R. & Hastings, M. (2014). Defcon 22 Presentation. Investigating PowerShell Attacks &#91;slides&#93;. Retrieved November 3, 2014.
* https://www.endgame.com/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.f-secure.com/documents/996508/1030745/CozyDuke - F-Secure Labs. (2015, April 22). CozyDuke: Malware Analysis. Retrieved December 10, 2015.
* https://www.f-secure.com/documents/996508/1030745/cosmicduke_whitepaper.pdf - F-Secure Labs. (2014, July). COSMICDUKE Cosmu with a twist of MiniDuke. Retrieved July 3, 2014.
* https://www.fidelissecurity.com/sites/default/files/FTA_1018_looking_at_the_sky_for_a_dark_comet.pdf - Fidelis Cybersecurity. (2015, August 4). Looking at the Sky for a DarkComet. Retrieved April 5, 2016.
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
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/regional/fr_FR/offers/pdfs/ig-mtrends-2016.pdf - Mandiant. (2016, February). M-Trends 2016. Retrieved January 4, 2017.
* https://www.gnu.org/software/acct/ - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.
* https://www.justice.gov/opa/press-release/file/1092091/download - Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.
* https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/august/smuggling-hta-files-in-internet-exploreredge/ - Warren, R. (2017, August 8). Smuggling HTA files in Internet Explorer/Edge. Retrieved January 16, 2019.
* https://www.offensive-security.com/metasploit-unleashed/fun-incognito/ - Offensive Security. (n.d.). What is Incognito. Retrieved April 21, 2017.
* https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.
* https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf - Claud Xiao. (n.d.). WireLurker: A New Era in iOS and OS X Malware. Retrieved July 10, 2017.
* https://www.proofpoint.com/us/threat-insight/post/home-routers-under-attack-malvertising-windows-android-devices - Kafeine. (2016, December 13). Home Routers Under Attack via Malvertising on Windows, Android Devices. Retrieved January 16, 2019.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.rsaconference.com/writable/presentations/file_upload/ht-209_rivner_schwartz.pdf - Rivner, U., Schwartz, E. (2012). They’re Inside… Now What?. Retrieved November 25, 2016.
* https://www.schneier.com/academic/paperfiles/paper-clueless-agents.pdf - Riordan, J., Schneier, B. (1998, June 18). Environmental Key Generation towards Clueless Agents. Retrieved January 18, 2019.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.secureworks.com/research/wcry-ransomware-analysis - Counter Threat Unit Research Team. (2017, May 18). WCry Ransomware Analysis. Retrieved March 26, 2019.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.symantec.com/connect/blogs/shamoon-attacks - Symantec. (2012, August 16). The Shamoon Attacks. Retrieved March 14, 2019.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing - Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.
* https://www.uperesia.com/analyzing-malicious-office-documents - Felix. (2016, September). Analyzing Malicious Office Documents. Retrieved April 11, 2018.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.). Retrieved December 4, 2014.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2016/03/30/meet-remaiten-a-linux-bot-on-steroids-targeting-routers-and-potentially-other-iot-devices/ - Michal Malik AND Marc-Etienne M.Léveillé. (2016, March 30). Meet Remaiten – a Linux bot on steroids targeting routers and potentially other IoT devices. Retrieved September 7, 2017.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* Arp - 1
* BITSAdmin - 1
* Cobalt Strike - 1
* Empire - 2
* FTP - 1
* LaZagne - 2
* Mimikatz - 3
* Net - 3
* PoshC2 - 1
* PowerSploit - 1
* Pupy - 1
* QuasarRAT - 1
* RawDisk - 1
* Remcos - 1
* Ruler - 1
* Systeminfo - 1
* Windows Credential Editor - 1
* at - 1
* cmd - 1
* ipconfig - 1
* netsh - 1
* netstat - 1
* route - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* http://www.ampliasecurity.com/research/wcefaq.html - Amplia Security. (n.d.). Windows Credentials Editor (WCE) F.A.Q.. Retrieved December 17, 2015.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://blog.talosintelligence.com/2018/08/picking-apart-remcos.html - Brumaghin, E., Unterbrink, H. (2018, August 22). Picking Apart Remcos Botnet-In-A-Box. Retrieved November 6, 2018.
* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf - Lunghi, D., et al. (2017, December). Untangling the Patchwork Cyberespionage Group. Retrieved July 10, 2018.
* https://en.wikipedia.org/wiki/File_Transfer_Protocol - Wikipedia. (2016, June 15). File Transfer Protocol. Retrieved July 20, 2016.
* https://github.com/AlessandroZ/LaZagne - Zanni, A. (n.d.). The LaZagne Project !!!. Retrieved December 14, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/n1nj4sec/pupy - Nicolas Verdier. (n.d.). Retrieved January 29, 2018.
* https://github.com/nettitude/PoshC2 - Nettitude. (2016, June 8). PoshC2: Powershell C2 Server and Implants. Retrieved April 23, 2019.
* https://github.com/quasar/QuasarRAT - MaxXor. (n.d.). QuasarRAT. Retrieved July 10, 2018.
* https://github.com/sensepost/notruler - SensePost. (2017, September 21). NotRuler - The opposite of Ruler, provides blue teams with the ability to detect Ruler usage against Exchange. Retrieved February 4, 2019.
* https://github.com/sensepost/ruler - SensePost. (2016, August 18). Ruler: A tool to abuse Exchange services. Retrieved February 4, 2019.
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
* https://technet.microsoft.com/en-us/library/bb490991.aspx - Microsoft. (n.d.). Route. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb491007.aspx - Microsoft. (n.d.). Systeminfo. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/cc755121.aspx - Microsoft. (n.d.). Dir. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/cc771049.aspx - Microsoft. (n.d.). Del. Retrieved April 22, 2016.
* https://technet.microsoft.com/library/bb490939.aspx - Microsoft. (n.d.). Using Netsh. Retrieved February 13, 2017.
* https://www.fortinet.com/blog/threat-research/remcos-a-new-rat-in-the-wild-2.html - Bacurio, F., Salvio, J. (2017, February 14). REMCOS: A New RAT In The Wild. Retrieved November 6, 2018.
* https://www.itprotoday.com/windows-78/eldos-provides-raw-disk-access-vista-and-xp - Edwards, M. (2007, March 14). EldoS Provides Raw Disk Access for Vista and XP. Retrieved March 26, 2019.
* https://www.riskiq.com/blog/labs/spear-phishing-turkish-defense-contractors/ - Klijnsma, Y. (2018, January 23). Espionage Campaign Leverages Spear Phishing, RATs Against Turkish Defense Contractors. Retrieved November 6, 2018.
* https://www.volexity.com/blog/2018/06/07/patchwork-apt-group-targets-us-think-tanks/ - Meltzer, M, et al. (2018, June 07). Patchwork APT Group Targets US Think Tanks. Retrieved July 16, 2018.

# Validate the following malware

* AuditCred - 1
* AutoIt backdoor - 1
* BADCALL - 1
* BLACKCOFFEE - 1
* Bankshot - 1
* China Chopper - 1
* Derusbi - 1
* DustySky - 1
* FALLCHILL - 1
* Felismus - 1
* HARDRAIN - 1
* HOMEFRY - 1
* HOPLIGHT - 1
* KEYMARBLE - 1
* Kwampirs - 1
* MURKYTOP - 1
* Mis-Type - 1
* Misdat - 1
* NETWIRE - 1
* NanHaiShu - 1
* NanoCore - 2
* Orz - 1
* POWERSTATS - 1
* POWERTON - 1
* PoisonIvy - 1
* Proxysvc - 1
* RATANKBA - 1
* S-Type - 1
* Shamoon - 1
* Starloader - 1
* StoneDrill - 1
* TURNEDUP - 1
* TYPEFRAME - 1
* Volgmer - 1
* WannaCry - 1
* ZLib - 1
* njRAT - 1

# Review the following malware references

* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://www.clearskysec.com/wp-content/uploads/2016/06/Operation-DustySky2_-6.2016_TLP_White.pdf - ClearSky Cybersecurity. (2016, June 9). Operation DustySky - Part 2. Retrieved August 3, 2016.
* http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/autoit-compiled-worm-affecting-removable-media-delivers-fileless-version-of-bladabindi-njrat-backdoor/ - Pascual, C. (2018, November 27). AutoIt-Compiled Worm Affecting Removable Media Delivers Fileless Version of BLADABINDI/njRAT Backdoor. Retrieved June 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-campaign-targeting-cryptocurrencies-reveals-remote-controller-tool-evolved-ratankba/ - Lei, C., et al. (2018, January 24). Lazarus Campaign Targeting Cryptocurrencies Reveals Remote Controller Tool, an Evolved RATANKBA, and More. Retrieved May 22, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/lazarus-continues-heists-mounts-attacks-on-financial-organizations-in-latin-america/ - Trend Micro. (2018, November 20). Lazarus Continues Heists, Mounts Attacks on Financial Organizations in Latin America. Retrieved December 3, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/ratankba-watering-holes-against-enterprises/ - Trend Micro. (2017, February 27). RATANKBA: Delving into Large-scale Watering Holes against Enterprises. Retrieved May 22, 2018.
* https://blogs.forcepoint.com/security-labs/playing-cat-mouse-introducing-felismus-malware - Somerville, L. and Toro, A. (2017, March 30). Playing Cat & Mouse: Introducing the Felismus Malware. Retrieved November 16, 2017.
* https://cofense.com/nanocore-rat-resurfaced-sewers/ - Patel, K. (2018, March 02). The NanoCore RAT Has Resurfaced From the Sewers. Retrieved November 9, 2018.
* https://logrhythm.com/blog/a-technical-analysis-of-wannacry-ransomware/ - Noerenberg, E., Costis, A., and Quist, N. (2017, May 16). A Technical Analysis of WannaCry Ransomware. Retrieved March 25, 2019.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180722/Report_Shamoon_StoneDrill_final.pdf - Kaspersky Lab. (2017, March 7). From Shamoon to StoneDrill: Wipers attacking Saudi organizations and beyond. Retrieved March 14, 2019.
* https://researchcenter.paloaltonetworks.com/2016/02/nanocorerat-behind-an-increase-in-tax-themed-phishing-e-mails/ - Kasza, A., Halfpop, T. (2016, February 09). NanoCoreRAT Behind an Increase in Tax-Themed Phishing E-mails. Retrieved November 9, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/ - Lancaster, T.. (2017, November 14). Muddying the Water: Targeted Attacks in the Middle East. Retrieved March 15, 2018.
* https://researchcenter.paloaltonetworks.com/2018/08/unit42-gorgon-group-slithering-nation-state-cybercrime/ - Falcone, R., et al. (2018, August 02). The Gorgon Group: Slithering Between Nation State and Cybercrime. Retrieved August 7, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/analyzing-operation-ghostsecret-attack-seeks-to-steal-data-worldwide/ - Sherstobitoff, R., Malhotra, A. (2018, April 24). Analyzing Operation GhostSecret: Attack Seeks to Steal Data Worldwide. Retrieved May 16, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/hidden-cobra-targets-turkish-financial-sector-new-bankshot-implant/ - Sherstobitoff, R. (2018, March 08). Hidden Cobra Targets Turkish Financial Sector With New Bankshot Implant. Retrieved May 18, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/netwire-rat-behind-recent-targeted-attacks/ - McAfee. (2015, March 2). Netwire RAT Behind Recent Targeted Attacks. Retrieved February 15, 2018.
* https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/ - Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.
* https://www.brighttalk.com/webcast/10703/275683 - Davis, S. and Carr, N. (2017, September 21). APT33: New Insights into Iranian Cyber Espionage Group. Retrieved February 15, 2018.
* https://www.clearskysec.com/wp-content/uploads/2016/01/Operation%20DustySky_TLP_WHITE.pdf - ClearSky. (2016, January 7). Operation DustySky. Retrieved January 8, 2016.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.
* https://www.digitrustgroup.com/nanocore-not-your-average-rat/ - The DigiTrust Group. (2017, January 01). NanoCore Is Not Your Average RAT. Retrieved November 9, 2018.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fidelissecurity.com/sites/default/files/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2013/08/njw0rm-brother-from-the-same-mother.html - Dawda, U. and Villeneuve, N. (2013, August 30). Njw0rm - Brother From the Same Mother. Retrieved June 4, 2019.
* https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html - FireEye. (2016, November 30). FireEye Responds to Wave of Destructive Cyber Attacks in Gulf Region. Retrieved January 11, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html - Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html - O'Leary, J., et al. (2017, September 20). Insights into Iranian Cyber Espionage: APT33 Targets Aerospace and Energy Sectors and has Ties to Destructive Malware. Retrieved February 15, 2018.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.fireeye.com/blog/threat-research/2018/12/overruled-containing-a-potentially-destructive-adversary.html - Ackerman, G., et al. (2018, December 21). OVERRULED: Containing a Potentially Destructive Adversary. Retrieved January 17, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved November 12, 2014.
* https://www.forcepoint.com/sites/default/files/resources/files/forcepoint-security-labs-monsoon-analysis-report.pdf - Settle, A., et al. (2016, August 8). MONSOON - Analysis Of An APT Campaign. Retrieved September 22, 2016.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.secureworks.com/research/wcry-ransomware-analysis - Counter Threat Unit Research Team. (2017, May 18). WCry Ransomware Analysis. Retrieved March 26, 2019.
* https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia - Symantec Security Response Attack Investigation Team. (2018, April 23). New Orangeworm attack group targets the healthcare sector in the U.S., Europe, and Asia. Retrieved May 8, 2018.
* https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group - Symantec DeepSight Adversary Intelligence Team. (2018, December 10). Seedworm: Group Compromises Government Agencies, Oil & Gas, NGOs, Telecoms, and IT Firms. Retrieved December 14, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/connect/blogs/shamoon-attacks - Symantec. (2012, August 16). The Shamoon Attacks. Retrieved March 14, 2019.
* https://www.symantec.com/connect/blogs/sowbug-cyber-espionage-group-targets-south-american-and-southeast-asian-governments - Symantec Security Response. (2017, November 7). Sowbug: Cyber espionage group targets South American and Southeast Asian governments. Retrieved November 16, 2017.
* https://www.symantec.com/security-center/writeup/2014-081811-3237-99?tabid=2 - Yagi, J. (2014, August 24). Trojan.Volgmer. Retrieved July 16, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www.threatminer.org/_reports/2013/fta-1009---njrat-uncovered-1.pdf - Fidelis Cybersecurity. (2013, June 28). Fidelis Threat Advisory #1009: "njRAT" Uncovered. Retrieved June 4, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-132A - US-CERT. (2017, May 12). Alert (TA17-132A): Indicators Associated With WannaCry Ransomware. Retrieved March 25, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-318A - US-CERT. (2017, November 22). Alert (TA17-318A): HIDDEN COBRA – North Korean Remote Administration Tool: FALLCHILL. Retrieved December 7, 2017.
* https://www.us-cert.gov/ncas/alerts/TA17-318B - US-CERT. (2017, November 22). Alert (TA17-318B): HIDDEN COBRA – North Korean Trojan: Volgmer. Retrieved December 7, 2017.
* https://www.us-cert.gov/ncas/analysis-reports/AR18-165A - US-CERT. (2018, June 14). MAR-10135536-12 – North Korean Trojan: TYPEFRAME. Retrieved July 13, 2018.
* https://www.us-cert.gov/ncas/analysis-reports/AR18-221A - US-CERT. (2018, August 09). MAR-10135536-17 – North Korean Trojan: KEYMARBLE. Retrieved August 16, 2018.
* https://www.us-cert.gov/ncas/analysis-reports/AR19-100A - US-CERT. (2019, April 10). MAR-10135536-8 – North Korean Trojan: HOPLIGHT. Retrieved April 19, 2019.
* https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-D_WHITE_S508C.PDF - US-CERT. (2017, November 01). Malware Analysis Report (MAR) - 10135536-D. Retrieved July 16, 2018.
* https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-F.pdf - US-CERT. (2018, February 05). Malware Analysis Report (MAR) - 10135536-F. Retrieved June 11, 2018.
* https://www.us-cert.gov/sites/default/files/publications/MAR-10135536-G.PDF - US-CERT. (2018, February 06). Malware Analysis Report (MAR) - 10135536-G. Retrieved June 7, 2018.
* https://www.washingtonpost.com/business/economy/more-than-150-countries-affected-by-massive-cyberattack-europol-says/2017/05/14/5091465e-3899-11e7-9e48-c4f199710b69_story.html?utm_term=.7fa16b41cad4 - Dwoskin, E. and Adam, K. (2017, May 14). More than 150 countries affected by massive cyberattack, Europol says. Retrieved March 25, 2019.
* https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.

