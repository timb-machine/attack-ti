threat-crank.py 0.2.1
I: searching for industries that match .* factory.*|.* manufactur.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v2.0/enterprise-attack/enterprise-attack.json
# Threat groups

* APT18
* BRONZE BUTLER
* Elderwood
* Leviathan
* Threat Group-3390
* menuPass

# Validate the following attacks

* Account Discovery - 3
* Automated Collection - 1
* BITS Jobs - 1
* Binary Padding - 2
* Bypass User Account Control - 1
* Code Signing - 1
* Command-Line Interface - 4
* Commonly Used Port - 1
* Connection Proxy - 1
* Credential Dumping - 3
* Custom Cryptographic Protocol - 1
* DLL Search Order Hijacking - 1
* DLL Side-Loading - 2
* Data Compressed - 3
* Data Encoding - 1
* Data Encrypted - 2
* Data Staged - 3
* Data Transfer Size Limits - 1
* Data from Local System - 2
* Data from Network Shared Drive - 2
* Deobfuscate/Decode Files or Information - 2
* Disabling Security Tools - 1
* Drive-by Compromise - 1
* Exploitation for Client Execution - 2
* Exploitation for Privilege Escalation - 1
* External Remote Services - 2
* File Deletion - 3
* File and Directory Discovery - 1
* Input Capture - 1
* Masquerading - 1
* Network Service Scanning - 2
* Network Share Connection Removal - 1
* Obfuscated Files or Information - 2
* Pass the Ticket - 1
* PowerShell - 4
* Redundant Access - 1
* Registry Run Keys / Start Folder - 2
* Regsvr32 - 1
* Remote Desktop Protocol - 1
* Remote File Copy - 5
* Remote Services - 1
* Remote System Discovery - 2
* Scheduled Task - 4
* Screen Capture - 1
* Scripting - 2
* Shortcut Modification - 1
* Software Packing - 1
* Spearphishing Attachment - 3
* Spearphishing Link - 2
* Standard Application Layer Protocol - 1
* Standard Cryptographic Protocol - 1
* Supply Chain Compromise - 1
* System Network Configuration Discovery - 2
* System Network Connections Discovery - 2
* System Time Discovery - 1
* Trusted Relationship - 1
* User Execution - 3
* Valid Accounts - 4
* Web Service - 2
* Windows Management Instrumentation - 2
* Windows Management Instrumentation Event Subscription - 1
* Windows Remote Management - 1

# Validate the following phases

* collection - 10
* command-and-control - 13
* credential-access - 4
* defense-evasion - 29
* discovery - 13
* execution - 23
* exfiltration - 6
* initial-access - 12
* lateral-movement - 9
* persistence - 17
* privilege-escalation - 11

# Validate the following platforms

* Linux - 76
* Windows - 110
* macOS - 77

# Validate the following defences

* Anti-virus - 14
* Application whitelisting - 2
* Binary Analysis - 2
* Data Execution Prevention - 2
* Exploit Prevention - 2
* File monitoring - 1
* Firewall - 7
* Heuristic detection - 1
* Host forensic analysis - 7
* Host intrusion prevention systems - 9
* Log analysis - 5
* Network intrusion detection system - 7
* Process whitelisting - 12
* Signature-based detection - 8
* System access controls - 4
* Whitelisting by file name or path - 3
* Windows User Account Control - 2

# Validate the following data sources

* API monitoring - 11
* Anti-virus - 6
* Application Logs - 2
* Authentication logs - 16
* Binary file metadata - 14
* DLL monitoring - 1
* DNS records - 2
* Data loss prevention - 1
* Detonation chamber - 5
* Email gateway - 7
* Environment variable - 2
* File monitoring - 49
* Host network interface - 2
* Kernel drivers - 1
* Loaded DLLs - 3
* Mail server - 5
* Malware reverse engineering - 5
* Netflow/Enclave netflow - 19
* Network device logs - 1
* Network intrusion detection system - 6
* Network protocol analysis - 15
* Packet capture - 25
* PowerShell logs - 3
* Process Monitoring - 7
* Process command-line parameters - 62
* Process monitoring - 74
* Process use of network - 22
* SSL/TLS inspection - 8
* Services - 1
* System calls - 3
* Third-party application logs - 1
* WMI Objects - 1
* Web proxy - 4
* Windows Error Reporting - 1
* Windows Registry - 9
* Windows event logs - 7

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.gentilkiwi.com/securite/mimikatz/pass-the-ticket-kerberos - Deply, B. (2014, January 13). Pass the ticket. Retrieved June 2, 2016.
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/ - Wrightson, T. (2012, January 2). CAPTURING WINDOWS 7 CREDENTIALS AT LOGON USING CUSTOM CREDENTIAL PROVIDER. Retrieved November 12, 2014.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/msrc/archive/2010/08/21/microsoft-security-advisory-2269637-released.aspx - Microsoft. (2010, August 22). Microsoft Security Advisory 2269637 Released. Retrieved December 5, 2014.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://defcon.org/images/defcon-22/dc-22-presentations/Campbell/DEFCON-22-Christopher-Campbell-The-Secret-Life-of-Krbtgt.pdf - Campbell, C. (2014). The Secret Life of Krbtgt. Retrieved December 4, 2014.
* http://en.wikipedia.org/wiki/Executable%20compression - Executable compression. (n.d.).  Retrieved December 4, 2014.
* http://msdn.microsoft.com/en-US/library/ms682586 - Microsoft. (n.d.). Dynamic-Link Library Search Order. Retrieved November 30, 2014.
* http://msdn.microsoft.com/en-US/library/ms682600 - Microsoft. (n.d.). Dynamic-Link Library Redirection. Retrieved December 5, 2014.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://msdn.microsoft.com/en-us/library/aa384426 - Microsoft. (n.d.). Windows Remote Management. Retrieved November 12, 2014.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html - Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.metasploit.com - Metasploit. (n.d.).  Retrieved December 4, 2014.
* http://www.netsec.colostate.edu/~zhang/DetectingEncryptedBotnetTraffic.pdf - Zhang, H., Papadopoulos, C., & Massey, D. (2013, April). Detecting encrypted botnet traffic. Retrieved August 19, 2015.
* http://www.pretentiousname.com/misc/win7%20uac%20whitelist2.html - Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.symantec.com/content/en/us/enterprise/media/security%20response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://adsecurity.org/?p=556 - Metcalf, S. (2014, November 22). Mimikatz and Active Directory Kerberos Attacks. Retrieved June 2, 2016.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities - Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://cloudblogs.microsoft.com/microsoftsecure/2018/03/07/behavior-monitoring-combined-with-machine-learning-spoils-a-massive-dofoil-coin-mining-campaign/ - Windows Defender Research. (2018, March 7). Behavior monitoring combined with machine learning spoils a massive Dofoil coin mining campaign. Retrieved March 20, 2018.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749211(v=ws.10) - Microsoft. (2008, July 25). Credential Security Service Provider and SSO for Terminal Services Logon. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Active%20Directory - Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Binary-to-text%20encoding - Wikipedia. (2016, December 26). Binary-to-text encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Character%20encoding - Wikipedia. (2017, February 19). Character Encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Code%20signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Command-line%20interface - Wikipedia. (2016, June 26). Command-line interface. Retrieved June 27, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/List%20of%20file%20signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Server%20Message%20Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.).  Retrieved December 4, 2014.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-US/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved December 5, 2014.
* https://msdn.microsoft.com/en-us/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved June 3, 2016.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc422924.aspx - Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/ms724961.aspx - Microsoft. (n.d.). System Time. Retrieved November 25, 2016.
* https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html - Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.
* https://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/ - Bryan Lee and Rob Downs. (2016, February 12). A Look Into Fysbis: Sofacy’s Linux Backdoor. Retrieved September 10, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://technet.microsoft.com/bb490717.aspx - Microsoft. (n.d.). Net Use. Retrieved November 25, 2016.
* https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx - Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.
* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works - Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/cc785125.aspx - Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://technet.microsoft.com/windows-server-docs/identity/ad-ds/get-started/windows-time-service/windows-time-service-tools-and-settings - Mathers, B. (2016, September 30). Windows Time Service Tools and Settings. Retrieved November 25, 2016.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.commandfive.com/papers/C5%20APT%20SKHack.pdf - Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.
* https://www.defcon.org/images/defcon-22/dc-22-presentations/Kazanciyan-Hastings/DEFCON-22-Ryan-Kazanciyan-Matt-Hastings-Investigating-Powershell-Attacks.pdf - Kazanciyan, R. & Hastings, M. (2014). Defcon 22 Presentation. Investigating PowerShell Attacks &#91;slides&#93;. Retrieved November 3, 2014.
* https://www.endgame.com/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.f-secure.com/documents/996508/1030745/CozyDuke - F-Secure Labs. (2015, April 22). CozyDuke: Malware Analysis. Retrieved December 10, 2015.
* https://www.f-secure.com/documents/996508/1030745/cosmicduke%20whitepaper.pdf - F-Secure Labs. (2014, July). COSMICDUKE Cosmu with a twist of MiniDuke. Retrieved July 3, 2014.
* https://www.fidelissecurity.com/sites/default/files/FTA%201018%20looking%20at%20the%20sky%20for%20a%20dark%20comet.pdf - Fidelis Cybersecurity. (2015, August 4). Looking at the Sky for a DarkComet. Retrieved April 5, 2016.
* https://www.fireeye.com/blog/threat-research/2016/02/greater%20visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear%20phishing%20techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Stewart, A. (2014). DLL SIDE-LOADING: A Thorn in the Side of the Anti-Virus Industry. Retrieved November 12, 2014.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.mandiant.com/blog/dll-search-order-hijacking-revisited/ - Mandiant. (2010, August 31). DLL Search Order Hijacking Revisited. Retrieved December 5, 2014.
* https://www.owasp.org/index.php/Binary%20planting - OWASP. (2013, January 30). Binary planting. Retrieved June 7, 2016.
* https://www.rsaconference.com/writable/presentations/file%20upload/ht-209%20rivner%20schwartz.pdf - Rivner, U., Schwartz, E. (2012). They’re Inside… Now What?. Retrieved November 25, 2016.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2 - Jacobsen, K. (2014, May 16). Lateral Movement with PowerShell&#91;slides&#93;. Retrieved November 12, 2014.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.uperesia.com/analyzing-malicious-office-documents - Felix. (2016, September). Analyzing Malicious Office Documents. Retrieved April 11, 2018.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.).  Retrieved December 4, 2014.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2016/03/30/meet-remaiten-a-linux-bot-on-steroids-targeting-routers-and-potentially-other-iot-devices/ - Michal Malik AND Marc-Etienne M.Léveillé. (2016, March 30). Meet Remaiten – a Linux bot on steroids targeting routers and potentially other IoT devices. Retrieved September 7, 2017.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools


# Review the following tool references


# Validate the following malware


# Review the following malware references


