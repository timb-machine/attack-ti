threat-crank.py 0.2.1
I: searching for industries that match .* teach.*|.* academi.*|.* school.*|.* universit.*|.* college.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v3.0/enterprise-attack/enterprise-attack.json
# Threat groups

* Charming Kitten
* Leviathan
* menuPass

# Validate the following attacks

* Account Discovery - 1
* BITS Jobs - 1
* Binary Padding - 1
* Code Signing - 1
* Command-Line Interface - 2
* Connection Proxy - 1
* Credential Dumping - 1
* DLL Search Order Hijacking - 1
* DLL Side-Loading - 1
* Data Compressed - 1
* Data Staged - 2
* Data from Network Shared Drive - 1
* Deobfuscate/Decode Files or Information - 2
* Exploitation for Client Execution - 1
* File Deletion - 1
* Network Service Scanning - 1
* Obfuscated Files or Information - 2
* PowerShell - 2
* Process Hollowing - 1
* Registry Run Keys / Startup Folder - 1
* Regsvr32 - 1
* Remote Desktop Protocol - 1
* Remote File Copy - 2
* Remote Services - 1
* Remote System Discovery - 1
* Scheduled Task - 1
* Scripting - 2
* Shortcut Modification - 1
* Spearphishing Attachment - 2
* Spearphishing Link - 1
* System Network Configuration Discovery - 1
* System Network Connections Discovery - 1
* Trusted Relationship - 1
* User Execution - 2
* Valid Accounts - 2
* Web Service - 1
* Windows Management Instrumentation - 2
* Windows Management Instrumentation Event Subscription - 1

# Validate the following phases

* collection - 3
* command-and-control - 4
* credential-access - 1
* defense-evasion - 17
* discovery - 5
* execution - 13
* exfiltration - 1
* initial-access - 6
* lateral-movement - 4
* persistence - 8
* privilege-escalation - 4

# Validate the following platforms

* Linux - 34
* Windows - 73
* macOS - 33

# Validate the following defences

* Anti-virus - 8
* Application whitelisting - 2
* Binary Analysis - 1
* Data Execution Prevention - 2
* Exploit Prevention - 2
* Firewall - 4
* Host forensic analysis - 4
* Host intrusion prevention systems - 6
* Log analysis - 3
* Network intrusion detection system - 4
* Process whitelisting - 10
* Signature-based detection - 6
* System access controls - 2
* Whitelisting by file name or path - 3
* Windows User Account Control - 1

# Validate the following data sources

* API monitoring - 4
* Anti-virus - 3
* Application Logs - 1
* Authentication logs - 7
* Binary file metadata - 6
* DLL monitoring - 1
* DNS records - 1
* Detonation chamber - 3
* Email gateway - 5
* Environment variable - 2
* File monitoring - 22
* Host network interface - 1
* Loaded DLLs - 2
* Mail server - 3
* Malware reverse engineering - 3
* Netflow/Enclave netflow - 8
* Network intrusion detection system - 4
* Network protocol analysis - 7
* Packet capture - 9
* PowerShell logs - 1
* Process Monitoring - 5
* Process command-line parameters - 29
* Process monitoring - 31
* Process use of network - 8
* SSL/TLS inspection - 4
* System calls - 1
* Third-party application logs - 1
* WMI Objects - 1
* Web proxy - 1
* Windows Registry - 4
* Windows event logs - 4

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/msrc/archive/2010/08/21/microsoft-security-advisory-2269637-released.aspx - Microsoft. (2010, August 22). Microsoft Security Advisory 2269637 Released. Retrieved December 5, 2014.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://msdn.microsoft.com/en-US/library/ms682586 - Microsoft. (n.d.). Dynamic-Link Library Search Order. Retrieved November 30, 2014.
* http://msdn.microsoft.com/en-US/library/ms682600 - Microsoft. (n.d.). Dynamic-Link Library Redirection. Retrieved December 5, 2014.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://www.autosectools.com/process-hollowing.pdf - Leitch, J. (n.d.). Process Hollowing. Retrieved November 12, 2014.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html - Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.metasploit.com - Metasploit. (n.d.). Retrieved December 4, 2014.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749211(v=ws.10) - Microsoft. (2008, July 25). Credential Security Service Provider and SSO for Terminal Services Logon. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Active_Directory - Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Command-line_interface - Wikipedia. (2016, June 26). Command-line interface. Retrieved June 27, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-US/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved December 5, 2014.
* https://msdn.microsoft.com/en-us/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved June 3, 2016.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc422924.aspx - Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html - Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
* https://technet.microsoft.com/en-us/library/cc785125.aspx - Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.defcon.org/images/defcon-22/dc-22-presentations/Kazanciyan-Hastings/DEFCON-22-Ryan-Kazanciyan-Matt-Hastings-Investigating-Powershell-Attacks.pdf - Kazanciyan, R. & Hastings, M. (2014). Defcon 22 Presentation. Investigating PowerShell Attacks &#91;slides&#93;. Retrieved November 3, 2014.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Stewart, A. (2014). DLL SIDE-LOADING: A Thorn in the Side of the Anti-Virus Industry. Retrieved November 12, 2014.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.mandiant.com/blog/dll-search-order-hijacking-revisited/ - Mandiant. (2010, August 31). DLL Search Order Hijacking Revisited. Retrieved December 5, 2014.
* https://www.owasp.org/index.php/Binary_planting - OWASP. (2013, January 30). Binary planting. Retrieved June 7, 2016.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.uperesia.com/analyzing-malicious-office-documents - Felix. (2016, September). Analyzing Malicious Office Documents. Retrieved April 11, 2018.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.). Retrieved December 4, 2014.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* BITSAdmin - 1
* Cobalt Strike - 1
* Mimikatz - 1
* Net - 1
* Ping - 1
* PowerSploit - 1
* PsExec - 1
* certutil - 1
* cmd - 1
* pwdump - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive - Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (1985, June 22). pwdump. Retrieved June 22, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://technet.microsoft.com/en-us/library/bb490880.aspx - Microsoft. (n.d.). Cmd. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/bb490886.aspx - Microsoft. (n.d.). Copy. Retrieved April 26, 2016.
* https://technet.microsoft.com/en-us/library/bb490968.aspx - Microsoft. (n.d.). Ping. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/cc755121.aspx - Microsoft. (n.d.). Dir. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/cc771049.aspx - Microsoft. (n.d.). Del. Retrieved April 22, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/cc732443.aspx - Microsoft. (2012, November 14). Certutil. Retrieved July 3, 2017.

# Validate the following malware

* BLACKCOFFEE - 1
* ChChes - 1
* China Chopper - 1
* Derusbi - 1
* DownPaper - 1
* EvilGrab - 1
* HOMEFRY - 1
* MURKYTOP - 1
* NanHaiShu - 1
* Orz - 1
* PlugX - 1
* PoisonIvy - 1
* RedLeaves - 1
* SNUGRIDE - 1
* UPPERCUT - 1

# Review the following malware references

* http://blog.jpcert.or.jp/2017/02/chches-malware--93d6.html - Nakamura, Y.. (2017, February 17). ChChes - Malware that Communicates with C&C Servers Using Cookie Headers. Retrieved March 1, 2017.
* http://labs.lastline.com/an-analysis-of-plugx - Vasilenko, R. (2013, December 17). An Analysis of PlugX Malware. Retrieved November 24, 2015.
* http://researchcenter.paloaltonetworks.com/2015/04/unit-42-identifies-new-dragonok-backdoor-malware-deployed-against-japanese-targets/ - Miller-Osborn, J., Grunzweig, J.. (2015, April). Unit 42 Identifies New DragonOK Backdoor Malware Deployed Against Japanese Targets. Retrieved November 4, 2015.
* http://researchcenter.paloaltonetworks.com/2017/02/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/ - Miller-Osborn, J. and Grunzweig, J.. (2017, February 16). menuPass Returns with New Malware and New Attacks Against Japanese Academics and Organizations. Retrieved March 1, 2017.
* http://www.clearskysec.com/wp-content/uploads/2017/12/Charming_Kitten_2017.pdf - ClearSky Cyber Security. (2017, December). Charming Kitten. Retrieved December 27, 2017.
* http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://twitter.com/ItsReallyNick/status/850105140589633536 - Carr, N.. (2017, April 6). Retrieved June 29, 2017.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fidelissecurity.com/sites/default/files/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2014/06/clandestine-fox-part-deux.html - Scott, M.. (2014, June 10). Clandestine Fox, Part Deux. Retrieved January 14, 2016.
* https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html - FireEye iSIGHT Intelligence. (2017, April 6). APT10 (MenuPass Group): New Tools, Global Campaign Latest Manifestation of Longstanding Threat. Retrieved June 29, 2017.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html - Matsuda, A., Muhammad I. (2018, September 13). APT10 Targeting Japanese Corporations Using Updated TTPs. Retrieved September 17, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved November 12, 2014.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf - PwC and BAE Systems. (2017, April). Operation Cloud Hopper: Technical Annex. Retrieved April 13, 2017.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.

