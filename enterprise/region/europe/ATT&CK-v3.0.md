threat-crank.py 0.2.1
I: searching for regions that match .* europe.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v3.0/enterprise-attack/enterprise-attack.json
# Threat groups

* Cobalt Group
* Dust Storm
* Leviathan
* Molerats
* Orangeworm

# Validate the following attacks

* BITS Jobs - 1
* Binary Padding - 1
* Bypass User Account Control - 1
* CMSTP - 1
* Code Signing - 2
* Command-Line Interface - 1
* Credential Dumping - 1
* Data Staged - 1
* Data from Local System - 1
* Deobfuscate/Decode Files or Information - 1
* Dynamic Data Exchange - 1
* Exploitation for Client Execution - 2
* Exploitation for Privilege Escalation - 1
* File Deletion - 1
* File and Directory Discovery - 1
* Network Service Scanning - 1
* New Service - 1
* Obfuscated Files or Information - 3
* PowerShell - 2
* Process Discovery - 1
* Process Injection - 1
* Redundant Access - 1
* Registry Run Keys / Startup Folder - 2
* Regsvr32 - 2
* Remote Access Tools - 1
* Remote Desktop Protocol - 1
* Remote File Copy - 2
* Scheduled Task - 1
* Scripting - 2
* Shortcut Modification - 1
* Spearphishing Attachment - 2
* Spearphishing Link - 2
* Standard Application Layer Protocol - 2
* Standard Cryptographic Protocol - 1
* User Execution - 2
* Valid Accounts - 1
* Web Service - 1
* Windows Admin Shares - 1
* Windows Management Instrumentation - 1
* Windows Management Instrumentation Event Subscription - 1
* XSL Script Processing - 1

# Validate the following phases

* collection - 2
* command-and-control - 7
* credential-access - 1
* defense-evasion - 20
* discovery - 3
* execution - 16
* initial-access - 5
* lateral-movement - 4
* persistence - 9
* privilege-escalation - 6

# Validate the following platforms

* Linux - 37
* Windows - 82
* macOS - 38

# Validate the following defences

* Anti-virus - 9
* Application whitelisting - 5
* Binary Analysis - 1
* Data Execution Prevention - 2
* Digital Certificate Validation - 1
* Exploit Prevention - 2
* Firewall - 3
* Host forensic analysis - 5
* Host intrusion prevention systems - 5
* Log analysis - 4
* Network intrusion detection system - 3
* Process whitelisting - 9
* Signature-based detection - 5
* System access controls - 1
* Whitelisting by file name or path - 3
* Windows User Account Control - 3

# Validate the following data sources

* API monitoring - 4
* Anti-virus - 4
* Application Logs - 1
* Authentication logs - 6
* Binary file metadata - 8
* DLL monitoring - 3
* DNS records - 2
* Detonation chamber - 4
* Email gateway - 7
* Environment variable - 3
* File monitoring - 23
* Host network interface - 1
* Loaded DLLs - 2
* Mail server - 4
* Malware reverse engineering - 7
* Named Pipes - 1
* Netflow/Enclave netflow - 9
* Network intrusion detection system - 6
* Network protocol analysis - 9
* Packet capture - 13
* PowerShell logs - 1
* Process Monitoring - 11
* Process command-line parameters - 28
* Process monitoring - 29
* Process use of network - 14
* SSL/TLS inspection - 7
* System calls - 3
* WMI Objects - 1
* Web proxy - 2
* Windows Error Reporting - 1
* Windows Registry - 9
* Windows event logs - 8

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/jepayne/archive/2015/11/24/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem.aspx - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* http://blogs.technet.com/b/jepayne/archive/2015/11/27/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts.aspx - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://hick.org/code/skape/papers/needle.txt - skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://phrack.org/issues/51/8.html - halflife. (1997, September 1). Shared Library Redirection Techniques. Retrieved December 20, 2017.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://vxer.org/lib/vrn00.html - O'Neill, R. (2009, May). Modern Day ELF Runtime infection via GOT poisoning. Retrieved December 20, 2017.
* http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html - stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.
* http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/ - Seetharaman, N. (2018, July 7). Detecting CMSTP-Enabled Code Execution and UAC Bypass With Sysmon.. Retrieved August 6, 2018.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html - Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.metasploit.com - Metasploit. (n.d.). Retrieved December 4, 2014.
* http://www.pretentiousname.com/misc/win7_uac_whitelist2.html - Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://access.redhat.com/documentation/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.crysys.hu/2013/03/teamspy/ - CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.
* https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows - Liberman, T. (2016, October 27). ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWS. Retrieved December 8, 2017.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://docs.microsoft.com/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script - Wenzel, M. et al. (2017, March 30). XSLT Stylesheet Scripting Using <msxsl:script>. Retrieved July 3, 2018.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-vista/cc749211(v=ws.10) - Microsoft. (2008, July 25). Credential Security Service Provider and SSO for Terminal Services Logon. Retrieved April 11, 2018.
* https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc786431(v=ws.10) - Microsoft. (2009, October 8). How Connection Manager Works. Retrieved April 11, 2018.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697 - Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection - Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.
* https://en.wikipedia.org/wiki/Active_Directory - Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Command-line_interface - Wikipedia. (2016, June 26). Command-line interface. Retrieved June 27, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/api0cradle/UltimateAppLockerByPassList - Moe, O. (2018, March 1). Ultimate AppLocker Bypass List. Retrieved April 10, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf - CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc422924.aspx - Microsoft. (n.d.). 2.2.1.1.4 Password Encryption. Retrieved April 11, 2018.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms649053.aspx - Microsoft. (n.d.). About Atom Tables. Retrieved December 8, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms681951.aspx - Microsoft. (n.d.). Asynchronous Procedure Calls. Retrieved December 8, 2017.
* https://msitpros.com/?p=3960 - Moe, O. (2017, August 15). Research on CMSTP.exe. Retrieved April 11, 2018.
* https://obscuresecurity.blogspot.co.uk/2012/05/gpp-password-retrieval-with-powershell.html - Campbell, C. (2012, May 24). GPP Password Retrieval with PowerShell. Retrieved April 11, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://pentestlab.blog/2017/07/06/applocker-bypass-msxsl/ - netbiosX. (2017, July 6). AppLocker Bypass – MSXSL. Retrieved July 3, 2018.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://reaqta.com/2018/03/spear-phishing-campaign-leveraging-msxsl/ - Admin. (2018, March 2). Spear-phishing campaign leveraging on MSXSL. Retrieved July 3, 2018.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-hacking.html - Smith, C. (2018, April 17). WMIC.EXE Whitelisting Bypass - Hacking with Style, Stylesheets. Retrieved July 3, 2018.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
* https://technet.microsoft.com/bb490717.aspx - Microsoft. (n.d.). Net Use. Retrieved November 25, 2016.
* https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx - Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.
* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works - Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.
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
* https://twitter.com/ItsReallyNick/status/958789644165894146 - Carr, N. (2018, January 31). Here is some early bad cmstp.exe... Retrieved April 11, 2018.
* https://twitter.com/NickTyrer/status/958450014111633408 - Tyrer, N. (2018, January 30). CMSTP.exe - remote .sct execution applocker bypass. Retrieved April 11, 2018.
* https://twitter.com/dez_/status/986614411711442944 - Desimone, J. (2018, April 18). Status Update. Retrieved July 3, 2018.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/ - Gavriel, H. & Erbesfeld, B. (2018, April 11). New ‘Early Bird’ Code Injection Technique Discovered. Retrieved May 24, 2018.
* https://www.datawire.io/code-injection-on-linux-and-macos/ - Turner-Trauring, I. (2017, April 18). “This will only hurt for a moment”: code injection on Linux and macOS with LD_PRELOAD. Retrieved December 20, 2017.
* https://www.defcon.org/images/defcon-22/dc-22-presentations/Kazanciyan-Hastings/DEFCON-22-Ryan-Kazanciyan-Matt-Hastings-Investigating-Powershell-Attacks.pdf - Kazanciyan, R. & Hastings, M. (2014). Defcon 22 Presentation. Investigating PowerShell Attacks &#91;slides&#93;. Retrieved November 3, 2014.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.fidelissecurity.com/sites/default/files/FTA_1018_looking_at_the_sky_for_a_dark_comet.pdf - Fidelis Cybersecurity. (2015, August 4). Looking at the Sky for a DarkComet. Retrieved April 5, 2016.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/blog/threat-research/2017/11/ursnif-variant-malicious-tls-callback-technique.html - Vaish, A. & Nemes, S. (2017, November 28). Newly Observed Ursnif Variant Employs Malicious TLS Callback Technique to Achieve Process Injection. Retrieved December 18, 2017.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.gnu.org/software/acct/ - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.
* https://www.microsoft.com/download/details.aspx?id=21714 - Microsoft. (n.d.). Command Line Transformation Utility (msxsl.exe). Retrieved July 3, 2018.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf - Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.
* https://www.uperesia.com/analyzing-malicious-office-documents - Felix. (2016, September). Analyzing Malicious Office Documents. Retrieved April 11, 2018.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.). Retrieved December 4, 2014.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.

# Validate the following tools

* Arp - 1
* BITSAdmin - 1
* Cobalt Strike - 2
* Mimikatz - 1
* Net - 1
* PsExec - 1
* SDelete - 1
* Systeminfo - 1
* cmd - 1
* ipconfig - 1
* netstat - 1
* route - 1

# Review the following tool references

* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive - Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://technet.microsoft.com/en-us/library/bb490864.aspx - Microsoft. (n.d.). Arp. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490880.aspx - Microsoft. (n.d.). Cmd. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/bb490886.aspx - Microsoft. (n.d.). Copy. Retrieved April 26, 2016.
* https://technet.microsoft.com/en-us/library/bb490921.aspx - Microsoft. (n.d.). Ipconfig. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490947.aspx - Microsoft. (n.d.). Netstat. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb490991.aspx - Microsoft. (n.d.). Route. Retrieved April 17, 2016.
* https://technet.microsoft.com/en-us/library/bb491007.aspx - Microsoft. (n.d.). Systeminfo. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/cc755121.aspx - Microsoft. (n.d.). Dir. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/cc771049.aspx - Microsoft. (n.d.). Del. Retrieved April 22, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.

# Validate the following malware

* BLACKCOFFEE - 1
* China Chopper - 1
* Derusbi - 1
* DustySky - 1
* HOMEFRY - 1
* Kwampirs - 1
* MURKYTOP - 1
* Mis-Type - 1
* Misdat - 1
* More_eggs - 1
* NanHaiShu - 1
* Orz - 1
* PoisonIvy - 1
* S-Type - 1
* ZLib - 1

# Review the following malware references

* http://www.clearskysec.com/wp-content/uploads/2016/06/Operation-DustySky2_-6.2016_TLP_White.pdf - ClearSky Cybersecurity. (2016, June 9). Operation DustySky - Part 2. Retrieved August 3, 2016.
* http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://blog.talosintelligence.com/2018/07/multiple-cobalt-personality-disorder.html - Svajcer, V. (2018, July 31). Multiple Cobalt Personality Disorder. Retrieved September 5, 2018.
* https://www.clearskysec.com/wp-content/uploads/2016/01/Operation%20DustySky_TLP_WHITE.pdf - ClearSky. (2016, January 7). Operation DustySky. Retrieved January 8, 2016.
* https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fidelissecurity.com/sites/default/files/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved November 12, 2014.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/blogs/threat-intelligence/orangeworm-targets-healthcare-us-europe-asia - Symantec Security Response Attack Investigation Team. (2018, April 23). New Orangeworm attack group targets the healthcare sector in the U.S., Europe, and Asia. Retrieved May 8, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.

