threat-crank.py 0.2.1
I: searching for industries that match .* servic.*|.* ISP.*|.* MSP.*|.* provid.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v7.2/enterprise-attack/enterprise-attack.json
# Threat groups

* APT19
* Elderwood
* GCMAN
* MuddyWater
* menuPass

# Validate the following attacks

* Archive Collected Data - 1
* Archive via Utility - 2
* Bypass User Access Control - 1
* CMSTP - 1
* Cached Domain Credentials - 1
* Command and Scripting Interpreter - 1
* Commonly Used Port - 1
* Compile After Delivery - 1
* Component Object Model - 1
* Credentials In Files - 1
* Credentials from Password Stores - 1
* Credentials from Web Browsers - 1
* DLL Search Order Hijacking - 1
* DLL Side-Loading - 2
* Data from Local System - 1
* Data from Network Shared Drive - 1
* Deobfuscate/Decode Files or Information - 3
* Domain Account - 1
* Drive-by Compromise - 2
* Dynamic Data Exchange - 1
* Exfiltration Over C2 Channel - 1
* Exploitation for Client Execution - 2
* External Proxy - 2
* File Deletion - 1
* File and Directory Discovery - 1
* Hidden Window - 1
* Ingress Tool Transfer - 3
* Keylogging - 1
* LSA Secrets - 2
* LSASS Memory - 1
* Local Data Staging - 1
* Malicious File - 4
* Malicious Link - 1
* Masquerading - 1
* Match Legitimate Name or Location - 2
* Modify Registry - 1
* Mshta - 1
* Multi-Stage Channels - 1
* Network Service Scanning - 1
* Obfuscated Files or Information - 4
* Office Template Macros - 1
* PowerShell - 3
* Process Discovery - 1
* Process Hollowing - 1
* Registry Run Keys / Startup Folder - 2
* Regsvr32 - 1
* Remote Data Staging - 1
* Remote Desktop Protocol - 1
* Remote System Discovery - 1
* Rename System Utilities - 1
* Rundll32 - 2
* SSH - 2
* Scheduled Task - 2
* Screen Capture - 1
* Security Account Manager - 1
* Security Software Discovery - 1
* Software Packing - 1
* Spearphishing Attachment - 4
* Spearphishing Link - 1
* Standard Encoding - 2
* Steganography - 1
* Supply Chain Compromise - 1
* System Information Discovery - 2
* System Network Configuration Discovery - 3
* System Network Connections Discovery - 1
* System Owner/User Discovery - 2
* Trusted Relationship - 1
* VNC - 1
* Valid Accounts - 1
* Visual Basic - 1
* Web Protocols - 2
* Windows Command Shell - 2
* Windows Management Instrumentation - 2
* Windows Service - 1

# Validate the following phases

* collection - 9
* command-and-control - 11
* credential-access - 9
* defense-evasion - 28
* discovery - 14
* execution - 20
* exfiltration - 1
* initial-access - 10
* lateral-movement - 4
* persistence - 10
* privilege-escalation - 11

# Validate the following platforms

* AWS - 10
* Azure - 10
* Azure AD - 2
* GCP - 10
* Linux - 79
* Office 365 - 4
* SaaS - 6
* Windows - 142
* macOS - 81

# Validate the following defences

* Anti-virus - 13
* Application control - 13
* Application control by file name or path - 7
* Binary Analysis - 1
* Digital Certificate Validation - 4
* Firewall - 1
* Heuristic detection - 1
* Host forensic analysis - 6
* Host intrusion prevention systems - 9
* Log analysis - 4
* Network intrusion detection system - 4
* Signature-based detection - 9
* Static File Analysis - 1
* System access controls - 1
* Windows User Account Control - 1

# Validate the following data sources

* API monitoring - 8
* AWS CloudTrail logs - 6
* Anti-virus - 7
* Application logs - 1
* Authentication logs - 7
* Azure activity logs - 5
* Binary file metadata - 14
* DLL monitoring - 9
* DNS records - 1
* Detonation chamber - 5
* Email gateway - 9
* Environment variable - 4
* File monitoring - 51
* Loaded DLLs - 9
* Mail server - 5
* Malware reverse engineering - 4
* Netflow/Enclave netflow - 17
* Network device logs - 3
* Network intrusion detection system - 10
* Network protocol analysis - 19
* Packet capture - 20
* PowerShell logs - 12
* Process command-line parameters - 69
* Process monitoring - 88
* Process use of network - 26
* SSL/TLS inspection - 7
* Stackdriver logs - 6
* System calls - 3
* Third-party application logs - 1
* Web proxy - 5
* Windows Registry - 8
* Windows event logs - 15

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.jpcert.or.jp/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html - CG. (2014, May 20). Mimikatz Against Virtual Machine Memory Part 1. Retrieved November 12, 2014.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://en.wikipedia.org/wiki/Executable_compression - Executable compression. (n.d.). Retrieved December 4, 2014.
* http://msdn.microsoft.com/en-us/library/aa376977 - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved November 12, 2014.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://pages.endgame.com/rs/627-YBU-612/images/EndgameJournal_The%20Masquerade%20Ball_Pages_R2.pdf - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://www.autosectools.com/process-hollowing.pdf - Leitch, J. (n.d.). Process Hollowing. Retrieved November 12, 2014.
* http://www.endurant.io/cmstp/detecting-cmstp-enabled-code-execution-and-uac-bypass-with-sysmon/ - Seetharaman, N. (2018, July 7). Detecting CMSTP-Enabled Code Execution and UAC Bypass With Sysmon.. Retrieved August 6, 2018.
* http://www.hexacorn.com/blog/2017/04/19/beyond-good-ol-run-key-part-62/ - Hexacorn. (2017, April 17). Beyond good ol’ Run key, Part 62. Retrieved July 3, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.pretentiousname.com/misc/win7_uac_whitelist2.html - Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.
* http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://airbus-cyber-security.com/fileless-malware-behavioural-analysis-kovter-persistence/ - Dove, A. (2016, March 23). Fileless Malware – A Behavioural Analysis Of Kovter Persistence. Retrieved December 5, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/describe-instances.html - Amazon. (n.d.). describe-instances. Retrieved May 26, 2020.
* https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities - Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/windows-app-runs-on-mac-downloads-info-stealer-and-adware/ - Trend Micro. (2019, February 11). Windows App Runs on Mac, Downloads Info Stealer and Adware. Retrieved April 25, 2019.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/sdk/gcloud/reference/compute/instances/list - Google. (n.d.). gcloud compute instances list. Retrieved May 26, 2020.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://cloudblogs.microsoft.com/microsoftsecure/2018/03/07/behavior-monitoring-combined-with-machine-learning-spoils-a-massive-dofoil-coin-mining-campaign/ - Windows Defender Research. (2018, March 7). Behavior monitoring combined with machine learning spoils a massive Dofoil coin mining campaign. Retrieved March 20, 2018.
* https://content.fireeye.com/m-trends/rpt-m-trends-2020 - FireEye / Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html - Amazon. (n.d.). DescribeInstances. Retrieved May 26, 2020.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/cli/azure/vm?view=azure-cli-latest - Microsoft. (n.d.). az vm. Retrieved May 26, 2020.
* https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8 - Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.
* https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1 - Wheeler, S. et al.. (2019, May 1). About PowerShell.exe. Retrieved October 11, 2019.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/hh994565(v%3Dws.11) - Microsfot. (2016, August 21). Cached and Stored Credentials Technical Overview. Retrieved February 21, 2020.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637 - Microsoft. (, May 23). Microsoft Security Advisory 2269637. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/windows-server/identity/securing-privileged-access/securing-privileged-access-reference-material?redirectedfrom=MSDN - Microsoft. (2019, February 14). Active Directory administrative tier model. Retrieved February 21, 2020.
* https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata - Microsoft. (2018, April 12). CryptUnprotectData function. Retrieved June 18, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection?redirectedfrom=MSDN - Microsoft. (2018, May 31). Dynamic-Link Library Redirection. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN - Microsoft. (2018, May 31). Dynamic-Link Library Search Order. Retrieved November 30, 2014.
* https://docs.microsoft.com/en-us/windows/win32/sbscs/about-side-by-side-assemblies- - Microsoft. (2018, May 31). About Side-by-Side Assemblies. Retrieved March 13, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/previous-versions/windows/it-pro/windows-server-2003/cc786431(v=ws.10) - Microsoft. (2009, October 8). How Connection Manager Works. Retrieved April 11, 2018.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697 - Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection - Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.
* https://en.wikipedia.org/wiki/Binary-to-text_encoding - Wikipedia. (2016, December 26). Binary-to-text encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Character_encoding - Wikipedia. (2017, February 19). Character Encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/HTML_Application - Wikipedia. (2017, October 14). HTML Application. Retrieved October 27, 2017.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://enigma0x3.net/2014/01/23/maintaining-access-with-normal-dotm/comment-page-1/ - Nelson, M. (2014, January 23). Maintaining Access with normal.dotm. Retrieved July 3, 2017.
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/ - Nelson, M. (2017, January 5). Lateral Movement using the MMC20 Application COM Object. Retrieved November 21, 2017.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/11/16/lateral-movement-using-outlooks-createobject-method-and-dotnettojscript/ - Nelson, M. (2017, November 16). Lateral Movement using Outlook's CreateObject Method and DotNetToJScript. Retrieved November 21, 2017.
* https://expel.io/blog/finding-evil-in-aws/ - Anthony Randazzo, Britton Manahan and Sam Lipton. (2020, April 28). Finding Evil in AWS. Retrieved June 25, 2020.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/api0cradle/UltimateAppLockerByPassList - Moe, O. (2018, March 1). Ultimate AppLocker Bypass List. Retrieved April 10, 2018.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/putterpanda/mimikittenz - Jamieson O'Reilly (putterpanda). (2016, July 4). mimikittenz. Retrieved June 20, 2019.
* https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html - Forshaw, J. (2018, April 18). Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege. Retrieved May 3, 2018.
* https://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-and-cracking-mscash-cached-domain-credentials - Mantvydas Baranauskas. (2019, November 16). Dumping and Cracking mscash - Cached Domain Credentials. Retrieved February 21, 2020.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://lolbas-project.github.io/lolbas/Binaries/Mshta/ - LOLBAS. (n.d.). Mshta.exe. Retrieved July 31, 2019.
* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/ - LOLBAS. (n.d.). Regsvr32.exe. Retrieved July 31, 2019.
* https://malware.news/t/using-outlook-forms-for-lateral-movement-and-persistence/13746 - Parisi, T., et al. (2017, July). Using Outlook Forms for Lateral Movement and Persistence. Retrieved February 5, 2019.
* https://medium.com/@bwtech789/outlook-today-homepage-persistence-33ea9b505943 - Soutcast. (2018, September 14). Outlook Today Homepage Persistence. Retrieved February 5, 2019.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://msdn.microsoft.com/en-US/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved December 5, 2014.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/en-us/vba/office-shared-vba/articles/getting-started-with-vba-in-office - Austin, J. (2017, June 6). Getting Started with VBA in Office. Retrieved July 3, 2017.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msitpros.com/?p=3960 - Moe, O. (2017, August 15). Research on CMSTP.exe. Retrieved April 11, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://passlib.readthedocs.io/en/stable/lib/passlib.hash.msdcc2.html - Eli Collins. (2016, November 25). Windows' Domain Cached Credentials v2. Retrieved February 21, 2020.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/head-in-the-clouds-bd038bb69e48 - Maddalena, C.. (2018, September 12). Head in the Clouds. Retrieved October 4, 2019.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/help/310593/description-of-the-runonceex-registry-key - Microsoft. (2018, August 20). Description of the RunOnceEx Registry Key. Retrieved June 29, 2018.
* https://support.office.com/article/Change-the-Normal-template-Normal-dotm-06de294b-d216-47f6-ab77-ccb5166f98ea - Microsoft. (n.d.). Change the Normal template (Normal.dotm). Retrieved July 3, 2017.
* https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx - Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.
* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works - Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc772408.aspx - Microsoft. (n.d.). Services. Retrieved June 7, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/ItsReallyNick/status/958789644165894146 - Carr, N. (2018, January 31). Here is some early bad cmstp.exe... Retrieved April 11, 2018.
* https://twitter.com/NickTyrer/status/958450014111633408 - Tyrer, N. (2018, January 30). CMSTP.exe - remote .sct execution applocker bypass. Retrieved April 11, 2018.
* https://twitter.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved December 12, 2017.
* https://www-01.ibm.com/support/docview.wss?uid=ssg1S1010146&myns=s028&mynp=OCSTHGUJ&mynp=OCSTLM5A&mynp=OCSTLM6B&mynp=OCHW206&mync=E&cm_sp=s028-_-OCSTHGUJ-OCSTLM5A-OCSTLM6B-OCHW206-_-E - IBM Support. (2017, April 26). Storwize USB Initialization Tool may contain malicious code. Retrieved May 28, 2019.
* https://www.221bluestreet.com/post/office-templates-and-globaldotname-a-stealthy-office-persistence-technique - Shukrun, S. (2019, June 2). Office Templates and GlobalDotName - A Stealthy Office Persistence Technique. Retrieved August 26, 2019.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.commandfive.com/papers/C5_APT_SKHack.pdf - Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.cylance.com/content/dam/cylance/pdfs/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved September 19, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.f-secure.com/documents/996508/1030745/CozyDuke - F-Secure Labs. (2015, April 22). CozyDuke: Malware Analysis. Retrieved December 10, 2015.
* https://www.fireeye.com/blog/threat-research/2010/08/dll-search-order-hijacking-revisited.html - Nick Harbour. (2010, September 1). DLL Search Order Hijacking Revisited. Retrieved March 13, 2020.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html - Berry, A., Galang, L., Jiang, G., Leathery, J., Mohandas, R. (2017, April 11). CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler. Retrieved October 27, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://www.fireeye.com/blog/threat-research/2017/07/hawkeye-malware-distributed-in-phishing-campaign.html - Swapnil Patil, Yogesh Londhe. (2017, July 25). HawkEye Credential Theft Malware Distributed in Recent Phishing Campaign. Retrieved June 18, 2019.
* https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html - Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Amanda Steward. (2014). FireEye DLL Side-Loading: A Thorn in the Side of the Anti-Virus Industry. Retrieved March 13, 2020.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.first.org/resources/papers/conf2017/Windows-Credentials-Attacks-and-Mitigation-Techniques.pdf - Chad Tilbury. (2017, August 8). 1Windows Credentials: Attack, Mitigation, Defense. Retrieved February 21, 2020.
* https://www.owasp.org/index.php/Binary_planting - OWASP. (2013, January 30). Binary planting. Retrieved June 7, 2016.
* https://www.passcape.com/index.php?section=docsys&cmd=details&id=23 - Passcape. (n.d.). Windows LSA secrets. Retrieved February 21, 2020.
* https://www.proofpoint.com/us/threat-insight/post/new-vega-stealer-shines-brightly-targeted-campaign - Proofpoint. (2018, May 10). New Vega Stealer shines brightly in targeted campaign . Retrieved June 18, 2019.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.schneider-electric.com/en/download/document/SESN-2018-236-01/ - Schneider Electric. (2018, August 24). Security Notification – USB Removable Media Provided With Conext Combox and Conext Battery Monitor. Retrieved May 28, 2019.
* https://www.ssh.com/ssh - SSH.COM. (n.d.). SSH (Secure Shell). Retrieved March 23, 2020.
* https://www.trendmicro.com/vinfo/dk/security/news/cybercrime-and-digital-threats/hacker-infects-node-js-package-to-steal-from-bitcoin-wallets - Trendmicro. (2018, November 29). Hacker Infects Node.js Package to Steal from Bitcoin Wallets. Retrieved April 10, 2019.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/ - Lassalle, D., et al. (2017, November 6). OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society. Retrieved November 6, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf - Kafka, F. (2018, January). ESET's Guide to Deobfuscating and Devirtualizing FinFisher. Retrieved August 12, 2019.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* ttps://ired.team/offensive-security/credential-access-and-credential-dumping/dumping-lsa-secrets - Mantvydas Baranauskas. (2019, November 16). Dumping LSA Secrets. Retrieved February 21, 2020.

# Validate the following tools

* Cobalt Strike - 1
* Empire - 2
* Impacket - 1
* Koadic - 1
* LaZagne - 1
* Mimikatz - 2
* Net - 1
* Ping - 1
* PowerSploit - 2
* PsExec - 1
* QuasarRAT - 1
* certutil - 1
* cmd - 1
* esentutl - 1
* pwdump - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://digital-forensics.sans.org/blog/2012/12/17/protecting-privileged-domain-accounts-psexec-deep-dive - Pilkington, M.. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh875546(v=ws.11) - Microsoft. (2016, August 30). Esentutl. Retrieved September 3, 2019.
* https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf - Lunghi, D., et al. (2017, December). Untangling the Patchwork Cyberespionage Group. Retrieved July 10, 2018.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (1985, June 22). pwdump. Retrieved June 22, 2016.
* https://github.com/AlessandroZ/LaZagne - Zanni, A. (n.d.). The LaZagne Project !!!. Retrieved December 14, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/quasar/QuasarRAT - MaxXor. (n.d.). QuasarRAT. Retrieved July 10, 2018.
* https://github.com/zerosum0x0/koadic - Magius, J., et al. (2017, July 19). Koadic. Retrieved June 18, 2018.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/ - Lee, B., Falcone, R. (2018, June 06). Sofacy Group’s Parallel Attacks. Retrieved June 18, 2018.
* https://s3.eu-west-1.amazonaws.com/ncsc-content/files/Joint%20report%20on%20publicly%20available%20hacking%20tools%20%28NCSC%29.pdf - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://technet.microsoft.com/en-us/library/bb490880.aspx - Microsoft. (n.d.). Cmd. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/bb490886.aspx - Microsoft. (n.d.). Copy. Retrieved April 26, 2016.
* https://technet.microsoft.com/en-us/library/bb490968.aspx - Microsoft. (n.d.). Ping. Retrieved April 8, 2016.
* https://technet.microsoft.com/en-us/library/cc755121.aspx - Microsoft. (n.d.). Dir. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/library/cc771049.aspx - Microsoft. (n.d.). Del. Retrieved April 22, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/cc732443.aspx - Microsoft. (2012, November 14). Certutil. Retrieved July 3, 2017.
* https://www.secureauth.com/labs/open-source-tools/impacket - SecureAuth. (n.d.).  Retrieved January 15, 2019.
* https://www.volexity.com/blog/2018/06/07/patchwork-apt-group-targets-us-think-tanks/ - Meltzer, M, et al. (2018, June 07). Patchwork APT Group Targets US Think Tanks. Retrieved July 16, 2018.

# Validate the following malware

* Briba - 1
* ChChes - 1
* EvilGrab - 1
* Hydraq - 1
* Linfo - 1
* Naid - 1
* Nerex - 1
* POWERSTATS - 1
* Pasam - 1
* PlugX - 1
* PoisonIvy - 2
* RedLeaves - 1
* SHARPSTATS - 1
* SNUGRIDE - 1
* UPPERCUT - 1
* Vasport - 1
* Wiarp - 1

# Review the following malware references

* http://blog.jpcert.or.jp/2017/02/chches-malware--93d6.html - Nakamura, Y.. (2017, February 17). ChChes - Malware that Communicates with C&C Servers Using Cookie Headers. Retrieved March 1, 2017.
* http://circl.lu/assets/files/tr-12/tr-12-circl-plugx-analysis-v1.pdf - Computer Incident Response Center Luxembourg. (2013, March 29). Analysis of a PlugX variant. Retrieved November 5, 2018.
* http://labs.lastline.com/an-analysis-of-plugx - Vasilenko, R. (2013, December 17). An Analysis of PlugX Malware. Retrieved November 24, 2015.
* http://researchcenter.paloaltonetworks.com/2015/04/unit-42-identifies-new-dragonok-backdoor-malware-deployed-against-japanese-targets/ - Miller-Osborn, J., Grunzweig, J.. (2015, April). Unit 42 Identifies New DragonOK Backdoor Malware Deployed Against Japanese Targets. Retrieved November 4, 2015.
* http://researchcenter.paloaltonetworks.com/2017/02/unit42-menupass-returns-new-malware-new-attacks-japanese-academics-organizations/ - Miller-Osborn, J. and Grunzweig, J.. (2017, February 16). menuPass Returns with New Malware and New Attacks Against Japanese Academics and Organizations. Retrieved March 1, 2017.
* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/muddywater-resurfaces-uses-multi-stage-backdoor-powerstats-v3-and-new-post-exploitation-tools/ - Lunghi, D. and Horejsi, J.. (2019, June 10). MuddyWater Resurfaces, Uses Multi-Stage Backdoor POWERSTATS V3 and New Post-Exploitation Tools. Retrieved May 14, 2020.
* https://community.softwaregrp.com/t5/Security-Research/9002-RAT-a-second-building-on-the-left/ba-p/228686#.WosBVKjwZPZ - Petrovsky, O. (2016, August 30). “9002 RAT” -- a second building on the left. Retrieved February 20, 2018.
* https://researchcenter.paloaltonetworks.com/2015/09/chinese-actors-use-3102-malware-in-attacks-on-us-government-and-eu-media/ - Falcone, R. & Miller-Osborn, J. (2015, September 23). Chinese Actors Use ‘3102’ Malware in Attacks on US Government and EU Media. Retrieved March 19, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-muddying-the-water-targeted-attacks-in-the-middle-east/ - Lancaster, T.. (2017, November 14). Muddying the Water: Targeted Attacks in the Middle East. Retrieved March 15, 2018.
* https://twitter.com/ItsReallyNick/status/850105140589633536 - Carr, N.. (2017, April 6). Retrieved June 29, 2017.
* https://www.arbornetworks.com/blog/asert/wp-content/uploads/2016/01/ASERT-Threat-Intelligence-Brief-2015-08-Uncovering-the-Seven-Point-Dagger.pdf - ASERT. (2015, August). ASERT Threat Intelligence Report – Uncovering the Seven Pointed Dagger. Retrieved March 19, 2018.
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf - ClearSky Cyber Security. (2018, November). MuddyWater Operations in Lebanon and Oman: Using an Israeli compromised domain for a two-stage campaign. Retrieved November 29, 2018.
* https://www.fireeye.com/blog/threat-research/2013/05/ready-for-summer-the-sunshop-campaign.html - Moran, N. (2013, May 20). Ready for Summer: The Sunshop Campaign. Retrieved March 19, 2018.
* https://www.fireeye.com/blog/threat-research/2013/11/operation-ephemeral-hydra-ie-zero-day-linked-to-deputydog-uses-diskless-method.html - Moran, N. et al.. (2013, November 10). Operation Ephemeral Hydra: IE Zero-Day Linked to DeputyDog Uses Diskless Method. Retrieved March 19, 2018.
* https://www.fireeye.com/blog/threat-research/2014/06/clandestine-fox-part-deux.html - Scott, M.. (2014, June 10). Clandestine Fox, Part Deux. Retrieved January 14, 2016.
* https://www.fireeye.com/blog/threat-research/2017/04/apt10_menupass_grou.html - FireEye iSIGHT Intelligence. (2017, April 6). APT10 (MenuPass Group): New Tools, Global Campaign Latest Manifestation of Longstanding Threat. Retrieved June 29, 2017.
* https://www.fireeye.com/blog/threat-research/2018/09/apt10-targeting-japanese-corporations-using-updated-ttps.html - Matsuda, A., Muhammad I. (2018, September 13). APT10 Targeting Japanese Corporations Using Updated TTPs. Retrieved September 17, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved November 12, 2014.
* https://www.proofpoint.com/us/threat-insight/post/operation-rat-cook-chinese-apt-actors-use-fake-game-thrones-leaks-lures - Huss, D. & Mesa, M. (2017, August 25). Operation RAT Cook: Chinese APT actors use fake Game of Thrones leaks as lures. Retrieved March 19, 2018.
* https://www.pwc.co.uk/cyber-security/pdf/cloud-hopper-annex-b-final.pdf - PwC and BAE Systems. (2017, April). Operation Cloud Hopper: Technical Annex. Retrieved April 13, 2017.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/blogs/threat-intelligence/seedworm-espionage-group - Symantec DeepSight Adversary Intelligence Team. (2018, December 10). Seedworm: Group Compromises Government Agencies, Oil & Gas, NGOs, Telecoms, and IT Firms. Retrieved December 14, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/connect/blogs/trojanhydraq-incident - Symantec Security Response. (2010, January 18). The Trojan.Hydraq Incident. Retrieved February 20, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-050412-4128-99 - Mullaney, C. & Honda, H. (2012, May 4). Trojan.Pasam. Retrieved February 22, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-051515-2843-99 - Ladley, F. (2012, May 15). Backdoor.Briba. Retrieved February 21, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-051515-3445-99 - Ladley, F. (2012, May 15). Backdoor.Nerex. Retrieved February 23, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-051605-2535-99 - Zhou, R. (2012, May 15). Backdoor.Linfo. Retrieved February 23, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-1005-99 - Zhou, R. (2012, May 15). Backdoor.Wiarp. Retrieved February 22, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-051606-5938-99 - Zhou, R. (2012, May 15). Backdoor.Vasport. Retrieved February 22, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2012-061518-4639-99 - Neville, A. (2012, June 15). Trojan.Naid. Retrieved February 22, 2018.

