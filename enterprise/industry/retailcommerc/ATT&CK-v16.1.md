threat-crank.py 0.2.1
I: searching for industries that match .* retail.*|.* commerc.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v16.1/enterprise-attack/enterprise-attack.json
# Threat groups

* APT41
* FIN13
* FIN6
* FIN7
* FIN8
* Scattered Spider

# Validate the following attacks

* Access Token Manipulation - 1
* Accessibility Features - 1
* Account Discovery - 1
* Additional Cloud Roles - 1
* Additional Local or Domain Groups - 2
* Application Shimming - 1
* Archive Collected Data - 1
* Archive via Custom Method - 1
* Archive via Utility - 3
* Asymmetric Cryptography - 2
* Asynchronous Procedure Call - 1
* Automated Collection - 1
* BITS Jobs - 1
* Bidirectional Communication - 1
* Binary Padding - 1
* Boot or Logon Initialization Scripts - 1
* Bootkit - 1
* Browser Information Discovery - 1
* Brute Force - 1
* Clear Command History - 1
* Clear Windows Event Logs - 2
* Cloud Infrastructure Discovery - 1
* Cloud Service Dashboard - 1
* Cloud Services - 1
* Code Repositories - 2
* Code Signing - 4
* Code Signing Certificates - 1
* Command Obfuscation - 3
* Command and Scripting Interpreter - 2
* Compiled HTML File - 1
* Compromise Software Supply Chain - 2
* Compute Hijacking - 1
* Conditional Access Policies - 1
* Create Account - 1
* Create Cloud Instance - 1
* Credentials In Files - 2
* Credentials from Password Stores - 2
* Credentials from Web Browsers - 2
* DLL Search Order Hijacking - 1
* DLL Side-Loading - 2
* DNS - 2
* Data Encrypted for Impact - 4
* Data Manipulation - 1
* Data Staged - 1
* Data Transfer Size Limits - 1
* Data from Cloud Storage - 1
* Data from Information Repositories - 1
* Data from Local System - 4
* Dead Drop Resolver - 1
* Default Accounts - 1
* Deobfuscate/Decode Files or Information - 1
* Direct Volume Access - 1
* Disable or Modify Tools - 1
* Domain Account - 4
* Domain Generation Algorithms - 1
* Domain Groups - 1
* Domain Trust Discovery - 1
* Domains - 1
* Drive-by Target - 1
* Dynamic Data Exchange - 1
* Dynamic Linker Hijacking - 1
* Email Collection - 1
* Email Hiding Rules - 1
* Environmental Keying - 1
* Exfiltration Over Unencrypted Non-C2 Protocol - 2
* Exfiltration to Cloud Storage - 2
* Exploit Public-Facing Application - 3
* Exploitation for Client Execution - 1
* Exploitation for Privilege Escalation - 3
* Exploitation of Remote Services - 1
* External Remote Services - 3
* Fallback Channels - 2
* File Deletion - 3
* File Transfer Protocols - 1
* File and Directory Discovery - 3
* Financial Theft - 2
* Gather Victim Identity Information - 1
* Group Policy Modification - 1
* Hidden Files and Directories - 1
* Impersonation - 2
* Indicator Blocking - 1
* Ingress Tool Transfer - 4
* Internal Proxy - 1
* Internet Connection Discovery - 2
* JavaScript - 2
* Kerberoasting - 1
* Keylogging - 2
* LSASS Memory - 4
* Lateral Tool Transfer - 1
* Local Account - 3
* Local Accounts - 1
* Local Data Staging - 1
* Make and Impersonate Token - 1
* Malicious File - 3
* Malicious Link - 2
* Malware - 2
* Masquerade Task or Service - 4
* Masquerading - 1
* Match Legitimate Name or Location - 3
* Messaging Applications - 1
* Modify Authentication Process - 1
* Modify Registry - 2
* Mshta - 1
* Multi-Factor Authentication - 1
* Multi-Factor Authentication Request Generation - 1
* Multi-Stage Channels - 1
* NTDS - 4
* Network Boundary Bridging - 1
* Network Service Discovery - 3
* Network Share Discovery - 2
* Network Topology - 1
* Non-Application Layer Protocol - 1
* Non-Standard Port - 1
* Obfuscated Files or Information - 1
* Pass the Hash - 2
* Password Cracking - 1
* Permission Groups Discovery - 2
* Phishing for Information - 1
* PowerShell - 5
* Private Keys - 1
* Process Injection - 1
* Protocol Tunneling - 2
* Proxy - 1
* Query Registry - 1
* Registry Run Keys / Startup Folder - 4
* Remote Access Software - 2
* Remote Data Staging - 2
* Remote Desktop Protocol - 5
* Remote System Discovery - 4
* Replication Through Removable Media - 1
* Rootkit - 1
* Rundll32 - 2
* SMB/Windows Admin Shares - 3
* SSH - 2
* Scan Databases - 1
* Scheduled Task - 5
* Screen Capture - 1
* Security Account Manager - 2
* Security Software Discovery - 1
* Service Execution - 2
* Software Packing - 1
* Spearphishing Attachment - 4
* Spearphishing Link - 2
* Spearphishing Voice - 1
* Spearphishing via Service - 1
* Steal Web Session Cookie - 1
* System Information Discovery - 3
* System Network Configuration Discovery - 2
* System Network Connections Discovery - 2
* System Owner/User Discovery - 3
* Token Impersonation/Theft - 1
* Tool - 5
* Trust Modification - 1
* Unix Shell - 1
* Upload Malware - 1
* User Activity Based Checks - 1
* User Execution - 1
* VNC - 1
* Valid Accounts - 4
* Video Capture - 1
* Visual Basic - 2
* Vulnerability Scanning - 1
* Web Protocols - 3
* Web Service - 2
* Web Services - 1
* Web Shell - 1
* Windows Command Shell - 5
* Windows Management Instrumentation - 5
* Windows Management Instrumentation Event Subscription - 1
* Windows Remote Management - 1
* Windows Service - 2
* Wordlist Scanning - 1

# Validate the following phases

* collection - 24
* command-and-control - 28
* credential-access - 27
* defense-evasion - 67
* discovery - 40
* execution - 37
* exfiltration - 5
* impact - 8
* initial-access - 22
* lateral-movement - 18
* persistence - 40
* privilege-escalation - 38
* reconnaissance - 7
* resource-development - 12

# Validate the following platforms

* Containers - 33
* IaaS - 50
* Identity Provider - 23
* Linux - 205
* Network - 69
* Office Suite - 32
* PRE - 19
* SaaS - 29
* Windows - 336
* macOS - 204

# Validate the following defences

* Anti Virus - 2
* Anti-virus - 19
* Application Control - 12
* Application control - 6
* Digital Certificate Validation - 4
* File Monitoring - 1
* File monitoring - 3
* File system access controls - 3
* Firewall - 6
* Heuristic Detection - 1
* Heuristic detection - 1
* Host Forensic Analysis - 3
* Host Intrusion Prevention Systems - 9
* Host forensic analysis - 9
* Host intrusion prevention systems - 3
* Log Analysis - 3
* Log analysis - 2
* Multi-Factor Authentication - 1
* Network Intrusion Detection System - 5
* Signature-based Detection - 4
* Signature-based detection - 4
* Static File Analysis - 2
* System Access Controls - 9
* System access controls - 2
* Windows User Account Control - 7

# Validate the following data sources

* Active Directory: Active Directory Credential Request - 3
* Active Directory: Active Directory Object Access - 3
* Active Directory: Active Directory Object Creation - 2
* Active Directory: Active Directory Object Deletion - 1
* Active Directory: Active Directory Object Modification - 7
* Application Log: Application Log Content - 38
* Cloud Service: Cloud Service Enumeration - 5
* Cloud Service: Cloud Service Metadata - 1
* Cloud Service: Cloud Service Modification - 2
* Cloud Storage: Cloud Storage Access - 1
* Cloud Storage: Cloud Storage Enumeration - 1
* Cloud Storage: Cloud Storage Modification - 4
* Command: Command Execution - 167
* Container: Container Creation - 1
* Container: Container Start - 1
* Domain Name: Active DNS - 1
* Domain Name: Domain Registration - 1
* Domain Name: Passive DNS - 1
* Drive: Drive Access - 1
* Drive: Drive Creation - 1
* Drive: Drive Modification - 2
* Driver: Driver Load - 8
* File: File Access - 39
* File: File Creation - 56
* File: File Deletion - 7
* File: File Metadata - 24
* File: File Modification - 30
* Firewall: Firewall Enumeration - 1
* Firewall: Firewall Metadata - 1
* Firmware: Firmware Modification - 1
* Group: Group Enumeration - 8
* Group: Group Metadata - 2
* Image: Image Creation - 1
* Image: Image Metadata - 4
* Instance: Instance Creation - 2
* Instance: Instance Enumeration - 1
* Instance: Instance Metadata - 1
* Instance: Instance Start - 1
* Internet Scan: Response Content - 3
* Logon Session: Logon Session Creation - 33
* Logon Session: Logon Session Metadata - 14
* Malware Repository: Malware Content - 2
* Malware Repository: Malware Metadata - 8
* Module: Module Load - 22
* Named Pipe: Named Pipe Metadata - 1
* Network Share: Network Share Access - 8
* Network Traffic: Network Connection Creation - 52
* Network Traffic: Network Traffic Content - 62
* Network Traffic: Network Traffic Flow - 75
* Process: OS API Execution - 56
* Process: Process Access - 15
* Process: Process Creation - 148
* Process: Process Metadata - 13
* Process: Process Modification - 2
* Process: Process Termination - 1
* Scheduled Job: Scheduled Job Creation - 5
* Scheduled Job: Scheduled Job Metadata - 5
* Scheduled Job: Scheduled Job Modification - 5
* Script: Script Execution - 27
* Sensor Health: Host Status - 3
* Service: Service Creation - 9
* Service: Service Metadata - 8
* Service: Service Modification - 2
* Snapshot: Snapshot Enumeration - 1
* User Account: User Account Authentication - 16
* User Account: User Account Creation - 4
* User Account: User Account Metadata - 1
* User Account: User Account Modification - 5
* Volume: Volume Enumeration - 1
* WMI: WMI Creation - 7
* Windows Registry: Windows Registry Key Access - 6
* Windows Registry: Windows Registry Key Creation - 16
* Windows Registry: Windows Registry Key Deletion - 3
* Windows Registry: Windows Registry Key Modification - 23

# Review the following attack references

* http://adsecurity.org/?p=1275 - Metcalf, S. (2015, January 19). Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest. Retrieved February 3, 2015.
* http://arstechnica.com/security/2015/08/newly-discovered-chinese-hacking-group-hacked-100-websites-to-use-as-watering-holes/ - Gallagher, S.. (2015, August 5). Newly discovered Chinese hacking group hacked 100+ websites to use as “watering holes”. Retrieved January 25, 2016.
* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.crowdstrike.com/registry-analysis-with-crowdresponse/ - Tilbury, C. (2014, August 28). Registry Analysis with CrowdResponse. Retrieved November 12, 2014.
* http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html - Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://blogs.technet.com/b/srd/archive/2014/05/13/ms14-025-an-update-for-group-policy-preferences.aspx - Security Research and Defense. (2014, May 13). MS14-025: An Update for Group Policy Preferences. Retrieved January 28, 2015.
* http://carnal0wnage.attackresearch.com/2014/05/mimikatz-against-virtual-machine-memory.html - CG. (2014, May 20). Mimikatz Against Virtual Machine Memory Part 1. Retrieved November 12, 2014.
* http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf - Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
* http://csis.pace.edu/~ctappert/srd2017/2017PDF/d4.pdf - Chen, L., Wang, T.. (2017, May 5). Detecting Algorithmically Generated Domains Using Data Visualization and N-Grams Methods . Retrieved April 26, 2019.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29 - Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.
* http://files.brucon.org/2015/Tomczak_and_Ballenthin_Shims_for_the_Win.pdf - Ballenthin, W., Tomczak, J.. (2015). The Real Shim Shary. Retrieved May 4, 2020.
* http://go.cybereason.com/rs/996-YZT-709/images/Cybereason-Lab-Analysis-Dissecting-DGAs-Eight-Real-World-DGA-Variants.pdf - Sternfeld, U. (2016). Dissecting Domain Generation Algorithms: Eight Real World DGA Variants. Retrieved February 18, 2019.
* http://hick.org/code/skape/papers/needle.txt - skape. (2003, January 19). Linux x86 run-time process manipulation. Retrieved December 20, 2017.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://phrack.org/issues/51/8.html - halflife. (1997, September 1). Shared Library Redirection Techniques. Retrieved December 20, 2017.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/KB/170292 - Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://www.blackhat.com/docs/asia-14/materials/Tsai/WP-Asia-14-Tsai-You-Cant-See-Me-A-Mac-OS-X-Rootkit-Uses-The-Tricks-You-Havent-Known-Yet.pdf - Pan, M., Tsai, S. (2014). You can’t see me: A Mac OS X Rootkit uses the tricks you haven't known yet. Retrieved December 21, 2017.
* http://www.chokepoint.net/2014/02/detecting-userland-preload-rootkits.html - stderr. (2014, February 14). Detecting Userland Preload Rootkits. Retrieved December 20, 2017.
* http://www.codeproject.com/Articles/32169/FDump-Dumping-File-Sectors-Directly-from-Disk-usin - Hakobyan, A. (2009, January 8). FDump - Dumping File Sectors Directly from Disk using Logical Offsets. Retrieved November 12, 2014.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.nth-dimension.org.uk/pub/BTL.pdf - Tim Brown. (2011, June 29). Breaking the links: Exploiting the linker. Retrieved March 29, 2021.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.symantec.com/connect/blogs/are-mbr-infections-back-fashion - Lau, H. (2011, August 8). Are MBR Infections Back in Fashion? (Infographic). Retrieved November 13, 2014.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf - ESET. (2016, October). En Route with Sednit - Part 2: Observing the Comings and Goings. Retrieved November 21, 2016.
* https://aadinternals.com/post/deviceidentity/ - Dr. Nestori Syynimaa. (2022, February 15). Stealing and faking Azure AD device identities. Retrieved February 21, 2023.
* https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/chap-system_auditing - Jahoda, M. et al.. (2017, March 14). redhat Security Guide - Chapter 7 - System Auditing. Retrieved December 20, 2017.
* https://adsecurity.org/?p=1588 - Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.
* https://adsecurity.org/?p=2053 - Metcalf, S. (2015, November 22). Dump Clear-Text Passwords for All Admins in the Domain Using Mimikatz DCSync. Retrieved November 15, 2021.
* https://adsecurity.org/?p=2293 - Metcalf, S. (2015, December 31). Cracking Kerberos TGS Tickets Using Kerberoast – Exploiting Kerberos to Compromise the Active Directory Domain. Retrieved March 22, 2018.
* https://adsecurity.org/?p=2716 - Metcalf, S. (2016, March 14). Sneaky Active Directory Persistence #17: Group Policy. Retrieved March 5, 2019.
* https://airbus-cyber-security.com/fileless-malware-behavioural-analysis-kovter-persistence/ - Dove, A. (2016, March 23). Fileless Malware – A Behavioural Analysis Of Kovter Persistence. Retrieved December 5, 2017.
* https://apnews.com/article/russia-ukraine-technology-business-europe-hacking-ce7a8aca506742ab8e8873e7f9f229c2 - FRANK BAJAK AND RAPHAEL SATTER. (2017, June 30). Companies still hobbled from fearsome cyberattack. Retrieved August 18, 2023.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arstechnica.com/information-technology/2014/06/active-malware-operation-let-attackers-sabotage-us-energy-industry/ - Dan Goodin. (2014, June 30). Active malware operation let attackers sabotage US energy industry. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://arxiv.org/pdf/1611.00791.pdf - Ahuja, A., Anderson, H., Grant, D., Woodbridge, J.. (2016, November 2). Predicting Domain Generation Algorithms with Long Short-Term Memory Networks. Retrieved April 26, 2019.
* https://aws.amazon.com/premiumsupport/knowledge-center/cloudtrail-search-api-calls/ - Amazon. (n.d.). Search CloudTrail logs for API calls to EC2 Instances. Retrieved June 17, 2020.
* https://aws.amazon.com/premiumsupport/knowledge-center/secure-s3-resources/ - Amazon. (2019, May 17). How can I secure the files in my Amazon S3 bucket?. Retrieved October 4, 2019.
* https://bashfuscator.readthedocs.io/en/latest/Mutators/command_obfuscators/index.html - LeFevre, A. (n.d.). Bashfuscator Command Obfuscators. Retrieved March 17, 2023.
* https://blog.avast.com/new-investigations-in-ccleaner-incident-point-to-a-possible-third-stage-that-had-keylogger-capacities - Avast Threat Intelligence Team. (2018, March 8). New investigations into the CCleaner incident point to a possible third stage that had keylogger capacities. Retrieved March 15, 2018.
* https://blog.crysys.hu/2013/03/teamspy/ - CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.
* https://blog.cyberproof.com/blog/double-bounced-attacks-with-email-spoofing-2022-trends - Itkin, Liora. (2022, September 1). Double-bounced attacks with email spoofing . Retrieved February 24, 2023.
* https://blog.ensilo.com/atombombing-brand-new-code-injection-for-windows - Liberman, T. (2016, October 27). ATOMBOMBING: BRAND NEW CODE INJECTION FOR WINDOWS. Retrieved December 8, 2017.
* https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/ - Schroeder, W. (2017, January 10). The Most Dangerous User Right You (Probably) Have Never Heard Of. Retrieved September 23, 2024.
* https://blog.harmj0y.net/powershell/kerberoasting-without-mimikatz/ - Schroeder, W. (2016, November 1). Kerberoasting Without Mimikatz. Retrieved September 23, 2024.
* https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/ - Schroeder, W. (2016, March 17). Abusing GPO Permissions. Retrieved September 23, 2024.
* https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/ - Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/researchers-corner/2019/09/hacking-with-aws-incorporating-leaky-buckets-osint-workflow/ - Vasilios Hioureas. (2019, September 13). Hacking with AWS: incorporating leaky buckets into your OSINT workflow. Retrieved February 14, 2022.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments - Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.
* https://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/ -  Ishaq Mohammed . (2021, January 10). Everything about CSV Injection and CSV Excel Macro Injection. Retrieved February 7, 2022.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A., McKay, K. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal . Retrieved July 29, 2022.
* https://blog.talosintelligence.com/2021/11/kimsuky-abuses-blogs-delivers-malware.html - An, J and Malhotra, A. (2021, November 10). North Korean attackers use malicious blogs to deliver malware to high-profile South Korean targets. Retrieved December 29, 2021.
* https://blog.talosintelligence.com/2022/03/transparent-tribe-new-campaign.html - Malhotra, A., Thattil, J. et al. (2022, March 29). Transparent Tribe campaign uses new bespoke malware to target Indian government officials . Retrieved September 6, 2022.
* https://blog.talosintelligence.com/ipfs-abuse/ - Edmund Brumaghin. (2022, November 9). Threat Spotlight: Cyber Criminal Adoption of IPFS for Phishing, Malware Campaigns. Retrieved March 8, 2023.
* https://blog.talosintelligence.com/roblox-scam-overview/ - Tiago Pereira. (2023, November 2). Attackers use JavaScript URLs, API forms and more to scam users in popular online game “Roblox”. Retrieved January 2, 2024.
* https://blog.timac.org/2012/1218-simple-code-injection-using-dyld_insert_libraries/ - Timac. (2012, December 18). Simple code injection using DYLD_INSERT_LIBRARIES. Retrieved March 26, 2020.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices - Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.
* https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://blogs.technet.microsoft.com/motiba/2018/02/23/detecting-kerberoasting-activity-using-azure-security-center/ - Bani, M. (2018, February 23). Detecting Kerberoasting activity using Azure Security Center. Retrieved March 23, 2018.
* https://blogs.technet.microsoft.com/musings_of_a_technical_tam/2012/02/13/group-policy-basics-part-1-understanding-the-structure-of-a-group-policy-object/ - srachui. (2012, February 13). Group Policy Basics – Part 1: Understanding the Structure of a Group Policy Object. Retrieved March 5, 2019.
* https://blogs.technet.microsoft.com/timmcmic/2015/06/08/exchange-and-office-365-mail-forwarding-2/ - McMichael, T.. (2015, June 8). Exchange and Office 365 Mail Forwarding. Retrieved October 8, 2019.
* https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16 - Bromiley, M. (2016, December 27). Malware Monday: VBScript and VBE Files. Retrieved March 17, 2023.
* https://business.bofa.com/en-us/content/what-is-vishing.html - Bank of America. (n.d.). How to avoid telephone scams. Retrieved September 8, 2023.
* https://cdn.logic-control.com/docs/scadafence/Anatomy-Of-A-Targeted-Ransomware-Attack-WP.pdf - Shaked, O. (2020, January 20). Anatomy of a Targeted Ransomware Attack. Retrieved June 18, 2022.
* https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.226.3427&rep=rep1&type=pdf - Zhaohui Wang & Angelos Stavrou. (n.d.). Exploiting Smart-Phone USB Connectivity For Fun And Profit. Retrieved May 25, 2022.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/iam/docs/conditions-overview - Google Cloud. (n.d.). Overview of IAM Conditions. Retrieved January 2, 2024.
* https://cloud.google.com/iam/docs/policies - Google Cloud. (2022, March 31). Understanding policies. Retrieved April 1, 2022.
* https://cloud.google.com/logging/docs/audit#admin-activity - Google. (n.d.). Audit Logs. Retrieved June 1, 2020.
* https://cloud.google.com/sdk/gcloud/reference/compute/instances/list - Google. (n.d.). gcloud compute instances list. Retrieved May 26, 2020.
* https://cloud.google.com/sdk/gcloud/reference/iam/service-accounts/list - Google. (2020, June 23). gcloud iam service-accounts list. Retrieved August 4, 2020.
* https://cloud.google.com/security-command-center/docs/quickstart-scc-dashboard - Google. (2019, October 3). Quickstart: Using the dashboard. Retrieved October 8, 2019.
* https://cloud.google.com/storage/docs/best-practices - Google. (2019, September 16). Best practices for Cloud Storage. Retrieved October 4, 2019.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://clymb3r.wordpress.com/2013/09/15/intercepting-password-changes-with-function-hooking/ - Bialek, J. (2013, September 15). Intercepting Password Changes With Function Hooking. Retrieved November 21, 2017.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://community.sophos.com/products/intercept/early-access-program/f/live-discover-response-queries/121529/live-discover---powershell-command-audit - jak. (2020, June 27). Live Discover - PowerShell command audit. Retrieved August 21, 2020.
* https://community.sophos.com/products/malware/b/blog/posts/powershell-command-history-forensics - Vikas, S. (2020, August 26). PowerShell Command History Forensics. Retrieved September 4, 2020.
* https://confluence.atlassian.com/confkb/how-to-enable-user-access-logging-182943.html - Atlassian. (2018, January 9). How to Enable User Access Logging. Retrieved April 4, 2018.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://cybernews.com/security/thomson-reuters-leaked-terabytes-sensitive-data/ - Vilius Petkauskas . (2022, November 3). Thomson Reuters collected and leaked at least 3TB of sensitive data. Retrieved September 25, 2024.
* https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks - Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.
* https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/ - Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.
* https://datatracker.ietf.org/doc/html/rfc6143#section-7.2.2 - T. Richardson, J. Levine, RealVNC Ltd.. (2011, March). The Remote Framebuffer Protocol. Retrieved September 20, 2021.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/NetServices/Introduction.html - Apple Inc. (2013, April 23). Bonjour Overview. Retrieved October 11, 2021.
* https://developer.apple.com/library/archive/documentation/DeveloperTools/Conceptual/DynamicLibraries/100-Articles/OverviewOfDynamicLibraries.html - Apple Inc.. (2012, July 23). Overview of Dynamic Libraries. Retrieved March 24, 2021.
* https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html - Apple. (2016, June 13). About Mac Scripting. Retrieved April 14, 2021.
* https://digital.nhs.uk/cyber-alerts/2020/cc-3681#summary - NHS Digital. (2020, November 26). Egregor Ransomware The RaaS successor to Maze. Retrieved December 29, 2020.
* https://dnsdumpster.com/ - Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.
* https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html - Amazon. (n.d.). DescribeInstances. Retrieved May 26, 2020.
* https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html - Amazon Web Services. (n.d.). Retrieved May 28, 2021.
* https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html - Amazon Web Services. (n.d.). Retrieved May 28, 2021.
* https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html - Amazon Web Services. (n.d.). AWS HeadBucket. Retrieved February 14, 2022.
* https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html - AWS. (n.d.). Policies and permissions in IAM. Retrieved April 1, 2022.
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html - Amazon. (n.d.). AWS Account Root User. Retrieved April 5, 2021.
* https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html - AWS. (n.d.). IAM JSON policy elements: Condition. Retrieved January 2, 2024.
* https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html - Amazon. (n.d.). AWS Console Sign-in Events. Retrieved October 23, 2019.
* https://docs.aws.amazon.com/cli/latest/reference/iam/list-users.html - Amazon. (n.d.). List Users. Retrieved August 11, 2020.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/archive/blogs/gauravseth/the-world-of-jscript-javascript-ecmascript - Microsoft. (2007, August 15). The World of JScript, JavaScript, ECMAScript …. Retrieved June 23, 2020.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/azure/active-directory/governance/conditional-access-exclusion - Microsoft. (2022, August 26). Use Azure AD access reviews to manage users excluded from Conditional Access policies. Retrieved August 30, 2022.
* https://docs.microsoft.com/en-us/azure/active-directory/hybrid/whatis-fed - Microsoft. (2018, November 28). What is federation with Azure AD?. Retrieved December 30, 2020.
* https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/view-activity-logs - Microsoft. (n.d.). View Azure activity logs. Retrieved June 17, 2020.
* https://docs.microsoft.com/en-us/azure/storage/common/storage-security-guide - Amlekar, M., Brooks, C., Claman, L., et. al.. (2019, March 20). Azure Storage security guide. Retrieved October 4, 2019.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/cli/azure/ad/user?view=azure-cli-latest - Microsoft. (n.d.). az ad user. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships - Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8 - Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.
* https://docs.microsoft.com/en-us/microsoft-365/compliance/use-sharing-auditing?view=o365-worldwide#sharepoint-sharing-events - Microsoft. (n.d.). Sharepoint Sharing Events. Retrieved October 8, 2021.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/office365/admin/add-users/about-admin-roles?view=o365-worldwide - Ako-Adjei, K., Dickhaus, M., Baumgartner, P., Faigel, D., et. al.. (2019, October 8). About admin roles. Retrieved October 18, 2019.
* https://docs.microsoft.com/en-us/office365/troubleshoot/active-directory/update-federated-domain-office-365 - Microsoft. (2020, September 14). Update or repair the settings of a federated domain in Office 365, Azure, or Intune. Retrieved December 30, 2020.
* https://docs.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps - Microsoft. (n.d.). New-InboxRule. Retrieved June 7, 2021.
* https://docs.microsoft.com/en-us/powershell/module/exchange/set-inboxrule?view=exchange-ps - Microsoft. (n.d.). Set-InboxRule. Retrieved June 7, 2021.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_history?view=powershell-7 - Microsoft. (2020, May 13). About History. Retrieved September 4, 2020.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1 - Microsoft. (2020, August 21). Running Remote Commands. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10) - Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637 - Microsoft. (, May 23). Microsoft Security Advisory 2269637. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata - Microsoft. (2018, April 12). CryptUnprotectData function. Retrieved June 18, 2019.
* https://docs.microsoft.com/en-us/windows/desktop/etw/consuming-events - Microsoft. (2018, May 30). About Event Tracing. Retrieved June 7, 2019.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts - Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720 - Lich, B., Miroshnikov, A. (2017, April 5). 4720(S): A user account was created. Retrieved June 30, 2017.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules - Microsoft. (2020, October 15). Microsoft recommended driver block rules. Retrieved March 16, 2021.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection?redirectedfrom=MSDN - Microsoft. (2018, May 31). Dynamic-Link Library Redirection. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order?redirectedfrom=MSDN - Microsoft. (2018, May 31). Dynamic-Link Library Search Order. Retrieved November 30, 2014.
* https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry - Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/powershell/module/microsoft.powershell.management/clear-eventlog - Microsoft. (n.d.). Clear-EventLog. Retrieved July 2, 2018.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/previous-versions/windows/desktop/htmlhelp/microsoft-html-help-1-4-sdk - Microsoft. (2018, May 30). Microsoft HTML Help 1.4. Retrieved October 3, 2018.
* https://docs.microsoft.com/scripting/winscript/windows-script-interfaces - Microsoft. (2017, January 18). Windows Script Interfaces. Retrieved June 23, 2020.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
* https://docs.microsoft.com/windows-server/administration/windows-commands/wevtutil - Plett, C. et al.. (2017, October 16). wevtutil. Retrieved July 2, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697 - Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection - Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/win32/com/translating-to-jscript - Microsoft. (2018, May 31). Translating to JScript. Retrieved June 23, 2020.
* https://docs.microsoft.com/windows/win32/services/service-control-manager - Microsoft. (2018, May 31). Service Control Manager. Retrieved March 28, 2020.
* https://docs.ostorlab.co/kb/IPA_URL_SCHEME_HIJACKING/index.html - Ostorlab. (n.d.). iOS URL Scheme Hijacking. Retrieved February 9, 2024.
* https://drive.google.com/file/d/1t0jn3xr4ff2fR30oQAUn_RsWSnMpOAQc/edit - Torello, A. & Guibernau, F. (n.d.). Environment Awareness. Retrieved September 13, 2024.
* https://eclecticlight.co/2020/11/16/checks-on-executable-code-in-catalina-and-big-sur-a-first-draft/ - Howard Oakley. (2020, November 16). Checks on executable code in Catalina and Big Sur: a first draft. Retrieved September 21, 2022.
* https://en.wikipedia.org/wiki/Active_Directory - Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/HTML_Application - Wikipedia. (2017, October 14). HTML Application. Retrieved October 27, 2017.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Password_cracking - Wikipedia. (n.d.). Password cracking. Retrieved December 23, 2015.
* https://en.wikipedia.org/wiki/Public-key_cryptography - Wikipedia. (2017, June 29). Public-key cryptography. Retrieved July 5, 2017.
* https://en.wikipedia.org/wiki/Rootkit - Wikipedia. (2016, June 1). Rootkit. Retrieved June 2, 2016.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.
* https://en.wikipedia.org/wiki/Shared_resource - Wikipedia. (2017, April 15). Shared resource. Retrieved June 30, 2017.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://en.wikipedia.org/wiki/Windows_Registry - Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.
* https://expel.com/blog/incident-report-from-cli-to-console-chasing-an-attacker-in-aws/ -  Brian Bahtiarian, David Blanton, Britton Manahan and Kyle Pellett. (2022, April 5). Incident report: From CLI to console, chasing an attacker in AWS. Retrieved April 7, 2022.
* https://expel.io/blog/finding-evil-in-aws/ - A. Randazzo, B. Manahan and S. Lipton. (2020, April 28). Finding Evil in AWS. Retrieved June 25, 2020.
* https://f.hubspotusercontent30.net/hubfs/8776530/Sygnia-%20Elephant%20Beetle_Jan2022.pdf?__hstc=147695848.3e8f1a482c8f8d4531507747318e660b.1680005306711.1680005306711.1680005306711.1&__hssc=147695848.1.1680005306711&__hsfp=3000179024&hsCtaTracking=189ec409-ae2d-4909-8bf1-62dcdd694372%7Cca91d317-8f10-4a38-9f80-367f551ad64d - Sygnia Incident Response Team. (2022, January 5). TG2003: ELEPHANT BEETLE UNCOVERING AN ORGANIZED FINANCIAL-THEFT OPERATION. Retrieved February 9, 2023.
* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AuditLogs/ADFSDomainTrustMods.yaml - Microsoft. (2020, December). Azure Sentinel Detections. Retrieved December 30, 2020.
* https://github.com/EmpireProject/Empire/blob/master/data/module_source/credentials/Invoke-Kerberoast.ps1 - EmpireProject. (2016, October 31). Invoke-Kerberoast.ps1. Retrieved March 22, 2018.
* https://github.com/Exploit-install/PSAttack-1 - Haight, J. (2016, April 21). PS>Attack. Retrieved September 27, 2024.
* https://github.com/Genetic-Malware/Ebowla/blob/master/Eko_2016_Morrow_Pitts_Master.pdf - Morrow, T., Pitts, J. (2016, October 28). Genetic Malware: Designing Payloads for Specific Targets. Retrieved January 18, 2019.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-NinjaCopy.ps1 - Bialek, J. (2015, December 16). Invoke-NinjaCopy.ps1. Retrieved June 2, 2016.
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml - Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.
* https://github.com/clarketm/s3recon - Travis Clarke. (2020, March 21). S3Recon GitHub. Retrieved March 4, 2022.
* https://github.com/danielbohannon/Invoke-DOSfuscation - Bohannon, D. (2018, March 19). Invoke-DOSfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Invoke-Obfuscation - Bohannon, D. (2016, September 24). Invoke-Obfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/dhondta/awesome-executable-packing - Alexandre D'Hondt. (n.d.). Awesome Executable Packing. Retrieved March 11, 2022.
* https://github.com/dxa4481/truffleHog - Dylan Ayrey. (2016, December 31). truffleHog. Retrieved October 19, 2020.
* https://github.com/gtworek/PSBits/tree/master/NoRunDll - gtworek. (2019, December 17). NoRunDll. Retrieved August 23, 2021.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/kgretzky/evilginx2 - Gretzky, Kuba. (2019, April 10). Retrieved October 8, 2019.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/michenriksen/gitrob - Michael Henriksen. (2018, June 9). Gitrob: Putting the Open Source in OSINT. Retrieved October 19, 2020.
* https://github.com/muraenateam/muraena - Orrù, M., Trotta, G.. (2019, September 11). Muraena. Retrieved October 14, 2019.
* https://github.com/nccgroup/demiguise/blob/master/examples/virginkey.js - Warren, R. (2017, August 2). Demiguise: virginkey.js. Retrieved January 17, 2019.
* https://github.com/nsacyber/Mitigating-Web-Shells -  NSA Cybersecurity Directorate. (n.d.). Mitigating Web Shells. Retrieved July 22, 2021.
* https://github.com/putterpanda/mimikittenz - Jamieson O'Reilly (putterpanda). (2016, July 4). mimikittenz. Retrieved June 20, 2019.
* https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh - undefined. (n.d.). Retrieved April 12, 2019.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md - Red Canary - Atomic Red Team. (n.d.). T1053.005 - Scheduled Task/Job: Scheduled Task. Retrieved June 19, 2024.
* https://github.com/ryhanson/phishery - Ryan Hanson. (2016, September 24). phishery. Retrieved October 23, 2020.
* https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/blob/9aa9181e/src/grd-settings.c#L207 - Pascal Nowack. (n.d.). Retrieved September 21, 2021.
* https://gitlab.gnome.org/GNOME/gnome-remote-desktop/-/blob/9aa9181e/src/org.gnome.desktop.remote-desktop.gschema.xml.in - Pascal Nowack. (n.d.). Retrieved September 21, 2021.
* https://giuliocomi.blogspot.com/2019/10/abusing-windows-10-narrators-feedback.html - Comi, G. (2019, October 19). Abusing Windows 10 Narrator's 'Feedback-Hub' URI for Fileless Persistence. Retrieved April 28, 2020.
* https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf - CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.
* https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/ - GrimHacker. (2017, July 24). Office365 ActiveSync Username Enumeration. Retrieved December 9, 2021.
* https://help.realvnc.com/hc/en-us/articles/360002250097-Setting-up-System-Authentication - Tegan. (2019, August 15). Setting up System Authentication. Retrieved September 20, 2021.
* https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf - Blaich, A., et al. (2018, January 18). Dark Caracal: Cyber-espionage at a Global Scale. Retrieved April 11, 2018.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://int0x33.medium.com/day-70-hijacking-vnc-enum-brute-access-and-crack-d3d18a4601cc - Z3RO. (2019, March 10). Day 70: Hijacking VNC (Enum, Brute, Access and Crack). Retrieved September 20, 2021.
* https://jon-gabilondo-angulo-7635.medium.com/how-to-inject-code-into-mach-o-apps-part-ii-ddb13ebc8191 - Jon Gabilondo. (2019, September 22). How to Inject Code into Mach-O Apps. Part II.. Retrieved March 24, 2021.
* https://jumpcloud.com/support/get-started-conditional-access-policies - JumpCloud. (n.d.). Get Started: Conditional Access Policies. Retrieved January 2, 2024.
* https://krebsonsecurity.com/2013/10/adobe-to-announce-source-code-customer-data-breach/ - Brian Krebs. (2013, October 3). Adobe To Announce Source Code, Customer Data Breach. Retrieved May 17, 2021.
* https://krebsonsecurity.com/2018/11/that-domain-you-forgot-to-renew-yeah-its-now-stealing-credit-cards/ - Krebs, B. (2018, November 13). That Domain You Forgot to Renew? Yeah, it’s Now Stealing Credit Cards. Retrieved September 20, 2019.
* https://krebsonsecurity.com/2023/05/discord-admins-hacked-by-malicious-bookmarks/ - Brian Krebs. (2023, May 30). Discord Admins Hacked by Malicious Bookmarks. Retrieved January 2, 2024.
* https://kubernetes.io/docs/concepts/security/service-accounts/ - Kubernetes. (n.d.). Service Accounts. Retrieved July 14, 2023.
* https://kubernetes.io/docs/reference/access-authn-authz/authorization/ - Kubernetes. (n.d.). Authorization Overview. Retrieved June 24, 2021.
* https://labs.detectify.com/2016/04/28/slack-bot-token-leakage-exposing-business-critical-information/ - Detectify. (2016, April 28). Slack bot token leakage exposing business critical information. Retrieved October 19, 2020.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://learn.microsoft.com/en-us/azure/active-directory/devices/concept-primary-refresh-token - Microsoft. (2022, September 9). What is a Primary Refresh Token?. Retrieved February 21, 2023.
* https://learn.microsoft.com/en-us/entra/identity/conditional-access/overview - Microsoft. (2023, November 15). What is Conditional Access?. Retrieved January 2, 2024.
* https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules - Microsoft. (2023, February 22). Mail flow rules (transport rules) in Exchange Online. Retrieved March 13, 2023.
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services - Microsoft. (2017, April 9). Allow log on through Remote Desktop Services. Retrieved August 5, 2024.
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11) - Microsoft. (2016, August 31). Net Localgroup. Retrieved August 5, 2024.
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11) - Microsoft. (2016, August 31). Net group. Retrieved August 5, 2024.
* https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-duplicatetoken - Microsoft. (2021, October 12). DuplicateToken function (securitybaseapi.h). Retrieved January 8, 2024.
* https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonuserw - Microsoft. (2023, March 10). LogonUserW function (winbase.h). Retrieved January 8, 2024.
* https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/winrm/portal - Microsoft. (n.d.). Windows Remote Management. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page?redirectedfrom=MSDN - Microsoft. (2023, March 7). Retrieved February 13, 2024.
* https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedcommand-base64encodedcommand - Microsoft. (2023, February 8). about_PowerShell_exe: EncodedCommand. Retrieved March 17, 2023.
* https://linux.die.net/man/1/bash - die.net. (n.d.). bash(1) - Linux man page. Retrieved June 12, 2020.
* https://linux.die.net/man/1/groups - MacKenzie, D. and Youngman, J. (n.d.). groups(1) - Linux man page. Retrieved January 11, 2024.
* https://linux.die.net/man/1/id - MacKenzie, D. and Robbins, A. (n.d.). id(1) - Linux man page. Retrieved January 11, 2024.
* https://lists.openstack.org/pipermail/openstack/2013-December/004138.html - Jay Pipes. (2013, December 23). Security Breach! Tenant A is seeing the VNC Consoles of Tenant B!. Retrieved September 12, 2024.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://lolbas-project.github.io/lolbas/Binaries/Diantz/ - Living Off The Land Binaries, Scripts and Libraries (LOLBAS). (n.d.). Diantz.exe. Retrieved October 25, 2021.
* https://lolbas-project.github.io/lolbas/Binaries/Esentutl/ - LOLBAS. (n.d.). Esentutl.exe. Retrieved September 3, 2019.
* https://lolbas-project.github.io/lolbas/Binaries/Mshta/ - LOLBAS. (n.d.). Mshta.exe. Retrieved July 31, 2019.
* https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF - Australian Cyber Security Centre. National Security Agency. (2020, April 21). Detect and Prevent Web Shell Malware. Retrieved February 9, 2024.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/20134940/kaspersky-lab-gauss.pdf - Kaspersky Lab. (2012, August). Gauss: Abnormal Distribution. Retrieved January 17, 2019.
* https://medium.com/@galolbardes/learn-how-easy-is-to-bypass-firewalls-using-dns-tunneling-and-also-how-to-block-it-3ed652f4a000 - Galobardes, R. (2018, October 30). Learn how easy is to bypass firewalls using DNS tunneling (and also how to block it). Retrieved March 15, 2020.
* https://medium.com/@yvyuz/a-death-match-of-domain-generation-algorithms-a5b5dbdc1c6e - Liu, H. and Yuzifovich, Y. (2018, January 9). A Death Match of Domain Generation Algorithms. Retrieved February 18, 2019.
* https://medium.com/cloudsploit/the-danger-of-unused-aws-regions-af0bf1b878fc - CloudSploit. (2019, June 8). The Danger of Unused AWS Regions. Retrieved October 8, 2019.
* https://medium.com/palantir/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63 - Palantir. (2018, December 24). Tampering with Windows Event Tracing: Background, Offense, and Defense. Retrieved June 7, 2019.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-lateral-movement-using-sysmon-and-splunk-318d3be141bc - French, D. (2018, September 30). Detecting Lateral Movement Using Sysmon and Splunk. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://msdn.microsoft.com/en-US/library/aa375365 - Microsoft. (n.d.). Manifests. Retrieved December 5, 2014.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/en-us/library/windows/desktop/aa446617(v=vs.85).aspx - Microsoft TechNet. (n.d.). Retrieved April 25, 2017.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://msdn.microsoft.com/library/ms677949.aspx - Microsoft. (n.d.). Service Principal Names. Retrieved March 22, 2018.
* https://msdn.microsoft.com/library/system.diagnostics.eventlog.clear.aspx - Microsoft. (n.d.). EventLog.Clear Method (). Retrieved July 2, 2018.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms649053.aspx - Microsoft. (n.d.). About Atom Tables. Retrieved December 8, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://msdn.microsoft.com/library/windows/desktop/ms681951.aspx - Microsoft. (n.d.). Asynchronous Procedure Calls. Retrieved December 8, 2017.
* https://msdn.microsoft.com/windows/desktop/ms524405 - Microsoft. (n.d.). About the HTML Help Executable Program. Retrieved October 3, 2018.
* https://msdn.microsoft.com/windows/desktop/ms644670 - Microsoft. (n.d.). HTML Help ActiveX Control Overview. Retrieved October 3, 2018.
* https://nakedsecurity.sophos.com/2020/10/02/serious-security-phishing-without-links-when-phishers-bring-along-their-own-web-pages/ - Ducklin, P. (2020, October 2). Serious Security: Phishing without links – when phishers bring along their own web pages. Retrieved October 20, 2020.
* https://nodejs.org/ - OpenJS Foundation. (n.d.). Node.js. Retrieved June 23, 2020.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2017-0176 - National Vulnerability Database. (2017, June 22). CVE-2017-0176 Detail. Retrieved April 3, 2018.
* https://o365blog.com/post/federation-vulnerability/ - Dr. Nestori Syynimaa. (2017, November 16). Security vulnerability in Azure AD & Office 365 identity federation. Retrieved September 28, 2022.
* https://objective-see.com/blog/blog_0x25.html - Patrick Wardle. (n.d.). Retrieved March 20, 2018.
* https://oddvar.moe/2017/08/13/bypassing-device-guard-umci-using-chm-cve-2017-8625/ - Moe, O. (2017, August 13). Bypassing Device guard UMCI using CHM – CVE-2017-8625. Retrieved October 3, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ - de Plaa, C. (2019, June 19). Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR. Retrieved September 29, 2021.
* https://owasp.org/www-community/attacks/CSV_Injection -  Albinowax Timo Goosen. (n.d.). CSV Injection. Retrieved February 7, 2022.
* https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-014_Vulnerability_Scanning - OWASP. (n.d.). OAT-014 Vulnerability Scanning. Retrieved October 20, 2020.
* https://pdfs.semanticscholar.org/2721/3d206bc3c1e8c229fb4820b6af09e7f975da.pdf - Song, C., et al. (2012, August 7). Impeding Automated Malware Analysis with Environment-sensitive Malware. Retrieved January 18, 2019.
* https://pentestlab.blog/2012/10/30/attacking-vnc-servers/ - Administrator, Penetration Testing Lab. (2012, October 30). Attacking VNC Servers. Retrieved October 6, 2021.
* https://pentestlab.blog/2017/04/03/token-manipulation/ - netbiosX. (2017, April 3). Token Manipulation. Retrieved April 21, 2017.
* https://permiso.io/blog/lucr-3-scattered-spider-getting-saas-y-in-the-cloud - Ian Ahl. (2023, September 20). LUCR-3: SCATTERED SPIDER GETTING SAAS-Y IN THE CLOUD. Retrieved September 25, 2023.
* https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-8625 - Microsoft. (2017, August 8). CVE-2017-8625 - Internet Explorer Security Feature Bypass Vulnerability. Retrieved October 3, 2018.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://portswigger.net/daily-swig/mfa-fatigue-attacks-users-tricked-into-allowing-device-access-due-to-overload-of-push-notifications - Jessica Haworth. (2022, February 16). MFA fatigue attacks: Users tricked into allowing device access due to overload of push notifications. Retrieved March 31, 2022.
* https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944 - Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.
* https://posts.specterops.io/head-in-the-clouds-bd038bb69e48 - Maddalena, C.. (2018, September 12). Head in the Clouds. Retrieved October 4, 2019.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5 - Pitt, L. (2020, August 6). Persistent JXA. Retrieved April 14, 2021.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://powershellmagazine.com/2014/07/16/investigating-powershell-attacks/ - Hastings, M. (2014, July 16). Investigating PowerShell Attacks. Retrieved December 1, 2021.
* https://ptylu.github.io/content/report/report.html?report=25 - Heiligenstein, L. (n.d.). REP-25: Disable Windows Event Logging. Retrieved April 7, 2022.
* https://redcanary.com/blog/clipping-silver-sparrows-wings/ - Tony Lambert. (2021, February 18). Clipping Silver Sparrow’s wings: Outing macOS malware before it takes flight. Retrieved April 20, 2021.
* https://redcanary.com/blog/rclone-mega-extortion/ - Justin Schoenfeld, Aaron Didier. (2021, May 4). Transferring leverage in a ransomware attack. Retrieved July 14, 2022.
* https://redcanary.com/threat-detection-report/techniques/powershell/ - Red Canary. (n.d.). 2022 Threat Detection Report: PowerShell. Retrieved March 17, 2023.
* https://redsiege.com/kerberoast-slides - Medin, T. (2014, November). Attacking Kerberos - Kicking the Guard Dog of Hades. Retrieved March 22, 2018.
* https://reinforce.awsevents.com/content/dam/reinforce/2024/slides/TDR432_New-tactics-and-techniques-for-proactive-threat-detection.pdf - Ben Fletcher and Steve de Vera. (2024, June). New tactics and techniques for proactive threat detection. Retrieved September 25, 2024.
* https://researchcenter.paloaltonetworks.com/2016/06/unit42-prince-of-persia-game-over/ - Bar, T., Conant, S., Efraim, L. (2016, June 28). Prince of Persia – Game Over. Retrieved July 5, 2017.
* https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/ - Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/ - Spencer Gietzen. (n.d.). AWS IAM Privilege Escalation – Methods and Mitigation. Retrieved May 27, 2022.
* https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/ - Gietzen, S. (n.d.). S3 Ransomware Part 1: Attack Vector. Retrieved April 14, 2021.
* https://rhinosecuritylabs.com/gcp/google-cloud-platform-gcp-bucket-enumeration/ - Spencer Gietzen. (2019, February 26). Google Cloud Platform (GCP) Bucket Enumeration and Privilege Escalation. Retrieved March 4, 2022.
* https://rootdse.org/posts/monitoring-realtime-activedirectory-domain-scenarios - Scarred Monk. (2022, May 6). Real-time detection scenarios in Active Directory environments. Retrieved August 5, 2024.
* https://s7d2.scene7.com/is/content/cylance/prod/cylance-web/en-us/resources/knowledge-center/resource-library/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved December 22, 2021.
* https://sarah-edwards-xzkc.squarespace.com/blog/2020/4/30/analysis-of-apple-unified-logs-quarantine-edition-entry-6-working-from-home-remote-logins - Sarah Edwards. (2020, April 30). Analysis of Apple Unified Logs: Quarantine Edition [Entry 6] – Working From Home? Remote Logins. Retrieved August 19, 2021.
* https://sec.okta.com/articles/2023/08/cross-tenant-impersonation-prevention-and-detection - Okta Defensive Cyber Operations. (2023, August 31). Cross-Tenant Impersonation: Prevention and Detection. Retrieved February 15, 2024.
* https://securelist.com/lazarus-threatneedle/100803/ - Vyacheslav Kopeytsev and Seongsu Park. (2021, February 25). Lazarus targets defense industry with ThreatNeedle. Retrieved October 27, 2021.
* https://securelist.com/lazarus-under-the-hood/77908/ - GReAT. (2017, April 3). Lazarus Under the Hood. Retrieved April 17, 2019.
* https://securelist.com/old-malware-tricks-to-bypass-detection-in-the-age-of-big-data/78010/ - Ishimaru, S.. (2017, April 13). Old Malware Tricks To Bypass Detection in the Age of Big Data. Retrieved May 30, 2019.
* https://securelist.com/project-tajmahal/90240/ - GReAT. (2019, April 10). Project TajMahal – a sophisticated new APT framework. Retrieved October 14, 2019.
* https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/ - Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securityintelligence.com/posts/brazking-android-malware-upgraded-targeting-brazilian-banks/ - Shahar Tavor. (n.d.). BrazKing Android Malware Upgraded and Targeting Brazilian Banks. Retrieved March 24, 2023.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://shodan.io - Shodan. (n.d.). Shodan. Retrieved October 20, 2020.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://social.technet.microsoft.com/wiki/contents/articles/717.service-principal-names-spns-setspn-syntax-setspn-exe.aspx - Microsoft. (2010, April 13). Service Principal Names (SPNs) SetSPN Syntax (Setspn.exe). Retrieved March 22, 2018.
* https://stackoverflow.com/questions/2913816/how-to-find-the-location-of-the-scheduled-tasks-folder - Stack Overflow. (n.d.). How to find the location of the Scheduled Tasks folder. Retrieved June 19, 2024.
* https://stealthbits.com/blog/how-to-detect-overpass-the-hash-attacks/ - Warren, J. (2019, February 26). How to Detect Overpass-the-Hash Attacks. Retrieved February 4, 2021.
* https://support.apple.com/HT208050 - Apple. (2020, January 28). Use zsh as the default shell on your Mac. Retrieved June 12, 2020.
* https://support.apple.com/guide/mail/use-rules-to-manage-emails-you-receive-mlhlp1017/mac - Apple. (n.d.). Use rules to manage emails you receive in Mail on Mac. Retrieved June 14, 2021.
* https://support.apple.com/guide/remote-desktop/set-up-a-computer-running-vnc-software-apdbed09830/mac - Apple Support. (n.d.). Set up a computer running VNC software for Remote Desktop. Retrieved August 18, 2021.
* https://support.google.com/chrome/a/answer/7349337 - Chrome Enterprise and Education Help. (n.d.). Use Chrome Browser with Roaming User Profiles. Retrieved March 28, 2023.
* https://support.google.com/chrome/answer/1649523 - Google. (n.d.). Retrieved March 14, 2024.
* https://support.microsoft.com/en-us/office/manage-email-messages-by-using-rules-c24f5dea-9465-4df4-ad17-a50704d66c59 - Microsoft. (n.d.). Manage email messages by using rules. Retrieved June 11, 2021.
* https://support.office.com/en-us/article/add-another-admin-f693489f-9f55-4bd0-a637-a81ce93de22d - Microsoft. (n.d.). Add Another Admin. Retrieved October 18, 2019.
* https://support.office.com/en-us/article/configure-audit-settings-for-a-site-collection-a9920c97-38c0-44f2-8bcb-4cf1e2ae22d2 - Microsoft. (2017, July 19). Configure audit settings for a site collection. Retrieved April 4, 2018.
* https://support.okta.com/help/s/article/Conditional-access-based-on-device-security-posture?language=en_US - Okta. (2023, November 30). Conditional Access Based on Device Security Posture. Retrieved January 2, 2024.
* https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/wastedlocker-ransomware-us - Symantec Threat Intelligence. (2020, June 25). WastedLocker: Symantec Identifies Wave of Attacks Against U.S. Organizations. Retrieved May 20, 2021.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-ransomware-attacks-against-microsoft-defender/ba-p/1928947 - Tran, T. (2020, November 24). Demystifying Ransomware Attacks Against Microsoft Defender Solution. Retrieved January 26, 2022.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://techcommunity.microsoft.com/t5/security-compliance-and-identity/rule-your-inbox-with-microsoft-cloud-app-security/ba-p/299154 - Niv Goldenberg. (2018, December 12). Rule your inbox with Microsoft Cloud App Security. Retrieved June 7, 2021.
* https://techcommunity.microsoft.com/t5/windows-it-pro-blog/wmi-command-line-wmic-utility-deprecation-next-steps/ba-p/4039242 - Microsoft. (2024, January 26). WMIC Deprecation. Retrieved February 13, 2024.
* https://techcrunch.com/2019/08/12/iphone-charging-cable-hack-computer-def-con/ - Zack Whittaker. (2019, August 12). This hacker’s iPhone charging cable can hijack your computer. Retrieved May 25, 2022.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc772408.aspx - Microsoft. (n.d.). Services. Retrieved June 7, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windows-server-docs/identity/ad-ds/manage/component-updates/command-line-process-auditing - Mathers, B. (2017, March 7). Command line process auditing. Retrieved April 21, 2017.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/cc770880.aspx - Microsoft. (n.d.). Share a Folder or Drive. Retrieved June 30, 2017.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://theevilbit.github.io/posts/dyld_insert_libraries_dylib_injection_in_macos_osx_deep_dive/ - Fitzl, C. (2019, July 9). DYLD_INSERT_LIBRARIES DYLIB injection in macOS / OSX. Retrieved March 26, 2020.
* https://thehackernews.com/2022/05/avoslocker-ransomware-variant-using-new.html - Lakshmanan, R. (2022, May 2). AvosLocker Ransomware Variant Using New Trick to Disable Antivirus Protection. Retrieved May 17, 2022.
* https://themittenmac.com/what-does-apt-activity-look-like-on-macos/ - Jaron Bradley. (2021, November 14). What does APT Activity Look Like on macOS?. Retrieved January 19, 2022.
* https://therecord.media/fbi-fin7-hackers-target-us-companies-with-badusb-devices-to-install-ransomware/ - The Record. (2022, January 7). FBI: FIN7 hackers target US companies with BadUSB devices to install ransomware. Retrieved January 14, 2022.
* https://therecord.media/russian-hackers-bypass-2fa-by-annoying-victims-with-repeated-push-notifications/ - Catalin Cimpanu. (2021, December 9). Russian hackers bypass 2FA by annoying victims with repeated push notifications. Retrieved March 31, 2022.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://threatpost.com/facebook-launching-pad-phishing-attacks/160351/ - O'Donnell, L. (2020, October 20). Facebook: A Top Launching Pad For Phishing Attacks. Retrieved October 20, 2020.
* https://tools.cisco.com/security/center/resources/integrity_assurance.html#23 - Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.
* https://trustedsec.com/blog/to-oob-or-not-to-oob-why-out-of-band-communications-are-essential-for-incident-response - Tyler Hudak. (2022, December 29). To OOB, or Not to OOB?: Why Out-of-Band Communications are Essential for Incident Response. Retrieved August 30, 2024.
* https://umbrella.cisco.com/blog/2016/10/10/domain-generation-algorithms-effective/ - Scarfo, A. (2016, October 10). Domain Generation Algorithms – Why so effective?. Retrieved February 18, 2019.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/attackers-tactics-and-techniques-in-unsecured-docker-daemons-revealed/ - Chen, J.. (2020, January 29). Attacker's Tactics and Techniques in Unsecured Docker Daemons Revealed. Retrieved March 31, 2021.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://unit42.paloaltonetworks.com/examining-vba-initiated-infostealer-campaign/ - Vicky Ray and Rob Downs. (2014, October 29). Examining a VBA-Initiated Infostealer Campaign. Retrieved March 13, 2023.
* https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/ - Chen, J. et al. (2021, February 3). Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes. Retrieved April 5, 2021.
* https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/ - Chen, Y., Hu, W., Xu, Z., et. al. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.
* https://unit42.paloaltonetworks.com/threat-brief-understanding-domain-generation-algorithms-dga/ - Unit 42. (2019, February 7). Threat Brief: Understanding Domain Generation Algorithms (DGA). Retrieved February 19, 2019.
* https://unit42.paloaltonetworks.com/unit42-sofacy-continues-global-attacks-wheels-new-cannon-trojan/ - Falcone, R., Lee, B.. (2018, November 20). Sofacy Continues Global Attacks and Wheels Out New ‘Cannon’ Trojan. Retrieved April 23, 2019.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa21-008a - CISA. (2021, January 8). Detecting Post-Compromise Threat Activity in Microsoft Cloud Environments. Retrieved January 8, 2021.
* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a - CISA. (2021, May 6). Analysis Report (AR21-126A) FiveHands Ransomware. Retrieved June 7, 2021.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://wald0.com/?p=179 - Robbins, A. (2018, April 2). A Red Teamer’s Guide to GPOs and OUs. Retrieved March 5, 2019.
* https://web.archive.org/web/20141031134104/http://kasperskycontenthub.com/wp-content/uploads/sites/43/vlpdfs/unveilingthemask_v1.0.pdf - Kaspersky Labs. (2014, February 11). Unveiling “Careto” - The Masked APT. Retrieved July 5, 2017.
* https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://web.archive.org/web/20160327101330/http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* https://web.archive.org/web/20170923102302/https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://web.archive.org/web/20171223000420/https://www.riskiq.com/blog/labs/lazarus-group-cryptocurrency/ - RISKIQ. (2017, December 20). Mining Insights: Infrastructure Analysis of Lazarus Group Cyber Attacks on the Cryptocurrency Industry. Retrieved July 29, 2022.
* https://web.archive.org/web/20190508170150/https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://web.archive.org/web/20210708014107/https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.
* https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf - PwC and BAE Systems. (2017, April). Operation Cloud Hopper. Retrieved April 5, 2017.
* https://web.archive.org/web/20220527112908/https://www.riskiq.com/blog/labs/ukraine-malware-infrastructure/ - RISKIQ. (2022, March 15). RiskIQ Threat Intelligence Roundup: Campaigns Targeting Ukraine and Global Malware Infrastructure. Retrieved July 29, 2022.
* https://web.archive.org/web/20220629230035/https://www.prevailion.com/darkwatchman-new-fileless-techniques/ - Smith, S., Stafford, M. (2021, December 14). DarkWatchman: A new evolution in fileless techniques. Retrieved January 10, 2022.
* https://web.archive.org/web/20230602111604/https://www.opm.gov/cybersecurity/cybersecurity-incidents/ - Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved September 16, 2024.
* https://wunderwuzzi23.github.io/blog/passthecookie.html - Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.akamai.com/blog/security/catch-me-if-you-can-javascript-obfuscation - Katz, O. (2020, October 26). Catch Me if You Can—JavaScript Obfuscation. Retrieved March 17, 2023.
* https://www.anomali.com/blog/rocke-evolves-its-arsenal-with-a-new-malware-family-written-in-golang - Anomali Labs. (2019, March 15). Rocke Evolves Its Arsenal With a New Malware Family Written in Golang. Retrieved April 24, 2019.
* https://www.attackify.com/blog/rundll32_execution_order/ - Attackify. (n.d.). Rundll32.exe Obscurity. Retrieved August 23, 2021.
* https://www.avertium.com/resources/threat-reports/everything-you-need-to-know-about-callback-phishing - Avertium. (n.d.). EVERYTHING YOU NEED TO KNOW ABOUT CALLBACK PHISHING. Retrieved February 2, 2023.
* https://www.baeldung.com/linux/ld_preload-trick-what-is - baeldung. (2020, August 9). What Is the LD_PRELOAD Trick?. Retrieved March 24, 2021.
* https://www.bbc.com/news/technology-60933174 - Joe Tidy. (2022, March 30). Ronin Network: What a $600m hack says about the state of crypto. Retrieved August 18, 2023.
* https://www.blackhat.com/docs/eu-15/materials/eu-15-Pierce-Defending-Against-Malicious-Application-Compatibility-Shims-wp.pdf - Pierce, Sean. (2015, November). Defending Against Malicious Application Compatibility Shims. Retrieved June 22, 2017.
* https://www.blackhat.com/docs/eu-17/materials/eu-17-Atkinson-A-Process-Is-No-One-Hunting-For-Token-Manipulation.pdf - Atkinson, J., Winchester, R. (2017, December 7). A Process is No One: Hunting for Token Manipulation. Retrieved December 21, 2017.
* https://www.blackhat.com/presentations/bh-dc-08/McFeters-Rios-Carter/Presentation/bh-dc-08-mcfeters-rios-carter.pdf - Nathan McFeters. Billy Kim Rios. Rob Carter.. (2008). URI Use and Abuse. Retrieved February 9, 2024.
* https://www.blackhillsinfosec.com/bypass-web-proxy-filtering/ - Fehrman, B. (2017, April 13). How to Bypass Web-Proxy Filtering. Retrieved September 20, 2019.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.bleepingcomputer.com/news/security/dozens-of-vnc-vulnerabilities-found-in-linux-windows-solutions/ - Sergiu Gatlan. (2019, November 22). Dozens of VNC Vulnerabilities Found in Linux, Windows Solutions. Retrieved September 20, 2021.
* https://www.bleepingcomputer.com/news/security/new-godlua-malware-evades-traffic-monitoring-via-dns-over-https/ - Gatlan, S. (2019, July 3). New Godlua Malware Evades Traffic Monitoring via DNS over HTTPS. Retrieved March 15, 2020.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.broadcom.com/support/security-center/protection-bulletin/birdyclient-malware-leverages-microsoft-graph-api-for-c-c-communication - Broadcom. (2024, May 2). BirdyClient malware leverages Microsoft Graph API for C&C communication. Retrieved July 1, 2024.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/ - Baskin, B. (2020, July 8). TAU Threat Discovery: Conti Ransomware. Retrieved February 17, 2021.
* https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a - CISA. (2021, April 15). Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations. Retrieved August 30, 2024.
* https://www.cisa.gov/sites/default/files/Ransomware_Trifold_e-version.pdf - FBI. (n.d.). Ransomware. Retrieved August 18, 2023.
* https://www.cisa.gov/uscert/ncas/alerts/aa22-074a - Cyber Security Infrastructure Agency. (2022, March 15). Russian State-Sponsored Cyber Actors Gain Network Access by Exploiting Default Multifactor Authentication Protocols and “PrintNightmare” Vulnerability. Retrieved May 31, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/C_commands.html#wp1068167689 - Cisco. (2022, August 16). copy - Cisco IOS Configuration Fundamentals Command Reference . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_protocols_through_showmon.html#wp2760878733 - Cisco. (2022, August 16). show running-config - Cisco IOS Configuration Fundamentals Command Reference . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_conn_pki/configuration/xe-17/sec-pki-xe-17-book/sec-deploy-rsa-pki.html#GUID-1CB802D8-9DE3-447F-BECE-CF22F5E11436 - Cisco. (2023, February 17). Chapter: Deploying RSA Keys Within a PKI . Retrieved March 27, 2023.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html - Cisco. (2023, March 7). Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-t2.html#wp1047035630 - Cisco. (2023, March 6). username - Cisco IOS Security Command Reference: Commands S to Z. Retrieved July 13, 2022.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.clearskysec.com/wp-content/uploads/2021/01/Lebanese-Cedar-APT.pdf - ClearSky Cyber Security. (2021, January). “Lebanese Cedar” APT Global Lebanese Espionage Campaign Leveraging Web Servers. Retrieved February 10, 2021.
* https://www.cloudflare.com/learning/email-security/what-is-vendor-email-compromise/#:~:text=Vendor%20email%20compromise%2C%20also%20referred,steal%20from%20that%20vendor%27s%20customers. - CloudFlare. (n.d.). What is vendor email compromise (VEC)?. Retrieved September 12, 2023.
* https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/ - Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.
* https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/ - Mudge, R. (2017, February 6). High-reputation Redirectors and Domain Fronting. Retrieved July 11, 2022.
* https://www.commandfive.com/papers/C5_APT_SKHack.pdf - Command Five Pty Ltd. (2011, September). SK Hack by an Advanced Persistent Threat. Retrieved April 6, 2018.
* https://www.computerworld.com/article/2486903/windows-malware-tries-to-infect-android-devices-connected-to-pcs.html - Lucian Constantin. (2014, January 23). Windows malware tries to infect Android devices connected to PCs. Retrieved May 25, 2022.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.crowdstrike.com/blog/4-ways-adversaries-hijack-dlls/ - CrowdStrike, Falcon OverWatch Team. (2022, December 30). Retrieved October 19, 2023.
* https://www.crowdstrike.com/blog/double-trouble-ransomware-data-leak-extortion-part-1/ - Crowdstrike. (2020, September 24). Double Trouble: Ransomware with Data Leak Extortion, Part 1. Retrieved December 6, 2023.
* https://www.crowdstrike.com/blog/hidden-administrative-accounts-bloodhound-to-the-rescue/ - Red Team Labs. (2018, April 24). Hidden Administrative Accounts: BloodHound to the Rescue. Retrieved October 28, 2020.
* https://www.crowdstrike.com/blog/how-crowdstrike-falcon-protects-against-wiper-malware-used-in-ukraine-attacks/ - Thomas, W. et al. (2022, February 25). CrowdStrike Falcon Protects from New Wiper Malware Used in Ukraine Cyberattacks. Retrieved March 25, 2022.
* https://www.crowdstrike.com/blog/how-doppelpaymer-hunts-and-kills-windows-processes/ - Hurley, S. (2021, December 7). Critical Hit: How DoppelPaymer Hunts and Kills Windows Processes. Retrieved January 26, 2022.
* https://www.crowdstrike.com/blog/http-iframe-injecting-linux-rootkit/ - Kurtz, G. (2012, November 19). HTTP iframe Injecting Linux Rootkit. Retrieved December 21, 2017.
* https://www.crowdstrike.com/blog/lemonduck-botnet-targets-docker-for-cryptomining-operations/ - Manoj Ahuje. (2022, April 21). LemonDuck Targets Docker for Cryptomining Operations. Retrieved June 30, 2022.
* https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/ - CrowdStrike. (2022, January 27). Early Bird Catches the Wormhole: Observations from the StellarParticle Campaign. Retrieved February 7, 2022.
* https://www.crowdstrike.com/blog/targeted-dharma-ransomware-intrusions-exhibit-consistent-techniques/ - Loui, E. Scheuerman, K. et al. (2020, April 16). Targeted Dharma Ransomware Intrusions Exhibit Consistent Techniques. Retrieved January 26, 2022.
* https://www.crowdstrike.com/cybersecurity-101/business-email-compromise-bec/ - Bart Lenaerts-Bergmans. (2023, March 10). What is Business Email Compromise?. Retrieved August 8, 2023.
* https://www.cyberbit.com/blog/endpoint-security/new-early-bird-code-injection-technique-discovered/ - Gavriel, H. & Erbesfeld, B. (2018, April 11). New ‘Early Bird’ Code Injection Technique Discovered. Retrieved May 24, 2018.
* https://www.cynet.com/attack-techniques-hands-on/defense-evasion-techniques/ - Ariel silver. (2022, February 1). Defense Evasion Techniques. Retrieved April 8, 2022.
* https://www.datawire.io/code-injection-on-linux-and-macos/ - Itamar Turner-Trauring. (2017, April 18). “This will only hurt for a moment”: code injection on Linux and macOS with LD_PRELOAD. Retrieved December 20, 2017.
* https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2 - Gilboa, A. (2021, February 16). LSASS Memory Dumps are Stealthier than Ever Before - Part 2. Retrieved December 27, 2023.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.elastic.co/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf - F-Secure Labs. (2015, September 17). The Dukes: 7 years of Russian cyberespionage. Retrieved December 10, 2015.
* https://www.fbi.gov/file-repository/fy-2022-fbi-congressional-report-business-email-compromise-and-real-estate-wire-fraud-111422.pdf/view - FBI. (2022). FBI 2022 Congressional Report on BEC and Real Estate Wire Fraud. Retrieved August 18, 2023.
* https://www.fireeye.com/blog/threat-research/2010/07/malware-persistence-windows-registry.html - Harbour, N. (2010, July 15). Malware Persistence without the Windows Registry. Retrieved November 17, 2020.
* https://www.fireeye.com/blog/threat-research/2010/08/dll-search-order-hijacking-revisited.html - Nick Harbour. (2010, September 1). DLL Search Order Hijacking Revisited. Retrieved March 13, 2020.
* https://www.fireeye.com/blog/threat-research/2011/06/fxsst.html - Harbour, N. (2011, June 3). What the fxsst?. Retrieved November 17, 2020.
* https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-1.html - Glyer, C., Kazanciyan, R. (2012, August 20). The “Hikit” Rootkit: Advanced and Persistent Attack Techniques (Part 1). Retrieved June 6, 2016.
* https://www.fireeye.com/blog/threat-research/2012/12/council-foreign-relations-water-hole-attack-details.html - Kindlund, D. (2012, December 30). CFR Watering Hole Attack Details. Retrieved December 18, 2020.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html - Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html - Berry, A., Galang, L., Jiang, G., Leathery, J., Mohandas, R. (2017, April 11). CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler. Retrieved October 27, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html - Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
* https://www.fireeye.com/blog/threat-research/2017/07/hawkeye-malware-distributed-in-phishing-campaign.html - Swapnil Patil, Yogesh Londhe. (2017, July 25). HawkEye Credential Theft Malware Distributed in Recent Phishing Campaign. Retrieved June 18, 2019.
* https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html - Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/rpt-mtrends-2016.pdf - Mandiant. (2016, February 25). Mandiant M-Trends 2016. Retrieved March 5, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Amanda Steward. (2014). FireEye DLL Side-Loading: A Thorn in the Side of the Anti-Virus Industry. Retrieved March 13, 2020.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.forbes.com/sites/runasandvik/2014/01/14/attackers-scrape-github-for-cloud-service-credentials-hijack-account-to-mine-virtual-currency/#242c479d3196 - Sandvik, R. (2014, January 14). Attackers Scrape GitHub For Cloud Service Credentials, Hijack Account To Mine Virtual Currency. Retrieved October 19, 2020.
* https://www.fortinet.com/blog/psirt-blogs/fg-ir-22-369-psirt-analysis -  Guillaume Lovet and Alex Kong. (2023, March 9). Analysis of FG-IR-22-369. Retrieved May 15, 2023.
* https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html - Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.gnu.org/software/acct/ - GNU. (2010, February 5). The GNU Accounting Utilities. Retrieved December 20, 2017.
* https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/ - Hexacorn. (2013, December 8). Beyond good ol’ Run key, Part 5. Retrieved August 14, 2024.
* https://www.hipaajournal.com/47gb-medical-records-unsecured-amazon-s3-bucket/ - HIPAA Journal. (2017, October 11). 47GB of Medical Records and Test Results Found in Unsecured Amazon S3 Bucket. Retrieved October 4, 2019.
* https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708 - Huntress. (n.d.). Retrieved March 14, 2024.
* https://www.ic3.gov/Media/PDF/AnnualReport/2022_IC3Report.pdf - IC3. (2022). 2022 Internet Crime Report. Retrieved August 18, 2023.
* https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me - Invictus Incident Response. (2024, January 31). The curious case of DangerDev@protonmail.me. Retrieved March 19, 2024.
* https://www.justice.gov/file/1080281/download - Mueller, R. (2018, July 13). Indictment - United States of America vs. VIKTOR BORISOVICH NETYKSHO, et al. Retrieved September 13, 2018.
* https://www.justice.gov/usao-cdca/pr/3-north-korean-military-hackers-indicted-wide-ranging-scheme-commit-cyber-attacks-and - Department of Justice. (2021). 3 North Korean Military Hackers Indicted in Wide-Ranging Scheme to Commit Cyber-attacks and Financial Crimes Across the Globe. Retrieved August 18, 2023.
* https://www.kaspersky.com/blog/browser-data-theft/27871/ - Golubev, S. (n.d.). How malware steals autofill data from browsers. Retrieved March 28, 2023.
* https://www.man7.org/linux/man-pages/man8/ld.so.8.html - Kerrisk, M. (2020, June 13). Linux Programmer's Manual. Retrieved June 15, 2020.
* https://www.man7.org/linux/man-pages/man8/usermod.8.html - Man7. (n.d.). Usermod. Retrieved August 5, 2024.
* https://www.mandiant.com/media/17826 - Mandiant. (n.d.). APT42: Crooked Charms, Cons and Compromise. Retrieved September 16, 2022.
* https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits - Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022.
* https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem - Marvi, A. et al.. (2023, March 16). Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation. Retrieved March 22, 2023.
* https://www.mandiant.com/resources/blog/ransomware-extortion-ot-docs - DANIEL KAPELLMANN ZAFRA, COREY HIDELBRANDT, NATHAN BRUBAKER, KEITH LUNDEN. (2022, January 31). 1 in 7 OT Ransomware Extortion Attacks Leak Critical Operational Technology Information. Retrieved August 18, 2023.
* https://www.mandiant.com/resources/blog/unc3524-eye-spy-email - Mandiant. (2022, May 2). UNC3524: Eye Spy on Your Email. Retrieved August 17, 2023.
* https://www.mandiant.com/resources/blog/unc3944-sms-phishing-sim-swapping-ransomware - Mandiant Intelligence. (2023, September 14). Why Are You Texting Me? UNC3944 Leverages SMS Phishing Campaigns for SIM Swapping, Ransomware, Extortion, and Notoriety. Retrieved January 2, 2024.
* https://www.mandiant.com/resources/blog/url-obfuscation-schema-abuse - Nick Simonian. (2023, May 22). Don't @ Me: URL Obfuscation Through Schema Abuse. Retrieved August 4, 2023.
* https://www.mandiant.com/resources/chasing-avaddon-ransomware - Hernandez, A. S. Tarter, P. Ocamp, E. J. (2022, January 19). One Source to Rule Them All: Chasing AVADDON Ransomware. Retrieved January 26, 2022.
* https://www.mandiant.com/resources/reports - Mandiant. (n.d.). Retrieved February 13, 2024.
* https://www.mandiant.com/resources/russian-targeting-gov-business - Luke Jenkins, Sarah Hawley, Parnian Najafi, Doug Bienstock. (2021, December 6). Suspected Russian Activity Targeting Government and Business Entities Around the Globe. Retrieved April 15, 2022.
* https://www.mandiant.com/sites/default/files/2021-09/mtrends-2020.pdf - Mandiant. (2020, February). M-Trends 2020. Retrieved April 24, 2020.
* https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/ - MDSec Research. (2017, July). Categorisation is not a Security Boundary. Retrieved September 20, 2019.
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - MDSec Research. (2020, December). Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams. Retrieved September 29, 2021.
* https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/ - Dominic Chell. (2021, January 1). macOS Post-Exploitation Shenanigans with VSCode Extensions. Retrieved April 20, 2021.
* https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/ - Microsoft. (2022, June 13). BlackCat. Retrieved February 13, 2024.
* https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/ - Microsoft. (2023, September 22). Malicious OAuth applications abuse cloud email services to spread spam. Retrieved March 13, 2023.
* https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Backdoor:Win32/Lamin.A - Microsoft. (2009, May 17). Backdoor:Win32/Lamin.A. Retrieved September 6, 2018.
* https://www.microsoft.com/security/blog/2016/06/01/hacking-team-breach-a-cyber-jurassic-park/ - Microsoft Secure Team. (2016, June 1). Hacking Team Breach: A Cyber Jurassic Park. Retrieved March 5, 2019.
* https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/ - Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.
* https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/ - Weizman, Y. (2020, April 2). Threat Matrix for Kubernetes. Retrieved March 30, 2021.
* https://www.microsoft.com/security/blog/2021/06/14/behind-the-scenes-of-business-email-compromise-using-cross-domain-threat-data-to-disrupt-a-large-bec-infrastructure/ - Carr, N., Sellmer, S. (2021, June 14). Behind the scenes of business email compromise: Using cross-domain threat data to disrupt a large BEC campaign. Retrieved June 15, 2021.
* https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/ - Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.
* https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/ - Microsoft. (2022, March 22). DEV-0537 criminal actor targeting organizations for data exfiltration and destruction. Retrieved March 23, 2022.
* https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ - Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.
* https://www.mitiga.io/blog/how-mitiga-found-pii-in-exposed-amazon-rds-snapshots - Ariel Szarf, Doron Karmi, and Lionel Saposnik. (n.d.). Oops, I Leaked It Again — How Mitiga Found PII in Exposed Amazon RDS Snapshots. Retrieved September 24, 2024.
* https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2017/august/smuggling-hta-files-in-internet-exploreredge/ - Warren, R. (2017, August 8). Smuggling HTA files in Internet Explorer/Edge. Retrieved January 16, 2019.
* https://www.netskope.com/blog/new-phishing-attacks-exploiting-oauth-authorization-flows-part-1 - Jenko Hwong. (2021, August 10). New Phishing Attacks Exploiting OAuth Authorization Flows (Part 1). Retrieved March 19, 2024.
* https://www.nytimes.com/2021/05/13/technology/colonial-pipeline-ransom.html - Nicole Perlroth. (2021, May 13). Colonial Pipeline paid 75 Bitcoin, or roughly $5 million, to hackers.. Retrieved August 18, 2023.
* https://www.obsidiansecurity.com/blog/behind-the-breach-self-service-password-reset-azure-ad/ - Noah Corradin and Shuyang Wang. (2023, August 1). Behind The Breach: Self-Service Password Reset (SSPR) Abuse in Azure AD. Retrieved March 28, 2024.
* https://www.offensive-security.com/metasploit-unleashed/vnc-authentication/ - Offensive Security. (n.d.). VNC Authentication. Retrieved October 6, 2021.
* https://www.optiv.com/insights/source-zero/blog/microsoft-365-oauth-device-code-flow-and-phishing - Optiv. (2021, August 17). Microsoft 365 OAuth Device Code Flow and Phishing. Retrieved March 19, 2024.
* https://www.owasp.org/index.php/Binary_planting - OWASP. (2013, January 30). Binary planting. Retrieved June 7, 2016.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf - Claud Xiao. (n.d.). WireLurker: A New Era in iOS and OS X Malware. Retrieved July 10, 2017.
* https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling - Palo Alto Networks. (n.d.). What Is DNS Tunneling?. Retrieved March 15, 2020.
* https://www.pcmag.com/news/hackers-try-to-phish-united-nations-staffers-with-fake-login-pages - Kan, M. (2019, October 24). Hackers Try to Phish United Nations Staffers With Fake Login Pages. Retrieved October 20, 2020.
* https://www.proofpoint.com/us/blog/threat-insight/caught-beneath-landline-411-telephone-oriented-attack-delivery - Selena Larson, Sam Scholten, Timothy Kromphardt. (2021, November 4). Caught Beneath the Landline: A 411 on Telephone Oriented Attack Delivery. Retrieved January 5, 2022.
* https://www.proofpoint.com/us/blog/threat-insight/clipboard-compromise-powershell-self-pwn - Tommy Madjar, Dusty Miller, Selena Larson. (2024, June 17). From Clipboard to Compromise: A PowerShell Self-Pwn. Retrieved August 2, 2024.
* https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain - Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.
* https://www.proofpoint.com/us/threat-insight/post/home-routers-under-attack-malvertising-windows-android-devices - Kafeine. (2016, December 13). Home Routers Under Attack via Malvertising on Windows, Android Devices. Retrieved January 16, 2019.
* https://www.proofpoint.com/us/threat-insight/post/new-vega-stealer-shines-brightly-targeted-campaign - Proofpoint. (2018, May 10). New Vega Stealer shines brightly in targeted campaign . Retrieved June 18, 2019.
* https://www.proofpoint.com/us/threat-reference/email-spoofing - Proofpoint. (n.d.). What Is Email Spoofing?. Retrieved February 24, 2023.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/blog/identifying-cobalt-strike-servers - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved September 16, 2024.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.reliaquest.com/blog/new-execution-technique-in-clearfake-campaign/ - Reliaquest. (2024, May 31). New Execution Technique in ClearFake Campaign. Retrieved August 2, 2024.
* https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/ - Joshua Wright. (2020, October 14). Retrieved March 22, 2024.
* https://www.sans.org/blog/red-team-tactics-hiding-windows-services/ - Joshua Wright. (2020, October 13). Retrieved March 22, 2024.
* https://www.sans.org/reading-room/whitepapers/forensics/detecting-malware-sandbox-evasion-techniques-36667 - Keragala, D. (2016, January 16). Detecting Malware and Sandbox Evasion Techniques. Retrieved April 17, 2019.
* https://www.schneier.com/academic/paperfiles/paper-clueless-agents.pdf - Riordan, J., Schneier, B. (1998, June 18). Environmental Key Generation towards Clueless Agents. Retrieved January 18, 2019.
* https://www.scmagazine.com/analysis/ragnar-locker-reminds-breach-victims-it-can-read-the-on-network-incident-response-chat-rooms - Joe Uchill. (2021, December 3). Ragnar Locker reminds breach victims it can read the on-network incident response chat rooms. Retrieved August 30, 2024.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/oauths-device-code-flow-abused-in-phishing-attacks - SecureWorks Counter Threat Unit Research Team. (2021, June 3). OAuth’S Device Code Flow Abused in Phishing Attacks. Retrieved March 19, 2024.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.secureworks.com/research/skeleton-key-malware-analysis - Dell SecureWorks. (2015, January 12). Skeleton Key Malware Analysis. Retrieved April 8, 2019.
* https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/ - Phil Stokes. (2019, December 5). macOS Red Team: Calling Apple APIs Without Building Binaries. Retrieved July 17, 2020.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.sentinelone.com/labs/nullbulge-threat-actor-masquerades-as-hacktivist-group-rebelling-against-ai/ -  Jim Walter. (2024, July 16). NullBulge | Threat Actor Masquerades as Hacktivist Group Rebelling Against AI. Retrieved August 30, 2024.
* https://www.slideshare.net/DennisMaldonado5/sticky-keys-to-the-kingdom - Maldonado, D., McGuffin, T. (2016, August 6). Sticky Keys to the Kingdom. Retrieved July 5, 2017.
* https://www.slideshare.net/kieranjacobsen/lateral-movement-with-power-shell-2 - Jacobsen, K. (2014, May 16). Lateral Movement with PowerShell&#91;slides&#93;. Retrieved November 12, 2014.
* https://www.ssh.com/ssh/tunneling - SSH.COM. (n.d.). SSH tunnel. Retrieved March 15, 2020.
* https://www.stormshield.com/news/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://www.sygnia.co/golden-saml-advisory - Sygnia. (2020, December). Detection and Hunting of Golden SAML Attack. Retrieved January 6, 2021.
* https://www.symantec.com/avcenter/reference/windows.rootkit.overview.pdf - Symantec. (n.d.). Windows Rootkit Overview. Retrieved December 21, 2017.
* https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage - Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf - Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.
* https://www.technologyreview.com/2013/08/21/83143/dropbox-and-similar-services-can-sync-malware/ - David Talbot. (2013, August 21). Dropbox and Similar Services Can Sync Malware. Retrieved May 31, 2023.
* https://www.techtarget.com/searchsecurity/tip/Preparing-for-uniform-resource-identifier-URI-exploits - Michael Cobb. (2007, October 11). Preparing for uniform resource identifier (URI) exploits. Retrieved February 9, 2024.
* https://www.tenable.com/blog/detecting-macos-high-sierra-root-account-without-authentication - Nick Miles. (2017, November 30). Detecting macOS High Sierra root account without authentication. Retrieved September 20, 2021.
* https://www.theguardian.com/games/2022/sep/19/grand-theft-auto-6-leak-who-hacked-rockstar-and-what-was-stolen - Keza MacDonald, Keith Stuart and Alex Hern. (2022, September 19). Grand Theft Auto 6 leak: who hacked Rockstar and what was stolen?. Retrieved August 30, 2024.
* https://www.thepythoncode.com/article/executing-bash-commands-remotely-in-python - Abdou Rockikz. (2020, July). How to Execute Shell Commands in a Remote Machine in Python. Retrieved July 26, 2021.
* https://www.theregister.com/2015/02/28/uber_subpoenas_github_for_hacker_details/ - McCarthy, K. (2015, February 28). FORK ME! Uber hauls GitHub into court to find who hacked database of 50,000 drivers. Retrieved October 19, 2020.
* https://www.theregister.com/2017/09/26/deloitte_leak_github_and_google/ - Thomson, I. (2017, September 26). Deloitte is a sitting duck: Key systems with RDP open, VPN and proxy 'login details leaked'. Retrieved October 19, 2020.
* https://www.tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html - The Linux Documentation Project. (n.d.). Shared Libraries. Retrieved January 31, 2020.
* https://www.trellix.com/blogs/research/beyond-file-search-a-novel-method/ -  Mathanraj Thangaraju, Sijo Jacob. (2023, July 26). Beyond File Search: A Novel Method for Exploiting the "search-ms" URI Protocol Handler. Retrieved March 15, 2024.
* https://www.trendmicro.com/en_us/research/19/e/infected-cryptocurrency-mining-containers-target-docker-hosts-with-exposed-apis-use-shodan-to-find-additional-victims.html - Oliveira, A. (2019, May 30). Infected Containers Target Docker via Exposed APIs. Retrieved April 6, 2021.
* https://www.trendmicro.com/en_us/research/20/d/exposed-redis-instances-abused-for-remote-code-execution-cryptocurrency-mining.html - David Fiser and Jaromir Horejsi. (2020, April 21). Exposed Redis Instances Abused for Remote Code Execution, Cryptocurrency Mining. Retrieved September 25, 2024.
* https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html - Remillano II, A., et al. (2020, June 20). XORDDoS, Kaiji Variants Target Exposed Docker Servers. Retrieved April 5, 2021.
* https://www.trendmicro.com/en_us/research/20/i/tricky-forms-of-phishing.html - Babon, P. (2020, September 3). Tricky 'Forms' of Phishing. Retrieved October 20, 2020.
* https://www.trendmicro.com/en_us/research/20/i/war-of-linux-cryptocurrency-miners-a-battle-for-resources.html - Oliveira, A., Fiser, D. (2020, September 10). War of Linux Cryptocurrency Miners: A Battle for Resources. Retrieved April 6, 2021.
* https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html - Hacquebord, F., Remorin, L. (2020, December 17). Pawn Storm’s Lack of Sophistication as a Strategy. Retrieved January 13, 2021.
* https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/a-misconfigured-amazon-s3-exposed-almost-50-thousand-pii-in-australia - Trend Micro. (2017, November 6). A Misconfigured Amazon S3 Exposed Almost 50 Thousand PII in Australia. Retrieved October 4, 2019.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.us-cert.gov/ncas/alerts/AA18-337A - US-CERT. (2018, December 3). Alert (AA18-337A): SamSam Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.us-cert.gov/ncas/alerts/TA16-091A - US-CERT. (2016, March 31). Alert (TA16-091A): Ransomware and Recent Variants. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-074A - US-CERT. (2018, March 16). Alert (TA18-074A): Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved June 6, 2018.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.virustotal.com/en/faq/ - VirusTotal. (n.d.). VirusTotal FAQ. Retrieved May 23, 2019.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2020/11/06/oceanlotus-extending-cyber-espionage-operations-through-fake-websites/ - Adair, S. and Lancaster, T. (2020, November 6). OceanLotus: Extending Cyber Espionage Operations Through Fake Websites. Retrieved November 20, 2020.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/ - Adair, S., Lancaster, T., Volexity Threat Research. (2022, June 15). DriftingCloud: Zero-Day Sophos Firewall Exploitation and an Insidious Breach. Retrieved July 1, 2022.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/ - ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.
* https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/ - Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf - Kafka, F. (2018, January). ESET's Guide to Deobfuscating and Devirtualizing FinFisher. Retrieved August 12, 2019.
* https://www.welivesecurity.com/wp-content/uploads/2019/08/ESET_Machete.pdf - ESET. (2019, July). MACHETE JUST GOT SHARPER Venezuelan government institutions under attack. Retrieved September 13, 2019.
* https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf - Hromcova, Z. and Cherpanov, A. (2020, June). INVISIMOLE: THE HIDDEN PART OF THE STORY. Retrieved July 16, 2020.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.wired.com/images_blogs/threatlevel/2010/11/w32_stuxnet_dossier.pdf - Nicolas Falliere, Liam O. Murchu, Eric Chien. (2011, February). W32.Stuxnet Dossier. Retrieved December 7, 2020.
* https://www.wired.com/story/magecart-amazon-cloud-hacks/ - Barrett, B.. (2019, July 11). Hack Brief: A Card-Skimming Hacker Group Hit 17K Domains—and Counting. Retrieved October 4, 2019.
* https://www.wired.com/story/pig-butchering-fbi-ic3-2022-report/ - Lily Hay Newman. (n.d.). ‘Pig Butchering’ Scams Are Now a $3 Billion Threat. Retrieved August 18, 2023.
* https://www.wired.com/story/russia-ukraine-cyberattacks-mandiant/ - Greenberg, A. (2022, November 10). Russia’s New Cyberwarfare in Ukraine Is Fast, Dirty, and Relentless. Retrieved March 22, 2023.
* https://www.wired.com/story/uber-paid-off-hackers-to-hide-a-57-million-user-data-breach/ - Andy Greenberg. (2017, January 21). Hack Brief: Uber Paid Off Hackers to Hide a 57-Million User Data Breach. Retrieved May 14, 2021.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www2.fireeye.com/rs/848-DID-242/images/rpt-apt29-hammertoss.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved September 17, 2015.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.
* https://x.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved September 12, 2024.
* https://x.com/TheDFIRReport/status/1498657772254240768 - The DFIR Report. (2022, March 1). "Change RDP port" #ContiLeaks. Retrieved September 12, 2024.
* https://x.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved September 12, 2024.
* https://x.com/rfackroyd/status/1639136000755765254 - Ackroyd, R. (2023, March 24). Twitter. Retrieved September 12, 2024.
* https://xorrior.com/persistent-credential-theft/ - Chris Ross. (2018, October 17). Persistent Credential Theft with Authorization Plugins. Retrieved April 22, 2021.

# Validate the following tools

* AdFind - 2
* BITSAdmin - 1
* CrackMapExec - 1
* Empire - 2
* Impacket - 3
* LaZagne - 1
* Mimikatz - 5
* Net - 2
* Nltest - 1
* PowerSploit - 2
* PsExec - 2
* Windows Credential Editor - 1
* certutil - 2
* dsquery - 2
* ftp - 1
* ngrok - 1
* pwdump - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://cyware.com/news/cyber-attackers-leverage-tunneling-service-to-drop-lokibot-onto-victims-systems-6f610e44 - Cyware. (2019, May 29). Cyber attackers leverage tunneling service to drop Lokibot onto victims’ systems. Retrieved September 15, 2020.
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ftp - Microsoft. (2021, July 21). ftp. Retrieved February 25, 2022.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (2007, August 9). pwdump. Retrieved June 22, 2016.
* https://github.com/AlessandroZ/LaZagne - Zanni, A. (n.d.). The LaZagne Project !!!. Retrieved December 14, 2018.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference - byt3bl33d3r. (2018, September 8). SMB: Command Reference. Retrieved July 17, 2020.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://linux.die.net/man/1/ftp - N/A. (n.d.). ftp(1) - Linux man page. Retrieved February 25, 2022.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://redcanary.com/blog/how-one-hospital-thwarted-a-ryuk-ransomware-outbreak/ - Brian Donohue, Katie Nickels, Paul Michaud, Adina Bodkins, Taylor Chapman, Tony Lambert, Jeff Felling, Kyle Rainey, Mike Haag, Matt Graeber, Aaron Didier.. (2020, October 29). A Bazar start: How one hospital thwarted a Ryuk ransomware outbreak. Retrieved October 30, 2020.
* https://ss64.com/nt/nltest.html - ss64. (n.d.). NLTEST.exe - Network Location Test. Retrieved February 14, 2019.
* https://technet.microsoft.com/en-us/library/cc732952.aspx - Microsoft. (n.d.). Dsquery. Retrieved April 18, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/cc732443.aspx - Microsoft. (2012, November 14). Certutil. Retrieved July 3, 2017.
* https://web.archive.org/web/20150511162820/http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* https://web.archive.org/web/20240904163410/https://www.ampliasecurity.com/research/wcefaq.html - Amplia Security. (n.d.). Windows Credentials Editor (WCE) F.A.Q.. Retrieved September 12, 2024.
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html - Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html - McKeague, B. et al. (2019, April 5). Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware. Retrieved April 17, 2019.
* https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html - Kennelly, J., Goody, K., Shilko, J. (2020, May 7). Navigating the MAZE: Tactics, Techniques and Procedures Associated With MAZE Ransomware Incidents. Retrieved May 18, 2020.
* https://www.malwarebytes.com/resources/files/2021/02/lazyscripter.pdf - Jazi, H. (2021, February). LazyScripter: From Empire to double RAT. Retrieved November 24, 2021.
* https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive/ - Pilkington, M. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://www.secureauth.com/labs/open-source-tools/impacket - SecureAuth. (n.d.).  Retrieved January 15, 2019.
* https://www.zdnet.com/article/sly-malware-author-hides-cryptomining-botnet-behind-ever-shifting-proxy-service/ - Cimpanu, C. (2018, September 13). Sly malware author hides cryptomining botnet behind ever-shifting proxy service. Retrieved September 15, 2020.

# Validate the following malware

* ASPXSpy - 1
* BADHATCH - 1
* BLACKCOFFEE - 1
* BOOSTWRITE - 1
* BlackCat - 1
* Carbanak - 1
* China Chopper - 1
* Cobalt Strike - 3
* DUSTPAN - 1
* DUSTTRAP - 1
* Derusbi - 1
* FlawedAmmyy - 1
* GRIFFON - 1
* GrimAgent - 1
* JSS Loader - 1
* KEYPLUG - 1
* Lizar - 1
* LockerGoga - 1
* MESSAGETAP - 1
* Maze - 2
* More_eggs - 1
* POWERSOURCE - 1
* PUNCHBUGGY - 1
* PUNCHTRACK - 1
* Pillowmint - 1
* PlugX - 1
* RDFSNIFFER - 1
* REvil - 1
* ROCKBOOT - 1
* Ragnar Locker - 1
* Ryuk - 1
* Sardonic - 1
* ShadowPad - 1
* TEXTMATE - 1
* WarzoneRAT - 1
* Winnti for Linux - 1
* ZxShell - 1
* gh0st RAT - 1
* njRAT - 1

# Review the following malware references

* http://blog.morphisec.com/security-alert-fin8-is-back - Gorelik, M.. (2019, June 10). SECURITY ALERT: FIN8 IS BACK IN BUSINESS, TARGETING THE HOSPITALITY INDUSTRY. Retrieved June 13, 2019.
* http://blog.talosintelligence.com/2017/03/dnsmessenger.html - Brumaghin, E. and Grady, C.. (2017, March 2). Covert Channels and Poor Decisions: The Tale of DNSMessenger. Retrieved March 8, 2017.
* http://circl.lu/assets/files/tr-12/tr-12-circl-plugx-analysis-v1.pdf - Computer Incident Response Center Luxembourg. (2013, March 29). Analysis of a PlugX variant. Retrieved November 5, 2018.
* http://labs.lastline.com/an-analysis-of-plugx - Vasilenko, R. (2013, December 17). An Analysis of PlugX Malware. Retrieved November 24, 2015.
* http://researchcenter.paloaltonetworks.com/2015/04/unit-42-identifies-new-dragonok-backdoor-malware-deployed-against-japanese-targets/ - Miller-Osborn, J., Grunzweig, J.. (2015, April). Unit 42 Identifies New DragonOK Backdoor Malware Deployed Against Japanese Targets. Retrieved November 4, 2015.
* https://bi-zone.medium.com/from-pentest-to-apt-attack-cybercriminal-group-fin7-disguises-its-malware-as-an-ethical-hackers-c23c9a75e319 - BI.ZONE Cyber Threats Research Team. (2021, May 13). From pentest to APT attack: cybercriminal group FIN7 disguises its malware as an ethical hacker’s toolkit. Retrieved February 2, 2022.
* https://blog.gigamon.com/2019/07/23/abadbabe-8badf00d-discovering-badhatch-and-a-detailed-look-at-fin8s-tooling/ - Savelesky, K., et al. (2019, July 23). ABADBABE 8BADFOOD: Discovering BADHATCH and a Detailed Look at FIN8's Tooling. Retrieved September 8, 2021.
* https://blog.talosintelligence.com/2018/07/multiple-cobalt-personality-disorder.html - Svajcer, V. (2018, July 31). Multiple Cobalt Personality Disorder. Retrieved September 5, 2018.
* https://blog.talosintelligence.com/2019/04/sodinokibi-ransomware-exploits-weblogic.html - Cadieux, P, et al (2019, April 30). Sodinokibi ransomware exploits WebLogic Server vulnerability. Retrieved August 4, 2020.
* https://blog.trendmicro.com/trendlabs-security-intelligence/autoit-compiled-worm-affecting-removable-media-delivers-fileless-version-of-bladabindi-njrat-backdoor/ - Pascual, C. (2018, November 27). AutoIt-Compiled Worm Affecting Removable Media Delivers Fileless Version of BLADABINDI/njRAT Backdoor. Retrieved June 4, 2019.
* https://blogs.cisco.com/security/talos/opening-zxshell - Allievi, A., et al. (2014, October 28). Threat Spotlight: Group 72, Opening the ZxShell. Retrieved September 24, 2019.
* https://cloud.google.com/blog/topics/threat-intelligence/apt41-arisen-from-dust - Mike Stokkel et al. (2024, July 18). APT41 Has Arisen From the DUST. Retrieved September 16, 2024.
* https://cloud.google.com/blog/topics/threat-intelligence/apt41-us-state-governments - Rufus Brown, Van Ta, Douglas Bienstock, Geoff Ackerman & John Wolfram. (2022, March 8). Does This Look Infected? A Summary of APT41 Targeting U.S. State Governments. Retrieved September 16, 2024.
* https://geminiadvisory.io/fin7-ransomware-bastion-secure/ - Gemini Advisory. (2021, October 21). FIN7 Recruits Talent For Push Into Ransomware. Retrieved February 2, 2022.
* https://go.crowdstrike.com/rs/281-OBQ-266/images/Report2020CrowdStrikeGlobalThreatReport.pdf - Crowdstrike. (2020, March 2). 2020 Global Threat Report. Retrieved December 11, 2020.
* https://go.recordedfuture.com/hubfs/reports/cta-2021-0228.pdf - Insikt Group. (2021, February 28). China-Linked Group RedEcho Targets the Indian Power Sector Amid Heightened Border Tensions. Retrieved March 22, 2021.
* https://intel471.com/blog/revil-ransomware-as-a-service-an-analysis-of-a-ransomware-affiliate-operation/ - Intel 471 Malware Intelligence team. (2020, March 31). REvil Ransomware-as-a-Service – An analysis of a ransomware affiliate operation. Retrieved August 4, 2020.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2017/08/07172148/ShadowPad_technical_description_PDF.pdf - Kaspersky Lab. (2017, August). ShadowPad: popular server management software hit in supply chain attack. Retrieved March 22, 2021.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/08064518/Carbanak_APT_eng.pdf - Kaspersky Lab's Global Research and Analysis Team. (2015, February). CARBANAK APT THE GREAT BANK ROBBERY. Retrieved August 23, 2018.
* https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a - Chronicle Blog. (2019, May 15). Winnti: More than just Windows and Gates. Retrieved April 29, 2020.
* https://news.sophos.com/en-us/2020/05/21/ragnar-locker-ransomware-deploys-virtual-machine-to-dodge-security/ - SophosLabs. (2020, May 21). Ragnar Locker ransomware deploys virtual machine to dodge security. Retrieved June 29, 2020.
* https://news.sophos.com/en-us/2020/09/17/maze-attackers-adopt-ragnar-locker-virtual-machine-technique/ - Brandt, A., Mackenzie, P.. (2020, September 17). Maze Attackers Adopt Ragnar Locker Virtual Machine Technique. Retrieved October 9, 2020.
* https://news.sophos.com/en-us/2022/07/14/blackcat-ransomware-attacks-not-merely-a-byproduct-of-bad-luck/ - Brandt, Andrew. (2022, July 14). BlackCat ransomware attacks not merely a byproduct of bad luck. Retrieved December 20, 2022.
* https://paper.seebug.org/papers/APT/APT_CyberCriminal_Campagin/2016/2016.02.29.Turbo_Campaign_Derusbi/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://research.checkpoint.com/2020/warzone-behind-the-enemy-lines/ - Harakhavik, Y. (2020, February 3). Warzone: Behind the enemy lines. Retrieved December 17, 2021.
* https://research.nccgroup.com/2018/04/17/decoding-network-data-from-a-gh0st-rat-variant/ - Pantazopoulos, N. (2018, April 17). Decoding network data from a Gh0st RAT variant. Retrieved November 2, 2018.
* https://securelist.com/fin7-5-the-infamous-cybercrime-rig-fin7-continues-its-activities/90703/ - Namestnikov, Y. and Aime, F. (2019, May 8). FIN7.5: the infamous cybercrime rig “FIN7” continues its activities. Retrieved October 11, 2019.
* https://securelist.com/shadowpad-in-corporate-networks/81432/ - GReAT. (2017, August 15). ShadowPad in corporate networks. Retrieved March 22, 2021.
* https://securelist.com/sodin-ransomware/91473/ - Mamedov, O, et al. (2019, July 3). Sodin ransomware exploits Windows vulnerability and processor architecture. Retrieved August 4, 2020.
* https://securityintelligence.com/posts/more_eggs-anyone-threat-actor-itg08-strikes-again/ - Villadsen, O.. (2019, August 29). More_eggs, Anyone? Threat Actor ITG08 Strikes Again. Retrieved September 16, 2019.
* https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/syssphinx-fin8-backdoor - Symantec Threat Hunter Team. (2023, July 18). FIN8 Uses Revamped Sardonic Backdoor to Deliver Noberus Ransomware. Retrieved August 9, 2023.
* https://threatpost.com/fin7-backdoor-ethical-hacking-tool/166194/ - Seals, T. (2021, May 14). FIN7 Backdoor Masquerades as Ethical Hacking Tool. Retrieved February 2, 2022.
* https://threatvector.cylance.com/en_us/home/threat-spotlight-sodinokibi-ransomware.html - Cylance. (2019, July 3). hreat Spotlight: Sodinokibi Ransomware. Retrieved August 4, 2020.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://us-cert.cisa.gov/ncas/alerts/aa21-200a - CISA. (2021, July 19). (AA21-200A) Joint Cybersecurity Advisory – Tactics, Techniques, and Procedures of Indicted APT40 Actors Associated with China’s MSS Hainan State Security Department. Retrieved August 12, 2021.
* https://usa.visa.com/dam/VCOM/global/support-legal/documents/fin6-cybercrime-group-expands-threat-To-ecommerce-merchants.pdf - Visa Public. (2019, February). FIN6 Cybercrime Group Expands Threat to eCommerce Merchants. Retrieved September 16, 2019.
* https://web.archive.org/web/20180808125108/https:/www.fireeye.com/blog/threat-research/2017/03/fin7_spear_phishing.html - Miller, S., et al. (2017, March 7). FIN7 Spear Phishing Campaign Targets Personnel Involved in SEC Filings. Retrieved March 8, 2017.
* https://web.archive.org/web/20210825130434/https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://web.archive.org/web/20230115144216/http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* https://web.archive.org/web/20240119213200/https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved January 22, 2016.
* https://www.arbornetworks.com/blog/asert/musical-chairs-playing-tetris/ - Sabo, S. (2018, February 15). Musical Chairs Playing Tetris. Retrieved February 19, 2018.
* https://www.bitdefender.com/files/News/CaseStudies/study/394/Bitdefender-PR-Whitepaper-BADHATCH-creat5237-en-EN.pdf - Vrabie, V., et al. (2021, March 10). FIN8 Returns with Improved BADHATCH Toolkit. Retrieved September 8, 2021.
* https://www.bitdefender.com/files/News/CaseStudies/study/401/Bitdefender-PR-Whitepaper-FIN8-creat5619-en-EN.pdf - Budaca, E., et al. (2021, August 25). FIN8 Threat Actor Goes Agile with New Sardonic Backdoor. Retrieved August 9, 2023.
* https://www.bleepingcomputer.com/news/security/ryuk-ransomware-uses-wake-on-lan-to-encrypt-offline-devices/ - Abrams, L. (2021, January 14). Ryuk Ransomware Uses Wake-on-Lan To Encrypt Offline Devices. Retrieved February 11, 2021.
* https://www.carbonblack.com/2019/03/22/tau-threat-intelligence-notification-lockergoga-ransomware/ - CarbonBlack Threat Analysis Unit. (2019, March 22). TAU Threat Intelligence Notification – LockerGoga Ransomware. Retrieved April 16, 2019.
* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ - Hanel, A. (2019, January 10). Big Game Hunting with Ryuk: Another Lucrative Targeted Ransomware. Retrieved May 12, 2020.
* https://www.crowdstrike.com/blog/carbon-spider-embraces-big-game-hunting-part-1/ - Loui, E. and Reynolds, J. (2021, August 30). CARBON SPIDER Embraces Big Game Hunting, Part 1. Retrieved September 20, 2021.
* https://www.cyber.gov.au/about-us/advisories/2022-004-acsc-ransomware-profile-alphv-aka-blackcat - Australian Cyber Security Centre. (2022, April 14). 2022-004: ACSC Ransomware Profile - ALPHV (aka BlackCat). Retrieved December 20, 2022.
* https://www.cynet.com/blog/cynet-detection-report-ragnar-locker-ransomware/ - Gold, B. (2020, April 27). Cynet Detection Report: Ragnar Locker Ransomware. Retrieved June 29, 2020.
* https://www.esentire.com/security-advisories/notorious-cybercrime-gang-fin7-lands-malware-in-law-firm-using-fake-legal-complaint-against-jack-daniels-owner-brown-forman-inc - eSentire. (2021, July 21). Notorious Cybercrime Gang, FIN7, Lands Malware in Law Firm Using Fake Legal Complaint Against Jack Daniels’ Owner, Brown-Forman Inc.. Retrieved September 20, 2021.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2013/08/njw0rm-brother-from-the-same-mother.html - Dawda, U. and Villeneuve, N. (2013, August 30). Njw0rm - Brother From the Same Mother. Retrieved June 4, 2019.
* https://www.fireeye.com/blog/threat-research/2014/06/clandestine-fox-part-deux.html - Scott, M.. (2014, June 10). Clandestine Fox, Part Deux. Retrieved January 14, 2016.
* https://www.fireeye.com/blog/threat-research/2015/07/demonstrating_hustle.html - FireEye Threat Intelligence. (2015, July 13). Demonstrating Hustle, Chinese APT Groups Quickly Use Zero-Day Vulnerability (CVE-2015-5119) Following Hacking Team Leak. Retrieved January 25, 2016.
* https://www.fireeye.com/blog/threat-research/2015/12/fin1-targets-boot-record.html - Andonov, D., et al. (2015, December 7). Thriving Beyond The Operating System: Financial Threat Group Targets Volume Boot Record. Retrieved May 13, 2016.
* https://www.fireeye.com/blog/threat-research/2016/05/windows-zero-day-payment-cards.html - Kizhakkinan, D., et al. (2016, May 11). Threat Actor Leverages Windows Zero-day Exploit in Payment Card Data Attacks. Retrieved February 12, 2018.
* https://www.fireeye.com/blog/threat-research/2017/06/behind-the-carbanak-backdoor.html - Bennett, J., Vengerik, B. (2017, June 12). Behind the CARBANAK Backdoor. Retrieved June 11, 2018.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html - Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html - McKeague, B. et al. (2019, April 5). Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware. Retrieved April 17, 2019.
* https://www.fireeye.com/blog/threat-research/2019/10/mahalo-fin7-responding-to-new-tools-and-techniques.html - Carr, N, et all. (2019, October 10). Mahalo FIN7: Responding to the Criminal Operators’ New Tools and Techniques. Retrieved October 11, 2019.
* https://www.fireeye.com/blog/threat-research/2019/10/messagetap-who-is-reading-your-text-messages.html - Leong, R., Perez, D., Dean, T. (2019, October 31). MESSAGETAP: Who’s Reading Your Text Messages?. Retrieved May 11, 2020.
* https://www.fireeye.com/blog/threat-research/2020/05/tactics-techniques-procedures-associated-with-maze-ransomware-incidents.html - Kennelly, J., Goody, K., Shilko, J. (2020, May 7). Navigating the MAZE: Tactics, Techniques and Procedures Associated With MAZE Ransomware Incidents. Retrieved May 18, 2020.
* https://www.fox-it.com/en/news/blog/anunak-aka-carbanak-update/ - Prins, R. (2015, February 16). Anunak (aka Carbanak) Update. Retrieved January 20, 2017.
* https://www.gdatasoftware.com/blog/2019/06/31724-strange-bits-sodinokibi-spam-cinarat-and-fake-g-data - Han, Karsten. (2019, June 4). Strange Bits: Sodinokibi Spam, CinaRAT, and Fake G DATA. Retrieved August 4, 2020.
* https://www.group-ib.com/blog/grimagent/ - Priego, A. (2021, July). THE BROTHERS GRIM: THE REVERSING TALE OF GRIMAGENT MALWARE USED BY RYUK. Retrieved September 19, 2024.
* https://www.group-ib.com/whitepapers/ransomware-uncovered.html - Group IB. (2020, May). Ransomware Uncovered: Attackers’ Latest Methods. Retrieved August 5, 2020.
* https://www.mandiant.com/resources/apt41-us-state-governments - Rufus Brown, Van Ta, Douglas Bienstock, Geoff Ackerman, John Wolfram. (2022, March 8). Does This Look Infected? A Summary of APT41 Targeting U.S. State Governments. Retrieved July 8, 2022.
* https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf - Fraser, N., et al. (2019, August 7). Double DragonAPT41, a dual espionage and cyber crime operation APT41. Retrieved September 23, 2019.
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-crescendo/ - Saavedra-Morales, J, et al. (2019, October 20). McAfee ATR Analyzes Sodinokibi aka REvil Ransomware-as-a-Service – Crescendo. Retrieved August 5, 2020.
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/ - McAfee. (2019, October 2). McAfee ATR Analyzes Sodinokibi aka REvil Ransomware-as-a-Service – What The Code Tells Us. Retrieved August 4, 2020.
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/ransomware-maze/ - Mundo, A. (2020, March 26). Ransomware Maze. Retrieved May 18, 2020.
* https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/ - Microsoft Defender Threat Intelligence. (2022, June 13). The many lives of BlackCat ransomware. Retrieved December 20, 2022.
* https://www.picussecurity.com/blog/a-brief-history-and-further-technical-analysis-of-sodinokibi-ransomware - Ozarslan, S. (2020, January 15). A Brief History of Sodinokibi. Retrieved August 5, 2020.
* https://www.proofpoint.com/us/threat-insight/post/leaked-ammyy-admin-source-code-turned-malware - Proofpoint Staff. (2018, March 7). Leaked Ammyy Admin Source Code Turned into Malware. Retrieved May 28, 2019.
* https://www.rapid7.com/blog/post/2021/03/23/defending-against-the-zero-day-analyzing-attacker-behavior-post-exploitation-of-microsoft-exchange/ - Eoin Miller. (2021, March 23). Defending Against the Zero Day: Analyzing Attacker Behavior Post-Exploitation of Microsoft Exchange. Retrieved October 27, 2022.
* https://www.secureworks.com/blog/revil-the-gandcrab-connection - Secureworks . (2019, September 24). REvil: The GandCrab Connection. Retrieved August 4, 2020.
* https://www.secureworks.com/research/revil-sodinokibi-ransomware - Counter Threat Unit Research Team. (2019, September 24). REvil/Sodinokibi Ransomware. Retrieved August 4, 2020.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.tetradefense.com/incident-response-services/cause-and-effect-sodinokibi-ransomware-analysis - Tetra Defense. (2020, March). CAUSE AND EFFECT: SODINOKIBI RANSOMWARE ANALYSIS. Retrieved December 14, 2020.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.
* https://www.threatminer.org/_reports/2013/fta-1009---njrat-uncovered-1.pdf - Fidelis Cybersecurity. (2013, June 28). Fidelis Threat Advisory #1009: "njRAT" Uncovered. Retrieved June 4, 2019.
* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/pillowmint-fin7s-monkey-thief/ - Trustwave SpiderLabs. (2020, June 22). Pillowmint: FIN7’s Monkey Thief . Retrieved July 27, 2020.
* https://www.uptycs.com/blog/warzone-rat-comes-with-uac-bypass-technique - Mohanta, A. (2020, November 25). Warzone RAT comes with UAC bypass technique. Retrieved April 7, 2022.
* https://www.welivesecurity.com/2020/07/09/more-evil-deep-look-evilnum-toolset/ - Porolli, M. (2020, July 9). More evil: A deep look at Evilnum and its toolset. Retrieved January 22, 2021.
* https://www2.fireeye.com/WBNR-Know-Your-Enemy-UNC622-Spear-Phishing.html - Elovitz, S. & Ahl, I. (2016, August 18). Know Your Enemy:  New Financially-Motivated & Spear-Phishing Group. Retrieved February 26, 2018.

