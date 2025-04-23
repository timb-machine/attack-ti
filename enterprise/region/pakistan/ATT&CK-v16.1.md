threat-crank.py 0.2.1
I: searching for regions that match .* pakistan.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v16.1/enterprise-attack/enterprise-attack.json
# Threat groups

* BITTER
* Gorgon Group
* Mustang Panda
* SideCopy
* Sidewinder
* The White Company
* Transparent Tribe

# Validate the following attacks

* Archive via Custom Method - 1
* Archive via Utility - 1
* Automated Collection - 2
* Automated Exfiltration - 1
* Binary Padding - 1
* Command Obfuscation - 1
* DLL Side-Loading - 3
* Deobfuscate/Decode Files or Information - 1
* Disable or Modify Tools - 1
* Domains - 5
* Double File Extension - 1
* Drive-by Compromise - 1
* Drive-by Target - 1
* Dynamic Data Exchange - 2
* Dynamic Resolution - 2
* Email Accounts - 1
* Encrypted Channel - 1
* Encrypted/Encoded File - 3
* Exfiltration over USB - 1
* Exploitation for Client Execution - 5
* Exploitation for Privilege Escalation - 1
* File Deletion - 2
* File and Directory Discovery - 2
* Hidden Files and Directories - 2
* Hidden Window - 1
* Ingress Tool Transfer - 5
* InstallUtil - 1
* JavaScript - 1
* Local Data Staging - 2
* Malicious File - 7
* Malicious Link - 3
* Masquerade Task or Service - 1
* Match Legitimate Name or Location - 4
* Modify Registry - 1
* Mshta - 3
* NTDS - 1
* Native API - 2
* Non-Application Layer Protocol - 1
* Obfuscated Files or Information - 1
* Portable Executable Injection - 1
* PowerShell - 3
* Process Discovery - 2
* Process Hollowing - 1
* Registry Run Keys / Startup Folder - 3
* Remote Access Software - 1
* Replication Through Removable Media - 1
* Scheduled Task - 2
* Security Software Discovery - 3
* Shortcut Modification - 1
* Software Discovery - 3
* Software Packing - 1
* Spearphishing Attachment - 9
* Spearphishing Link - 5
* Stage Capabilities - 1
* Symmetric Cryptography - 1
* System Information Discovery - 3
* System Location Discovery - 1
* System Network Configuration Discovery - 3
* System Network Connections Discovery - 1
* System Owner/User Discovery - 1
* System Time Discovery - 2
* Tool - 2
* Upload Malware - 3
* Visual Basic - 5
* Web Protocols - 3
* Web Service - 1
* Windows Command Shell - 2
* Windows Management Instrumentation - 1
* Windows Management Instrumentation Event Subscription - 1

# Validate the following phases

* collection - 6
* command-and-control - 15
* credential-access - 1
* defense-evasion - 30
* discovery - 21
* execution - 33
* exfiltration - 2
* initial-access - 12
* lateral-movement - 1
* persistence - 10
* privilege-escalation - 13
* reconnaissance - 4
* resource-development - 13

# Validate the following platforms

* Containers - 6
* IaaS - 14
* Identity Provider - 4
* Linux - 101
* Network - 28
* Office Suite - 5
* PRE - 17
* SaaS - 5
* Windows - 146
* macOS - 101

# Validate the following defences

* Anti-virus - 9
* Application Control - 8
* Application control - 6
* Digital Certificate Validation - 4
* File monitoring - 1
* Heuristic detection - 1
* Host Forensic Analysis - 1
* Host Intrusion Prevention Systems - 2
* Host forensic analysis - 5
* Host intrusion prevention systems - 1
* Log Analysis - 1
* Log analysis - 1
* Network Intrusion Detection System - 1
* Signature-based Detection - 2
* Signature-based detection - 3

# Validate the following data sources

* Active Directory: Active Directory Object Access - 1
* Application Log: Application Log Content - 21
* Command: Command Execution - 66
* Domain Name: Active DNS - 5
* Domain Name: Domain Registration - 5
* Domain Name: Passive DNS - 5
* Drive: Drive Creation - 2
* Driver: Driver Load - 2
* File: File Access - 9
* File: File Creation - 45
* File: File Deletion - 2
* File: File Metadata - 14
* File: File Modification - 16
* Firewall: Firewall Enumeration - 6
* Firewall: Firewall Metadata - 6
* Image: Image Metadata - 4
* Internet Scan: Response Content - 5
* Malware Repository: Malware Metadata - 2
* Module: Module Load - 17
* Network Traffic: Network Connection Creation - 18
* Network Traffic: Network Traffic Content - 35
* Network Traffic: Network Traffic Flow - 37
* Process: OS API Execution - 27
* Process: Process Access - 3
* Process: Process Creation - 79
* Process: Process Metadata - 7
* Process: Process Modification - 2
* Process: Process Termination - 1
* Scheduled Job: Scheduled Job Creation - 2
* Scheduled Job: Scheduled Job Metadata - 1
* Scheduled Job: Scheduled Job Modification - 1
* Script: Script Execution - 22
* Sensor Health: Host Status - 1
* Service: Service Creation - 1
* Service: Service Metadata - 2
* User Account: User Account Authentication - 2
* WMI: WMI Creation - 3
* Windows Registry: Windows Registry Key Access - 1
* Windows Registry: Windows Registry Key Creation - 7
* Windows Registry: Windows Registry Key Deletion - 2
* Windows Registry: Windows Registry Key Modification - 7

# Review the following attack references

* http://adsecurity.org/?p=1275 - Metcalf, S. (2015, January 19). Attackers Can Now Use Mimikatz to Implant Skeleton Key on Domain Controllers & BackDoor Your Active Directory Forest. Retrieved February 3, 2015.
* http://arstechnica.com/security/2015/08/newly-discovered-chinese-hacking-group-hacked-100-websites-to-use-as-watering-holes/ - Gallagher, S.. (2015, August 5). Newly discovered Chinese hacking group hacked 100+ websites to use as “watering holes”. Retrieved January 25, 2016.
* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html - Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.
* http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf - Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
* http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29 - Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/KB/170292 - Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf - ESET. (2016, October). En Route with Sednit - Part 2: Observing the Comings and Goings. Retrieved November 21, 2016.
* https://airbus-cyber-security.com/fileless-malware-behavioural-analysis-kovter-persistence/ - Dove, A. (2016, March 23). Fileless Malware – A Behavioural Analysis Of Kovter Persistence. Retrieved December 5, 2017.
* https://any.run/cybersecurity-blog/time-bombs-malware-with-delayed-execution/ - Malicious History. (2020, September 17). Time Bombs: Malware With Delayed Execution. Retrieved April 22, 2021.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://bashfuscator.readthedocs.io/en/latest/Mutators/command_obfuscators/index.html - LeFevre, A. (n.d.). Bashfuscator Command Obfuscators. Retrieved March 17, 2023.
* https://blog.crysys.hu/2013/03/teamspy/ - CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.
* https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/ - Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/malwarebytes-news/2020/10/silent-librarian-apt-phishing-attack/ - Malwarebytes Threat Intelligence Team. (2020, October 14). Silent Librarian APT right on schedule for 20/21 academic year. Retrieved February 3, 2021.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.nviso.eu/2020/02/04/the-return-of-the-spoof-part-2-command-line-spoofing/ - Daman, R. (2020, February 4). The return of the spoof part 2: Command line spoofing. Retrieved November 19, 2021.
* https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments - Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.
* https://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/ -  Ishaq Mohammed . (2021, January 10). Everything about CSV Injection and CSV Excel Macro Injection. Retrieved February 7, 2022.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A., McKay, K. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal . Retrieved July 29, 2022.
* https://blog.talosintelligence.com/2022/03/transparent-tribe-new-campaign.html - Malhotra, A., Thattil, J. et al. (2022, March 29). Transparent Tribe campaign uses new bespoke malware to target Indian government officials . Retrieved September 6, 2022.
* https://blog.talosintelligence.com/ipfs-abuse/ - Edmund Brumaghin. (2022, November 9). Threat Spotlight: Cyber Criminal Adoption of IPFS for Phishing, Malware Campaigns. Retrieved March 8, 2023.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/r980-ransomware-disposable-email-service/ - Antazo, F. and Yambao, M. (2016, August 10). R980 Ransomware Found Abusing Disposable Email Address Service. Retrieved October 13, 2020.
* https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices - Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.
* https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16 - Bromiley, M. (2016, December 27). Malware Monday: VBScript and VBE Files. Retrieved March 17, 2023.
* https://cdn.logic-control.com/docs/scadafence/Anatomy-Of-A-Targeted-Ransomware-Attack-WP.pdf - Shaked, O. (2020, January 20). Anatomy of a Targeted Ransomware Attack. Retrieved June 18, 2022.
* https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.226.3427&rep=rep1&type=pdf - Zhaohui Wang & Angelos Stavrou. (n.d.). Exploiting Smart-Phone USB Connectivity For Fun And Profit. Retrieved May 25, 2022.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://csrc.nist.gov/glossary/term/web_bug - NIST Information Technology Laboratory. (n.d.). web bug. Retrieved March 22, 2023.
* https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks - Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.
* https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/ - Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/documentation/coreservices - Apple. (n.d.). Core Services. Retrieved June 25, 2020.
* https://developer.apple.com/documentation/foundation - Apple. (n.d.). Foundation. Retrieved July 1, 2020.
* https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html - Apple. (2016, June 13). About Mac Scripting. Retrieved April 14, 2021.
* https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/CocoaApplicationLayer/CocoaApplicationLayer.html#//apple_ref/doc/uid/TP40001067-CH274-SW1 - Apple. (2015, September 16). Cocoa Application Layer. Retrieved June 25, 2020.
* https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-identity-documents.html - Amazon. (n.d.). Instance identity documents. Retrieved April 2, 2021.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/archive/blogs/gauravseth/the-world-of-jscript-javascript-ecmascript - Microsoft. (2007, August 15). The World of JScript, JavaScript, ECMAScript …. Retrieved June 23, 2020.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover - Microsoft. (2020, September 29). Prevent dangling DNS entries and avoid subdomain takeover. Retrieved October 12, 2020.
* https://docs.microsoft.com/en-us/azure/virtual-machines/windows/instance-metadata-service?tabs=windows - Microsoft. (2021, February 21). Azure Instance Metadata Service (Windows). Retrieved April 2, 2021.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1 - Wheeler, S. et al.. (2019, May 1). About PowerShell.exe. Retrieved October 11, 2019.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules - Microsoft. (2020, October 15). Microsoft recommended driver block rules. Retrieved March 16, 2021.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/api/ - Microsoft. (n.d.). Programming reference for the Win32 API. Retrieved March 15, 2020.
* https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry - Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/scripting/winscript/windows-script-interfaces - Microsoft. (2017, January 18). Windows Script Interfaces. Retrieved June 23, 2020.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/win32/com/translating-to-jscript - Microsoft. (2018, May 31). Translating to JScript. Retrieved June 23, 2020.
* https://docs.ostorlab.co/kb/IPA_URL_SCHEME_HIJACKING/index.html - Ostorlab. (n.d.). iOS URL Scheme Hijacking. Retrieved February 9, 2024.
* https://dotnet.microsoft.com/learn/dotnet/what-is-dotnet-framework - Microsoft. (n.d.). What is .NET Framework?. Retrieved March 15, 2020.
* https://en.ryte.com/wiki/Tracking_Pixel - Ryte Wiki. (n.d.). Retrieved March 5, 2024.
* https://en.wikipedia.org/wiki/Active_Directory - Wikipedia. (2018, March 10). Active Directory. Retrieved April 11, 2018.
* https://en.wikipedia.org/wiki/HTML_Application - Wikipedia. (2017, October 14). HTML Application. Retrieved October 27, 2017.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://github.com/Exploit-install/PSAttack-1 - Haight, J. (2016, April 21). PS>Attack. Retrieved September 27, 2024.
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml - Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.
* https://github.com/danielbohannon/Invoke-DOSfuscation - Bohannon, D. (2018, March 19). Invoke-DOSfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Invoke-Obfuscation - Bohannon, D. (2016, September 24). Invoke-Obfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/dhondta/awesome-executable-packing - Alexandre D'Hondt. (n.d.). Awesome Executable Packing. Retrieved March 11, 2022.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md - Red Canary - Atomic Red Team. (n.d.). T1053.005 - Scheduled Task/Job: Scheduled Task. Retrieved June 19, 2024.
* https://github.com/ryhanson/phishery - Ryan Hanson. (2016, September 24). phishery. Retrieved October 23, 2020.
* https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf - CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.
* https://iapp.org/resources/article/web-beacon/ - IAPP. (n.d.). Retrieved March 5, 2024.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://krebsonsecurity.com/2018/11/that-domain-you-forgot-to-renew-yeah-its-now-stealing-credit-cards/ - Krebs, B. (2018, November 13). That Domain You Forgot to Renew? Yeah, it’s Now Stealing Credit Cards. Retrieved September 20, 2019.
* https://krebsonsecurity.com/2019/02/a-deep-dive-on-the-recent-widespread-dns-hijacking-attacks/ - Brian Krebs. (2019, February 18). A Deep Dive on the Recent Widespread DNS Hijacking Attacks. Retrieved February 14, 2022.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa - Microsoft. (n.d.). CreateProcess function. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page?redirectedfrom=MSDN - Microsoft. (2023, March 7). Retrieved February 13, 2024.
* https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedcommand-base64encodedcommand - Microsoft. (2023, February 8). about_PowerShell_exe: EncodedCommand. Retrieved March 17, 2023.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://lolbas-project.github.io/lolbas/Binaries/Diantz/ - Living Off The Land Binaries, Scripts and Libraries (LOLBAS). (n.d.). Diantz.exe. Retrieved October 25, 2021.
* https://lolbas-project.github.io/lolbas/Binaries/Installutil/ - LOLBAS. (n.d.). Installutil.exe. Retrieved July 31, 2019.
* https://lolbas-project.github.io/lolbas/Binaries/Mshta/ - LOLBAS. (n.d.). Mshta.exe. Retrieved July 31, 2019.
* https://man7.org/linux/man-pages//man7/libc.7.html - Kerrisk, M. (2016, December 12). libc(7) — Linux manual page. Retrieved June 25, 2020.
* https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF - Australian Cyber Security Centre. National Security Agency. (2020, April 21). Detect and Prevent Web Shell Malware. Retrieved February 9, 2024.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://mrd0x.com/browser-in-the-browser-phishing-attack/ - mr.d0x. (2022, March 15). Browser In The Browser (BITB) Attack. Retrieved March 8, 2023.
* https://msdn.microsoft.com/en-us/library/50614e95.aspx - Microsoft. (n.d.). Installutil.exe (Installer Tool). Retrieved July 1, 2016.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://msdn.microsoft.com/ms724961.aspx - Microsoft. (n.d.). System Time. Retrieved November 25, 2016.
* https://nakedsecurity.sophos.com/2020/10/02/serious-security-phishing-without-links-when-phishers-bring-along-their-own-web-pages/ - Ducklin, P. (2020, October 2). Serious Security: Phishing without links – when phishers bring along their own web pages. Retrieved October 20, 2020.
* https://new.dc414.org/wp-content/uploads/2011/01/Process-Hollowing.pdf - Leitch, J. (n.d.). Process Hollowing. Retrieved September 12, 2024.
* https://news.sophos.com/en-us/2016/05/03/location-based-ransomware-threat-research/ - Wisniewski, C. (2016, May 3). Location-based threats: How cybercriminals target you based on where you live. Retrieved April 1, 2021.
* https://nodejs.org/ - OpenJS Foundation. (n.d.). Node.js. Retrieved June 23, 2020.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ - de Plaa, C. (2019, June 19). Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR. Retrieved September 29, 2021.
* https://owasp.org/www-community/attacks/CSV_Injection -  Albinowax Timo Goosen. (n.d.). CSV Injection. Retrieved February 7, 2022.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5 - Pitt, L. (2020, August 6). Persistent JXA. Retrieved April 14, 2021.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://powershellmagazine.com/2014/07/16/investigating-powershell-attacks/ - Hastings, M. (2014, July 16). Investigating PowerShell Attacks. Retrieved December 1, 2021.
* https://ptylu.github.io/content/report/report.html?report=25 - Heiligenstein, L. (n.d.). REP-25: Disable Windows Event Logging. Retrieved April 7, 2022.
* https://redcanary.com/blog/clipping-silver-sparrows-wings/ - Tony Lambert. (2021, February 18). Clipping Silver Sparrow’s wings: Outing macOS malware before it takes flight. Retrieved April 20, 2021.
* https://redcanary.com/threat-detection-report/techniques/powershell/ - Red Canary. (n.d.). 2022 Threat Detection Report: PowerShell. Retrieved March 17, 2023.
* https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls - Feichter, D. (2023, June 30). Direct Syscalls vs Indirect Syscalls. Retrieved September 27, 2023.
* https://research.checkpoint.com/2024/magnet-goblin-targets-publicly-facing-servers-using-1-day-vulnerabilities/ - Check Point Research. (2024, March 8). MAGNET GOBLIN TARGETS PUBLICLY FACING SERVERS USING 1-DAY VULNERABILITIES. Retrieved March 27, 2024.
* https://researchcenter.paloaltonetworks.com/2016/09/unit42-sofacys-komplex-os-x-trojan/ - Dani Creus, Tyler Halfpop, Robert Falcone. (2016, September 26). Sofacy's 'Komplex' OS X Trojan. Retrieved July 8, 2017.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://s3.documentcloud.org/documents/20413525/fbi-flash-indicators-of-compromise-ragnar-locker-ransomware-11192020-bc.pdf - FBI. (2020, November 19). Indicators of Compromise Associated with Ragnar Locker Ransomware. Retrieved September 12, 2024.
* https://s7d2.scene7.com/is/content/cylance/prod/cylance-web/en-us/resources/knowledge-center/resource-library/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved December 22, 2021.
* https://securelist.com/old-malware-tricks-to-bypass-detection-in-the-age-of-big-data/78010/ - Ishimaru, S.. (2017, April 13). Old Malware Tricks To Bypass Detection in the Age of Big Data. Retrieved May 30, 2019.
* https://securelist.com/transparent-tribe-part-1/98127/ - Dedola, G. (2020, August 20). Transparent Tribe: Evolution analysis, part 1. Retrieved April 1, 2021.
* https://securityintelligence.com/anatomy-of-an-hvnc-attack/ - Keshet, Lior. Kessem, Limor. (2017, January 25). Anatomy of an hVNC Attack. Retrieved November 28, 2023.
* https://securityintelligence.com/posts/brazking-android-malware-upgraded-targeting-brazilian-banks/ - Shahar Tavor. (n.d.). BrazKing Android Malware Upgraded and Targeting Brazilian Banks. Retrieved March 24, 2023.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://socprime.com/blog/rule-of-the-week-possible-malicious-file-double-extension/ - Eugene Tkachenko. (2020, May 1). Rule of the Week: Possible Malicious File Double Extension. Retrieved July 27, 2021.
* https://stackoverflow.com/questions/2913816/how-to-find-the-location-of-the-scheduled-tasks-folder - Stack Overflow. (n.d.). How to find the location of the Scheduled Tasks folder. Retrieved June 19, 2024.
* https://support.apple.com/en-gb/guide/remote-desktop/apd95406b8d/mac - Apple Support. (n.d.). About systemsetup in Remote Desktop. Retrieved March 27, 2024.
* https://support.google.com/chrome/answer/1649523 - Google. (n.d.). Retrieved March 14, 2024.
* https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-ransomware-attacks-against-microsoft-defender/ba-p/1928947 - Tran, T. (2020, November 24). Demystifying Ransomware Attacks Against Microsoft Defender Solution. Retrieved January 26, 2022.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://techcommunity.microsoft.com/t5/windows-it-pro-blog/wmi-command-line-wmic-utility-deprecation-next-steps/ba-p/4039242 - Microsoft. (2024, January 26). WMIC Deprecation. Retrieved February 13, 2024.
* https://techcrunch.com/2019/08/12/iphone-charging-cable-hack-computer-def-con/ - Zack Whittaker. (2019, August 12). This hacker’s iPhone charging cable can hijack your computer. Retrieved May 25, 2022.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://technet.microsoft.com/windows-server-docs/identity/ad-ds/get-started/windows-time-service/windows-time-service-tools-and-settings - Mathers, B. (2016, September 30). Windows Time Service Tools and Settings. Retrieved November 25, 2016.
* https://thehackernews.com/2022/05/avoslocker-ransomware-variant-using-new.html - Lakshmanan, R. (2022, May 2). AvosLocker Ransomware Variant Using New Trick to Disable Antivirus Protection. Retrieved May 17, 2022.
* https://therecord.media/phishing-campaign-used-qr-codes-to-target-energy-firm - Jonathan Greig. (2023, August 16). Phishing campaign used QR codes to target large energy company. Retrieved November 27, 2023.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://undocumented.ntinternals.net/ - The NTinterlnals.net team. (n.d.). Nowak, T. Retrieved June 25, 2020.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/domain-shadowing/ - Janos Szurdi, Rebekah Houser and Daiping Liu. (2022, September 21). Domain Shadowing: A Stealthy Use of DNS Compromise for Cybercrime. Retrieved March 7, 2023.
* https://unit42.paloaltonetworks.com/purpleurchin-steals-cloud-resources/ - Gamazo, William. Quist, Nathaniel.. (2023, January 5). PurpleUrchin Bypasses CAPTCHA and Steals Cloud Platform Resources. Retrieved February 28, 2024.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://web.archive.org/web/20160327101330/http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* https://web.archive.org/web/20170923102302/https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://web.archive.org/web/20171223000420/https://www.riskiq.com/blog/labs/lazarus-group-cryptocurrency/ - RISKIQ. (2017, December 20). Mining Insights: Infrastructure Analysis of Lazarus Group Cyber Attacks on the Cryptocurrency Industry. Retrieved July 29, 2022.
* https://web.archive.org/web/20190508170150/https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://web.archive.org/web/20210708014107/https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.
* https://web.archive.org/web/20220527112908/https://www.riskiq.com/blog/labs/ukraine-malware-infrastructure/ - RISKIQ. (2022, March 15). RiskIQ Threat Intelligence Roundup: Campaigns Targeting Ukraine and Global Malware Infrastructure. Retrieved July 29, 2022.
* https://web.archive.org/web/20220629230035/https://www.prevailion.com/darkwatchman-new-fileless-techniques/ - Smith, S., Stafford, M. (2021, December 14). DarkWatchman: A new evolution in fileless techniques. Retrieved January 10, 2022.
* https://wiki.archlinux.org/title/System_time - ArchLinux. (2024, February 1). System Time. Retrieved March 27, 2024.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.akamai.com/blog/security/catch-me-if-you-can-javascript-obfuscation - Katz, O. (2020, October 26). Catch Me if You Can—JavaScript Obfuscation. Retrieved March 17, 2023.
* https://www.blackhat.com/presentations/bh-dc-08/McFeters-Rios-Carter/Presentation/bh-dc-08-mcfeters-rios-carter.pdf - Nathan McFeters. Billy Kim Rios. Rob Carter.. (2008). URI Use and Abuse. Retrieved February 9, 2024.
* https://www.blackhillsinfosec.com/bypass-web-proxy-filtering/ - Fehrman, B. (2017, April 13). How to Bypass Web-Proxy Filtering. Retrieved September 20, 2019.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.bleepingcomputer.com/news/security/new-rat-malware-gets-commands-via-discord-has-ransomware-feature/ - Abrams, L. (2020, October 23). New RAT malware gets commands via Discord, has ransomware feature. Retrieved April 1, 2021.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.broadcom.com/support/security-center/protection-bulletin/birdyclient-malware-leverages-microsoft-graph-api-for-c-c-communication - Broadcom. (2024, May 2). BirdyClient malware leverages Microsoft Graph API for C&C communication. Retrieved July 1, 2024.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_monitor_permit_list_through_show_process_memory.html#wp3599497760 - Cisco. (2022, August 16). show processes - . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s2.html#wp1896741674 - Cisco. (2023, March 6). show clock detail - Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html - Cisco. (2023, March 7). Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/ - Mudge, R. (2017, February 6). High-reputation Redirectors and Domain Fronting. Retrieved July 11, 2022.
* https://www.computerworld.com/article/2486903/windows-malware-tries-to-infect-android-devices-connected-to-pcs.html - Lucian Constantin. (2014, January 23). Windows malware tries to infect Android devices connected to PCs. Retrieved May 25, 2022.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.crowdstrike.com/blog/how-doppelpaymer-hunts-and-kills-windows-processes/ - Hurley, S. (2021, December 7). Critical Hit: How DoppelPaymer Hunts and Kills Windows Processes. Retrieved January 26, 2022.
* https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/ - Jai Minton. (2023, March 31). How Falcon OverWatch Investigates Malicious Self-Extracting Archives, Decoy Files and Their Hidden Payloads. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/shlayer-malvertising-campaigns-still-using-flash-update-disguise/ - Aspen Lindblom, Joseph Goodwin, and Chris Sheldon. (2021, July 19). Shlayer Malvertising Campaigns Still Using Flash Update Disguise. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/targeted-dharma-ransomware-intrusions-exhibit-consistent-techniques/ - Loui, E. Scheuerman, K. et al. (2020, April 16). Targeted Dharma Ransomware Intrusions Exhibit Consistent Techniques. Retrieved January 26, 2022.
* https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/ - Gavriel, H. (2018, November 27). Malware Mitigation when Direct System Calls are Used. Retrieved September 29, 2021.
* https://www.digicert.com/kb/ssl-certificate-installation.htm - DigiCert. (n.d.). How to Install an SSL Certificate. Retrieved April 19, 2021.
* https://www.dragos.com/blog/industry-news/a-new-water-watering-hole/ - Kent Backman. (2021, May 18). When Intrusions Don’t Align: A New Water Watering Hole and Oldsmar. Retrieved August 18, 2022.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.elastic.co/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.elastic.co/guide/en/security/7.17/shortcut-file-written-or-modified-for-persistence.html#shortcut-file-written-or-modified-for-persistence - Elastic. (n.d.). Shortcut File Written or Modified for Persistence. Retrieved June 1, 2022.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.fireeye.com/blog/threat-research/2012/12/council-foreign-relations-water-hole-attack-details.html - Kindlund, D. (2012, December 30). CFR Watering Hole Attack Details. Retrieved December 18, 2020.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html - Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html - Berry, A., Galang, L., Jiang, G., Leathery, J., Mohandas, R. (2017, April 11). CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler. Retrieved October 27, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html - Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Amanda Steward. (2014). FireEye DLL Side-Loading: A Thorn in the Side of the Anti-Virus Industry. Retrieved March 13, 2020.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.fortinet.com/blog/psirt-blogs/fg-ir-22-369-psirt-analysis -  Guillaume Lovet and Alex Kong. (2023, March 9). Analysis of FG-IR-22-369. Retrieved May 15, 2023.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.gnu.org/software/libc/ - glibc developer community. (2020, February 1). The GNU C Library (glibc). Retrieved June 25, 2020.
* https://www.gnu.org/software/libc/manual/html_node/Creating-a-Process.html - Free Software Foundation, Inc.. (2020, June 18). Creating a Process. Retrieved June 25, 2020.
* https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708 - Huntress. (n.d.). Retrieved March 14, 2024.
* https://www.icann.org/groups/ssac/documents/sac-007-en - ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved March 6, 2017.
* https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me - Invictus Incident Response. (2024, January 31). The curious case of DangerDev@protonmail.me. Retrieved March 19, 2024.
* https://www.kernel.org/doc/html/v4.12/core-api/kernel-api.html - Linux Kernel Organization, Inc. (n.d.). The Linux Kernel API. Retrieved June 25, 2020.
* https://www.macinstruct.com/tutorials/synchronize-your-macs-clock-with-a-time-server/ - Cone, Matt. (2021, January 14). Synchronize your Mac's Clock with a Time Server. Retrieved March 27, 2024.
* https://www.malwarebytes.com/blog/news/2019/12/theres-an-app-for-that-web-skimmers-found-on-paas-heroku - Jérôme Segura. (2019, December 4). There's an app for that: web skimmers found on PaaS Heroku. Retrieved August 18, 2022.
* https://www.malwaretech.com/2015/09/hidden-vnc-for-beginners.html - Hutchins, Marcus. (2015, September 13). Hidden VNC for Beginners. Retrieved November 28, 2023.
* https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits - Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022.
* https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem - ALEXANDER MARVI, BRAD SLAYBAUGH, DAN EBREO, TUFAIL AHMED, MUHAMMAD UMAIR, TINA JOHNSON. (2023, March 16). Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation. Retrieved May 15, 2023.
* https://www.mandiant.com/resources/blog/unc3944-sms-phishing-sim-swapping-ransomware - Mandiant Intelligence. (2023, September 14). Why Are You Texting Me? UNC3944 Leverages SMS Phishing Campaigns for SIM Swapping, Ransomware, Extortion, and Notoriety. Retrieved January 2, 2024.
* https://www.mandiant.com/resources/blog/url-obfuscation-schema-abuse - Nick Simonian. (2023, May 22). Don't @ Me: URL Obfuscation Through Schema Abuse. Retrieved August 4, 2023.
* https://www.mandiant.com/resources/chasing-avaddon-ransomware - Hernandez, A. S. Tarter, P. Ocamp, E. J. (2022, January 19). One Source to Rule Them All: Chasing AVADDON Ransomware. Retrieved January 26, 2022.
* https://www.mandiant.com/resources/reports - Mandiant. (n.d.). Retrieved February 13, 2024.
* https://www.mandiant.com/resources/staying-hidden-on-the-endpoint-evading-detection-with-shellcode - Pena, E., Erikson, C. (2019, October 10). Staying Hidden on the Endpoint: Evading Detection with Shellcode. Retrieved November 29, 2021.
* https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/ - MDSec Research. (2017, July). Categorisation is not a Security Boundary. Retrieved September 20, 2019.
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - MDSec Research. (2020, December). Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams. Retrieved September 29, 2021.
* https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/ - Dominic Chell. (2021, January 1). macOS Post-Exploitation Shenanigans with VSCode Extensions. Retrieved April 20, 2021.
* https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/ - Microsoft. (2022, June 13). BlackCat. Retrieved February 13, 2024.
* https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/ - Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.
* https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ - Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.
* https://www.netskope.com/blog/a-big-catch-cloud-phishing-from-google-app-engine-and-azure-app-service - Ashwin Vamshi. (2020, August 12). A Big Catch: Cloud Phishing from Google App Engine and Azure App Service. Retrieved August 18, 2022.
* https://www.netskope.com/blog/new-phishing-attacks-exploiting-oauth-authorization-flows-part-1 - Jenko Hwong. (2021, August 10). New Phishing Attacks Exploiting OAuth Authorization Flows (Part 1). Retrieved March 19, 2024.
* https://www.netskope.com/blog/targeted-attacks-abusing-google-cloud-platform-open-redirection - Ashwin Vamshi. (2019, January 24). Targeted Attacks Abusing Google Cloud Platform Open Redirection. Retrieved August 18, 2022.
* https://www.optiv.com/insights/source-zero/blog/microsoft-365-oauth-device-code-flow-and-phishing - Optiv. (2021, August 17). Microsoft 365 OAuth Device Code Flow and Phishing. Retrieved March 19, 2024.
* https://www.paloaltonetworks.com/content/dam/pan/en_US/assets/pdf/reports/Unit_42/unit42-wirelurker.pdf - Claud Xiao. (n.d.). WireLurker: A New Era in iOS and OS X Malware. Retrieved July 10, 2017.
* https://www.pcmag.com/encyclopedia/term/double-extension - PCMag. (n.d.). Encyclopedia: double extension. Retrieved August 4, 2021.
* https://www.pcmag.com/news/hackers-try-to-phish-united-nations-staffers-with-fake-login-pages - Kan, M. (2019, October 24). Hackers Try to Phish United Nations Staffers With Fake Login Pages. Retrieved October 20, 2020.
* https://www.picussecurity.com/resource/the-system-information-discovery-technique-explained-mitre-attack-t1082 - YUCEEL, Huseyin Can. Picus Labs. (2022, June 9). The System Information Discovery Technique Explained - MITRE ATT&CK T1082. Retrieved March 27, 2024.
* https://www.picussecurity.com/resource/virtualization/sandbox-evasion-how-attackers-avoid-malware-analysis - YUCEEL, Huseyin Can. Picus Labs. (2022, June 9). Virtualization/Sandbox Evasion - How Attackers Avoid Malware Analysis. Retrieved December 26, 2023.
* https://www.proofpoint.com/sites/default/files/threat-reports/pfpt-us-tr-human-factor-report.pdf - Proofpoint. (n.d.). The Human Factor 2023: Analyzing the cyber attack chain. Retrieved July 20, 2023.
* https://www.proofpoint.com/us/blog/email-and-cloud-threats/cybersecurity-stop-month-qr-code-phishing - Tim Bedard and Tyler Johnson. (2023, October 4). QR Code Scams & Phishing. Retrieved November 27, 2023.
* https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain - Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.
* https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta407-silent-librarian - Proofpoint Threat Insight Team. (2019, September 5). Threat Actor Profile: TA407, the Silent Librarian. Retrieved February 3, 2021.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/blog/identifying-cobalt-strike-servers - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved September 16, 2024.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.rsaconference.com/writable/presentations/file_upload/ht-209_rivner_schwartz.pdf - Rivner, U., Schwartz, E. (2012). They’re Inside… Now What?. Retrieved November 25, 2016.
* https://www.secureworks.com/blog/oauths-device-code-flow-abused-in-phishing-attacks - SecureWorks Counter Threat Unit Research Team. (2021, June 3). OAuth’S Device Code Flow Abused in Phishing Attacks. Retrieved March 19, 2024.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/ - Phil Stokes. (2019, December 5). macOS Red Team: Calling Apple APIs Without Building Binaries. Retrieved July 17, 2020.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.seqrite.com/blog/how-to-avoid-dual-attack-and-vulnerable-files-with-double-extension/ - Seqrite. (n.d.). How to avoid dual attack and vulnerable files with double extension?. Retrieved July 27, 2021.
* https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf - Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.
* https://www.technologyreview.com/2013/08/21/83143/dropbox-and-similar-services-can-sync-malware/ - David Talbot. (2013, August 21). Dropbox and Similar Services Can Sync Malware. Retrieved May 31, 2023.
* https://www.techtarget.com/searchsecurity/tip/Preparing-for-uniform-resource-identifier-URI-exploits - Michael Cobb. (2007, October 11). Preparing for uniform resource identifier (URI) exploits. Retrieved February 9, 2024.
* https://www.trellix.com/blogs/research/beyond-file-search-a-novel-method/ -  Mathanraj Thangaraju, Sijo Jacob. (2023, July 26). Beyond File Search: A Novel Method for Exploiting the "search-ms" URI Protocol Handler. Retrieved March 15, 2024.
* https://www.trendmicro.com/en_us/research/20/i/tricky-forms-of-phishing.html - Babon, P. (2020, September 3). Tricky 'Forms' of Phishing. Retrieved October 20, 2020.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.virustotal.com/en/faq/ - VirusTotal. (n.d.). VirusTotal FAQ. Retrieved May 23, 2019.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/ - Lassalle, D., et al. (2017, November 6). OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society. Retrieved November 6, 2017.
* https://www.volexity.com/blog/2020/11/06/oceanlotus-extending-cyber-espionage-operations-through-fake-websites/ - Adair, S. and Lancaster, T. (2020, November 6). OceanLotus: Extending Cyber Espionage Operations Through Fake Websites. Retrieved November 20, 2020.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/ - ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.
* https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/ - Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.
* https://www.welivesecurity.com/2020/06/11/gamaredon-group-grows-its-game/ - Boutin, J. (2020, June 11). Gamaredon group grows its game. Retrieved June 16, 2020.
* https://www.welivesecurity.com/2022/01/25/watering-hole-deploys-new-macos-malware-dazzlespy-asia/ - M.Léveillé, M., Cherepanov, A.. (2022, January 25). Watering hole deploys new macOS malware, DazzleSpy, in Asia. Retrieved May 6, 2022.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf - Kafka, F. (2018, January). ESET's Guide to Deobfuscating and Devirtualizing FinFisher. Retrieved August 12, 2019.
* https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf - Hromcova, Z. and Cherpanov, A. (2020, June). INVISIMOLE: THE HIDDEN PART OF THE STORY. Retrieved July 16, 2020.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.youtube.com/watch?v=nJ0UsyiUEqQ - French, D., Filar, B.. (2020, March 21). A Chain Is No Stronger Than Its Weakest LNK. Retrieved November 30, 2020.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www.zscaler.com/blogs/security-research/fake-sites-stealing-steam-credentials - ZScaler. (2020, February 11). Fake Sites Stealing Steam Credentials. Retrieved March 8, 2023.
* https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved May 18, 2016.
* https://x.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved September 12, 2024.
* https://x.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved September 12, 2024.
* https://x.com/rfackroyd/status/1639136000755765254 - Ackroyd, R. (2023, March 24). Twitter. Retrieved September 12, 2024.

# Validate the following tools

* Koadic - 1
* NBTscan - 1
* QuasarRAT - 1
* Remcos - 1

# Review the following tool references

* https://blog.talosintelligence.com/2018/08/picking-apart-remcos.html - Brumaghin, E., Unterbrink, H. (2018, August 22). Picking Apart Remcos Botnet-In-A-Box. Retrieved November 6, 2018.
* https://documents.trendmicro.com/assets/tech-brief-untangling-the-patchwork-cyberespionage-group.pdf - Lunghi, D., et al. (2017, December). Untangling the Patchwork Cyberespionage Group. Retrieved July 10, 2018.
* https://github.com/offsecginger/koadic - Magius, J., et al. (2017, July 19). Koadic. Retrieved September 27, 2024.
* https://github.com/quasar/QuasarRAT - MaxXor. (n.d.). QuasarRAT. Retrieved July 10, 2018.
* https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html - Bezroutchko, A. (2019, November 19). NBTscan man page. Retrieved March 17, 2021.
* https://researchcenter.paloaltonetworks.com/2018/06/unit42-sofacy-groups-parallel-attacks/ - Lee, B., Falcone, R. (2018, June 06). Sofacy Group’s Parallel Attacks. Retrieved June 18, 2018.
* https://sectools.org/tool/nbtscan/ - SecTools. (2003, June 11). NBTscan. Retrieved March 17, 2021.
* https://securelist.com/apt10-sophisticated-multi-layered-loader-ecipekac-discovered-in-a41apt-campaign/101519/ - GREAT. (2021, March 30). APT10: sophisticated multi-layered loader Ecipekac discovered in A41APT campaign. Retrieved June 17, 2021.
* https://web.archive.org/web/20180124082756/https://www.riskiq.com/blog/labs/spear-phishing-turkish-defense-contractors/ - Klijnsma, Y. (2018, January 23). Espionage Campaign Leverages Spear Phishing, RATs Against Turkish Defense Contractors. Retrieved November 6, 2018.
* https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html - Hawley et al. (2019, January 29). APT39: An Iranian Cyber Espionage Group Focused on Personal Information. Retrieved February 19, 2019.
* https://www.fortinet.com/blog/threat-research/remcos-a-new-rat-in-the-wild-2.html - Bacurio, F., Salvio, J. (2017, February 14). REMCOS: A New RAT In The Wild. Retrieved November 6, 2018.
* https://www.malwarebytes.com/resources/files/2021/02/lazyscripter.pdf - Jazi, H. (2021, February). LazyScripter: From Empire to double RAT. Retrieved November 24, 2021.
* https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments - Symantec DeepSight Adversary Intelligence Team. (2019, June 20). Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments. Retrieved July 8, 2019.
* https://www.volexity.com/blog/2018/06/07/patchwork-apt-group-targets-us-think-tanks/ - Meltzer, M, et al. (2018, June 07). Patchwork APT Group Targets US Think Tanks. Retrieved July 16, 2018.

# Validate the following malware

* Action RAT - 1
* AuTo Stealer - 1
* Cobalt Strike - 1
* Crimson - 1
* DarkComet - 1
* NETWIRE - 1
* NanoCore - 1
* ObliqueRAT - 1
* Peppy - 1
* PlugX - 1
* PoisonIvy - 1
* RCSession - 1
* Revenge RAT - 1
* ZxxZ - 1
* njRAT - 2

# Review the following malware references

* http://circl.lu/assets/files/tr-12/tr-12-circl-plugx-analysis-v1.pdf - Computer Incident Response Center Luxembourg. (2013, March 29). Analysis of a PlugX variant. Retrieved November 5, 2018.
* http://labs.lastline.com/an-analysis-of-plugx - Vasilenko, R. (2013, December 17). An Analysis of PlugX Malware. Retrieved November 24, 2015.
* http://researchcenter.paloaltonetworks.com/2015/04/unit-42-identifies-new-dragonok-backdoor-malware-deployed-against-japanese-targets/ - Miller-Osborn, J., Grunzweig, J.. (2015, April). Unit 42 Identifies New DragonOK Backdoor Malware Deployed Against Japanese Targets. Retrieved November 4, 2015.
* https://blog.malwarebytes.com/threat-analysis/2012/06/you-dirty-rat-part-1-darkcomet/ - Kujawa, A. (2018, March 27). You dirty RAT! Part 1: DarkComet. Retrieved November 6, 2018.
* https://blog.talosintelligence.com/2021/02/obliquerat-new-campaign.html - Malhotra, A. (2021, March 2). ObliqueRAT returns with new campaign using hijacked websites. Retrieved September 2, 2021.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal. Retrieved September 2, 2021.
* https://blog.talosintelligence.com/2022/05/bitter-apt-adds-bangladesh-to-their.html - Raghuprasad, C . (2022, May 11). Bitter APT adds Bangladesh to their targets. Retrieved June 1, 2022.
* https://blog.trendmicro.com/trendlabs-security-intelligence/autoit-compiled-worm-affecting-removable-media-delivers-fileless-version-of-bladabindi-njrat-backdoor/ - Pascual, C. (2018, November 27). AutoIt-Compiled Worm Affecting Removable Media Delivers Fileless Version of BLADABINDI/njRAT Backdoor. Retrieved June 4, 2019.
* https://cofense.com/upgrades-delivery-support-infrastructure-revenge-rat-malware-bigger-threat/ - Gannon, M. (2019, February 11). With Upgrades in Delivery and Support Infrastructure, Revenge RAT Malware is a Bigger Threat. Retrieved May 1, 2019.
* https://documents.trendmicro.com/assets/white_papers/wp-uncovering-DRBcontrol.pdf - Lunghi, D. et al. (2020, February). Uncovering DRBControl. Retrieved November 12, 2021.
* https://researchcenter.paloaltonetworks.com/2016/02/nanocorerat-behind-an-increase-in-tax-themed-phishing-e-mails/ - Kasza, A., Halfpop, T. (2016, February 09). NanoCoreRAT Behind an Increase in Tax-Themed Phishing E-mails. Retrieved November 9, 2018.
* https://researchcenter.paloaltonetworks.com/2018/08/unit42-gorgon-group-slithering-nation-state-cybercrime/ - Falcone, R., et al. (2018, August 02). The Gorgon Group: Slithering Between Nation State and Cybercrime. Retrieved August 7, 2018.
* https://securelist.com/transparent-tribe-part-1/98127/ - Dedola, G. (2020, August 20). Transparent Tribe: Evolution analysis, part 1. Retrieved September 2, 2021.
* https://securingtomorrow.mcafee.com/mcafee-labs/netwire-rat-behind-recent-targeted-attacks/ - McAfee. (2015, March 2). Netwire RAT Behind Recent Targeted Attacks. Retrieved February 15, 2018.
* https://web.archive.org/web/20190717233006/http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/the-elderwood-project.pdf - O'Gorman, G., and McDonald, G.. (2012, September 6). The Elderwood Project. Retrieved February 15, 2018.
* https://web.archive.org/web/20210825130434/https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://web.archive.org/web/20230115144216/http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* https://web.archive.org/web/20240522112705/https://cofense.com/blog/nanocore-rat-resurfaced-sewers/ - Patel, K. (2018, March 02). The NanoCore RAT Has Resurfaced From the Sewers. Retrieved September 25, 2024.
* https://www.brighttalk.com/webcast/10703/275683 - Davis, S. and Carr, N. (2017, September 21). APT33: New Insights into Iranian Cyber Espionage Group. Retrieved February 15, 2018.
* https://www.cylance.com/content/dam/cylance-web/en-us/resources/knowledge-center/resource-library/reports/WhiteCompanyOperationShaheenReport.pdf?_ga=2.161661948.1943296560.1555683782-1066572390.1555511517 - Livelli, K, et al. (2018, November 12). Operation Shaheen. Retrieved May 1, 2019.
* https://www.digitrustgroup.com/nanocore-not-your-average-rat/ - The DigiTrust Group. (2017, January 01). NanoCore Is Not Your Average RAT. Retrieved November 9, 2018.
* https://www.fireeye.com/blog/threat-research/2013/08/njw0rm-brother-from-the-same-mother.html - Dawda, U. and Villeneuve, N. (2013, August 30). Njw0rm - Brother From the Same Mother. Retrieved June 4, 2019.
* https://www.fireeye.com/blog/threat-research/2014/06/clandestine-fox-part-deux.html - Scott, M.. (2014, June 10). Clandestine Fox, Part Deux. Retrieved January 14, 2016.
* https://www.fireeye.com/blog/threat-research/2017/09/apt33-insights-into-iranian-cyber-espionage.html - O'Leary, J., et al. (2017, September 20). Insights into Iranian Cyber Espionage: APT33 Targets Aerospace and Energy Sectors and has Ties to Destructive Malware. Retrieved February 15, 2018.
* https://www.malwarebytes.com/blog/news/2021/12/sidecopy-apt-connecting-lures-to-victims-payloads-to-infrastructure - Threat Intelligence Team. (2021, December 2). SideCopy APT: Connecting lures victims, payloads to infrastructure. Retrieved June 13, 2022.
* https://www.mandiant.com/sites/default/files/2021-09/rpt-poison-ivy.pdf - FireEye. (2014). POISON IVY: Assessing Damage and Extracting Intelligence. Retrieved September 19, 2024.
* https://www.proofpoint.com/sites/default/files/proofpoint-operation-transparent-tribe-threat-insight-en.pdf - Huss, D. (2016, March 1). Operation Transparent Tribe. Retrieved June 8, 2016.
* https://www.secureworks.com/research/bronze-president-targets-ngos - Counter Threat Unit Research Team. (2019, December 29). BRONZE PRESIDENT Targets NGOs. Retrieved April 13, 2021.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/connect/blogs/life-mars-how-attackers-took-advantage-hope-alien-existance-new-darkmoon-campaign - Payet, L. (2014, September 19). Life on Mars: How attackers took advantage of hope for alien existance in new Darkmoon campaign. Retrieved September 13, 2018.
* https://www.symantec.com/security_response/writeup.jsp?docid=2005-081910-3934-99 - Hayashi, K. (2005, August 18). Backdoor.Darkmoon. Retrieved February 23, 2018.
* https://www.threatminer.org/_reports/2013/fta-1009---njrat-uncovered-1.pdf - Fidelis Cybersecurity. (2013, June 28). Fidelis Threat Advisory #1009: "njRAT" Uncovered. Retrieved June 4, 2019.
* https://www.trendmicro.com/en_us/research/21/d/iron-tiger-apt-updates-toolkit-with-evolved-sysupdate-malware-va.html - Lunghi, D. and Lu, K. (2021, April 9). Iron Tiger APT Updates Toolkit With Evolved SysUpdate Malware. Retrieved November 12, 2021.
* https://www.trendmicro.com/vinfo/us/threat-encyclopedia/malware/DARKCOMET - TrendMicro. (2014, September 03). DARKCOMET. Retrieved November 6, 2018.

