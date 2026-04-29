threat-crank.py 0.2.1
I: searching for regions that match .* israel.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v19.0/enterprise-attack/enterprise-attack.json
# Threat groups

* APT-C-23
* Agrius
* CopyKittens
* HEXANE
* Moses Staff
* POLONIUM
* VOID MANTICORE
* WIRTE

# Validate the following attacks

* Account Manipulation - 1
* Acquire Infrastructure - 1
* Application Window Discovery - 1
* Archive via Custom Method - 1
* Archive via Utility - 3
* Audio Capture - 1
* Automated Collection - 2
* Bidirectional Communication - 2
* Brute Force - 3
* Cloud Accounts - 1
* Cloud Administration Command - 1
* Code Signing - 2
* Command Obfuscation - 2
* Compression - 2
* Credential Stuffing - 1
* Credentials from Password Stores - 1
* Credentials from Web Browsers - 1
* Credentials in Registry - 1
* DLL - 1
* DNS Server - 1
* Data Destruction - 1
* Data Encrypted for Impact - 1
* Data Staged - 1
* Data from Local System - 2
* Deobfuscate/Decode Files or Information - 2
* Disable or Modify Tools - 1
* Disk Content Wipe - 1
* Disk Structure Wipe - 1
* Domain Account - 1
* Domain Accounts - 2
* Domains - 3
* Email Accounts - 4
* Email Addresses - 1
* Encrypted/Encoded File - 1
* Exfiltration Over C2 Channel - 3
* Exfiltration to Cloud Storage - 2
* Exploit Public-Facing Application - 3
* External Remote Services - 1
* Financial Theft - 1
* Gather Victim Identity Information - 2
* Group Policy Modification - 1
* Hidden Window - 2
* Identify Roles - 1
* Impersonation - 2
* Ingress Tool Transfer - 4
* Inhibit System Recovery - 1
* Internal Spearphishing - 1
* Internet Connection Discovery - 1
* Keylogging - 1
* LSASS Memory - 2
* Lateral Tool Transfer - 1
* Local Account - 1
* Local Data Staging - 2
* Local Email Collection - 1
* Local Groups - 1
* Malicious File - 3
* Malicious Link - 1
* Malware - 3
* Masquerade Task or Service - 1
* Masquerading - 1
* Match Legitimate Resource Name or Location - 2
* Native API - 1
* Network Service Discovery - 1
* Non-Standard Port - 1
* Password Guessing - 1
* Password Spraying - 2
* Phishing - 1
* PowerShell - 4
* Process Discovery - 1
* Protocol Tunneling - 1
* Proxy - 2
* Python - 1
* Registry Run Keys / Startup Folder - 1
* Regsvr32 - 1
* Remote Desktop Protocol - 3
* Remote Desktop Software - 1
* Remote Email Collection - 1
* Remote System Discovery - 2
* Rundll32 - 1
* SMB/Windows Admin Shares - 1
* Scheduled Task - 1
* Screen Capture - 1
* Security Account Manager - 1
* Selective Exclusion - 1
* Server - 1
* Sharepoint - 1
* Social Media Accounts - 2
* Software Deployment Tools - 1
* Software Discovery - 1
* Spearphishing Attachment - 1
* Spearphishing Link - 1
* System Checks - 1
* System Information Discovery - 3
* System Network Configuration Discovery - 2
* System Network Connections Discovery - 1
* System Owner/User Discovery - 1
* Tool - 6
* Trusted Relationship - 2
* Upload Malware - 2
* Valid Accounts - 2
* Video Capture - 1
* Virtual Private Server - 1
* Visual Basic - 2
* Vulnerability Scanning - 1
* Web Protocols - 2
* Web Service - 1
* Web Services - 2
* Web Shell - 2
* Windows Command Shell - 2
* Windows Host Firewall - 2
* Windows Management Instrumentation - 1
* Windows Management Instrumentation Event Subscription - 1
* Windows Service - 1

# Validate the following phases

* collection - 18
* command-and-control - 14
* credential-access - 14
* defense-impairment - 6
* discovery - 18
* execution - 19
* exfiltration - 5
* impact - 6
* initial-access - 14
* lateral-movement - 7
* persistence - 13
* privilege-escalation - 11
* reconnaissance - 5
* resource-development - 26
* stealth - 25

# Validate the following platforms

* Android - 1
* Containers - 21
* ESXi - 61
* IaaS - 31
* Identity Provider - 15
* Linux - 118
* Network Devices - 42
* Office Suite - 24
* PRE - 31
* SaaS - 22
* Windows - 178
* macOS - 120

# Validate the following defences


# Validate the following data sources


# Review the following attack references

* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf - Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://media.blackhat.com/bh-us-10/whitepapers/Ryan/BlackHat-USA-2010-Ryan-Getting-In-Bed-With-Robin-Sage-v1.0.pdf - Ryan, T. (2010). “Getting In Bed with Robin Sage.”. Retrieved March 6, 2017.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://www.blackhillsinfosec.com/?p=4645 - Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf - ESET. (2016, October). En Route with Sednit - Part 2: Observing the Comings and Goings. Retrieved November 21, 2016.
* https://adsecurity.org/?p=2716 - Metcalf, S. (2016, March 14). Sneaky Active Directory Persistence #17: Group Policy. Retrieved March 5, 2019.
* https://apnews.com/article/russia-ukraine-technology-business-europe-hacking-ce7a8aca506742ab8e8873e7f9f229c2 - FRANK BAJAK AND RAPHAEL SATTER. (2017, June 30). Companies still hobbled from fearsome cyberattack. Retrieved August 18, 2023.
* https://arstechnica.com/information-technology/2014/06/active-malware-operation-let-attackers-sabotage-us-energy-industry/ - Dan Goodin. (2014, June 30). Active malware operation let attackers sabotage US energy industry. Retrieved March 9, 2017.
* https://arstechnica.com/information-technology/2021/02/armed-with-exploits-hackers-on-the-prowl-for-a-critical-vmware-vulnerability/ - Dan Goodin . (2021, February 25). Code-execution flaw in VMware has a severity rating of 9.8 out of 10. Retrieved April 8, 2025.
* https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/ - Bright, P. (2011, February 15). Anonymous speaks: the inside story of the HBGary hack. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://aws.amazon.com/identity/federation/ - Amazon. (n.d.). Identity Federation in AWS. Retrieved March 13, 2020.
* https://bashfuscator.readthedocs.io/en/latest/Mutators/command_obfuscators/index.html - LeFevre, A. (n.d.). Bashfuscator Command Obfuscators. Retrieved March 17, 2023.
* https://blog.crysys.hu/2013/03/teamspy/ - CrySyS Lab. (2013, March 20). TeamSpy – Obshie manevri. Ispolzovat’ tolko s razreshenija S-a. Retrieved April 11, 2018.
* https://blog.cyberproof.com/blog/double-bounced-attacks-with-email-spoofing-2022-trends - Itkin, Liora. (2022, September 1). Double-bounced attacks with email spoofing . Retrieved February 24, 2023.
* https://blog.harmj0y.net/activedirectory/the-most-dangerous-user-right-you-probably-have-never-heard-of/ - Schroeder, W. (2017, January 10). The Most Dangerous User Right You (Probably) Have Never Heard Of. Retrieved September 23, 2024.
* https://blog.harmj0y.net/redteaming/abusing-gpo-permissions/ - Schroeder, W. (2016, March 17). Abusing GPO Permissions. Retrieved September 23, 2024.
* https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/ - Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63 - Palantir. (2018, December 24). Tampering with Windows Event Tracing: Background, Offense, and Defense. Retrieved April 15, 2026.
* https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments - Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.sygnia.co/luna-moth-false-subscription-scams - Oren Biderman, Tomer Lahiyani, Noam Lifshitz, Ori Porag. (n.d.). LUNA MOTH: THE THREAT ACTORS BEHIND RECENT FALSE SUBSCRIPTION SCAMS. Retrieved February 2, 2023.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A., McKay, K. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal . Retrieved July 29, 2022.
* https://blog.talosintelligence.com/2021/11/kimsuky-abuses-blogs-delivers-malware.html - An, J and Malhotra, A. (2021, November 10). North Korean attackers use malicious blogs to deliver malware to high-profile South Korean targets. Retrieved December 29, 2021.
* https://blog.talosintelligence.com/2022/03/transparent-tribe-new-campaign.html - Malhotra, A., Thattil, J. et al. (2022, March 29). Transparent Tribe campaign uses new bespoke malware to target Indian government officials . Retrieved September 6, 2022.
* https://blog.talosintelligence.com/ipfs-abuse/ - Edmund Brumaghin. (2022, November 9). Threat Spotlight: Cyber Criminal Adoption of IPFS for Phishing, Malware Campaigns. Retrieved March 8, 2023.
* https://blog.talosintelligence.com/who-wasnt-responsible-for-olympic/ - Paul Rascagneres, Martin Lee. (2018, February 26). Who Wasn’t Responsible for Olympic Destroyer?. Retrieved June 14, 2025.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/r980-ransomware-disposable-email-service/ - Antazo, F. and Yambao, M. (2016, August 10). R980 Ransomware Found Abusing Disposable Email Address Service. Retrieved October 13, 2020.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://blogs.technet.microsoft.com/musings_of_a_technical_tam/2012/02/13/group-policy-basics-part-1-understanding-the-structure-of-a-group-policy-object/ - srachui. (2012, February 13). Group Policy Basics – Part 1: Understanding the Structure of a Group Policy Object. Retrieved March 5, 2019.
* https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16 - Bromiley, M. (2016, December 27). Malware Monday: VBScript and VBE Files. Retrieved March 17, 2023.
* https://cantoriscomputing.wordpress.com/2016/07/22/powershell-malware/ - Cantoris. (2016, July 22). PowerShell Malware. Retrieved December 12, 2024.
* https://cdn.logic-control.com/docs/scadafence/Anatomy-Of-A-Targeted-Ransomware-Attack-WP.pdf - Shaked, O. (2020, January 20). Anatomy of a Targeted Ransomware Attack. Retrieved June 18, 2022.
* https://cloud.google.com/blog/topics/threat-intelligence/cosmicenergy-ot-malware-russian-response/ - COSMICENERGY: New OT Malware Possibly Related To Russian Emergency Response Exercises. (2023, May 25). Ken Proska, Daniel Kapellmann Zafra, Keith Lunden, Corey Hildebrandt, Rushikesh Nandedkar, Nathan Brubaker. Retrieved March 18, 2025.
* https://cloud.google.com/blog/topics/threat-intelligence/scandalous-external-detection-using-network-scan-data-and-automation/ - Stephens, A. (2020, July 13). SCANdalous! (External Detection Using Network Scan Data and Automation). Retrieved November 17, 2024.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/solutions/federating-gcp-with-active-directory-introduction - Google. (n.d.). Federating Google Cloud with Active Directory. Retrieved March 13, 2020.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/documentation/coreservices - Apple. (n.d.). Core Services. Retrieved June 25, 2020.
* https://developer.apple.com/documentation/foundation - Apple. (n.d.). Foundation. Retrieved July 1, 2020.
* https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/NetServices/Introduction.html - Apple Inc. (2013, April 23). Bonjour Overview. Retrieved October 11, 2021.
* https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/OSX_Technology_Overview/CocoaApplicationLayer/CocoaApplicationLayer.html#//apple_ref/doc/uid/TP40001067-CH274-SW1 - Apple. (2015, September 16). Cocoa Application Layer. Retrieved June 25, 2020.
* https://digital.nhs.uk/cyber-alerts/2020/cc-3681#summary - NHS Digital. (2020, November 26). Egregor Ransomware The RaaS successor to Maze. Retrieved December 29, 2020.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.aws.amazon.com/systems-manager/latest/userguide/run-command.html - AWS. (n.d.). AWS Systems Manager Run Command. Retrieved March 13, 2023.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8 - Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1 - Wheeler, S. et al.. (2019, May 1). About PowerShell.exe. Retrieved October 11, 2019.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/windows-server/identity/ad-fs/deployment/how-to-connect-fed-azure-adfs - Microsoft. (n.d.). Deploying Active Directory Federation Services in Azure. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata - Microsoft. (2018, April 12). CryptUnprotectData function. Retrieved June 18, 2019.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts - Microsoft. (2019, August 23). Active Directory Accounts. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4738 - Lich, B., Miroshnikov, A. (2017, April 5). 4738(S): A user account was changed. Retrieved June 30, 2017.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/api/ - Microsoft. (n.d.). Programming reference for the Win32 API. Retrieved March 15, 2020.
* https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry - Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/sysinternals/downloads/sysmon - Russinovich, M. & Garnier, T. (2017, May 22). Sysmon v6.20. Retrieved December 13, 2017.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697 - Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection - Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.
* https://docs.ostorlab.co/kb/IPA_URL_SCHEME_HIJACKING/index.html - Ostorlab. (n.d.). iOS URL Scheme Hijacking. Retrieved February 9, 2024.
* https://documents.trendmicro.com/assets/wp/wp-criminal-hideouts-for-lease.pdf - Max Goncharov. (2015, July 15). Criminal Hideouts for Lease: Bulletproof Hosting Services. Retrieved March 6, 2017.
* https://dotnet.microsoft.com/learn/dotnet/what-is-dotnet-framework - Microsoft. (n.d.). What is .NET Framework?. Retrieved March 15, 2020.
* https://drive.google.com/file/d/1t0jn3xr4ff2fR30oQAUn_RsWSnMpOAQc/edit - Torello, A. & Guibernau, F. (n.d.). Environment Awareness. Retrieved September 13, 2024.
* https://eclecticlight.co/2020/11/16/checks-on-executable-code-in-catalina-and-big-sur-a-first-draft/ - Howard Oakley. (2020, November 16). Checks on executable code in Catalina and Big Sur: a first draft. Retrieved September 21, 2022.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://github.com/Exploit-install/PSAttack-1 - Haight, J. (2016, April 21). PS>Attack. Retrieved September 27, 2024.
* https://github.com/Neohapsis/creddump7 - Flathers, R. (2018, February 19). creddump7. Retrieved April 11, 2018.
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml - Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.
* https://github.com/danielbohannon/Invoke-DOSfuscation - Bohannon, D. (2018, March 19). Invoke-DOSfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Invoke-Obfuscation - Bohannon, D. (2016, September 24). Invoke-Obfuscation. Retrieved March 17, 2023.
* https://github.com/dxa4481/truffleHog - Dylan Ayrey. (2016, December 31). truffleHog. Retrieved October 19, 2020.
* https://github.com/gentilkiwi/mimikatz/issues/92 - Warren, J. (2017, June 22). lsadump::changentlm and lsadump::setntlm work, but generate Windows events #92. Retrieved December 4, 2017.
* https://github.com/gremwell/o365enum - gremwell. (2020, March 24). Office 365 User Enumeration. Retrieved May 27, 2022.
* https://github.com/gtworek/PSBits/tree/master/NoRunDll - gtworek. (2019, December 17). NoRunDll. Retrieved August 23, 2021.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/michenriksen/gitrob - Michael Henriksen. (2018, June 9). Gitrob: Putting the Open Source in OSINT. Retrieved October 19, 2020.
* https://github.com/nsacyber/Mitigating-Web-Shells -  NSA Cybersecurity Directorate. (n.d.). Mitigating Web Shells. Retrieved July 22, 2021.
* https://github.com/putterpanda/mimikittenz - Jamieson O'Reilly (putterpanda). (2016, July 4). mimikittenz. Retrieved June 20, 2019.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md - Red Canary - Atomic Red Team. (n.d.). T1053.005 - Scheduled Task/Job: Scheduled Task. Retrieved June 19, 2024.
* https://go.crowdstrike.com/rs/281-OBQ-266/images/15GlobalThreatReport.pdf - CrowdStrike Intelligence. (2016). 2015 Global Threat Report. Retrieved April 11, 2018.
* https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/ - GrimHacker. (2017, July 24). Office365 ActiveSync Username Enumeration. Retrieved December 9, 2021.
* https://insight-jp.nttsecurity.com/post/102hf3q/flagpro-the-new-malware-used-by-blacktech - Hada, H. (2021, December 28).  Flagpro The new malware used by BlackTech. Retrieved March 25, 2022.
* https://krebsonsecurity.com/2018/11/that-domain-you-forgot-to-renew-yeah-its-now-stealing-credit-cards/ - Krebs, B. (2018, November 13). That Domain You Forgot to Renew? Yeah, it’s Now Stealing Credit Cards. Retrieved September 20, 2019.
* https://krebsonsecurity.com/2024/03/thread-hijacking-phishes-that-prey-on-your-curiosity/ - Brian Krebs. (2024, March 28). Thread Hijacking: Phishes That Prey on Your Curiosity. Retrieved September 27, 2024.
* https://labs.detectify.com/writeups/slack-bot-token-leakage-exposing-business-critical-information/ - Detectify. (2016, April 28). Slack bot token leakage exposing business critical information. Retrieved November 17, 2024.
* https://labs.guard.io/etherhiding-hiding-web2-malicious-code-in-web3-smart-contracts-65ea78efad16 - Nati Tal and Oleg Zaytsev. (2023, October 13). “EtherHiding” — Hiding Web2 Malicious Code in Web3 Smart Contracts. Retrieved May 22, 2025.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://learn.microsoft.com/en-us/azure/virtual-machines/run-command-overview - Microsoft. (2023, March 10). Run scripts in your VM by using Run Command. Retrieved March 13, 2023.
* https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637 - Microsoft. (2014, May 13). Microsoft Security Advisory 2269637: Insecure Library Loading Could Allow Remote Code Execution. Retrieved January 30, 2025.
* https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow - Microsoft Windows Server. (2023, February 3). Diskshadow. Retrieved November 21, 2023.
* https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa - Microsoft. (n.d.). CreateProcess function. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection?redirectedfrom=MSDN - Microsoft. (2023, October 12). Dynamic-link library redirection. Retrieved January 30, 2025.
* https://learn.microsoft.com/en-us/windows/win32/sbscs/manifests?redirectedfrom=MSDN - Microsoft. (2021, January 7). Manifests. Retrieved January 30, 2025.
* https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page?redirectedfrom=MSDN - Microsoft. (2023, March 7). Retrieved February 13, 2024.
* https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedcommand-base64encodedcommand - Microsoft. (2023, February 8). about_PowerShell_exe: EncodedCommand. Retrieved March 17, 2023.
* https://linux.die.net/man/1/groups - MacKenzie, D. and Youngman, J. (n.d.). groups(1) - Linux man page. Retrieved January 11, 2024.
* https://linux.die.net/man/1/id - MacKenzie, D. and Robbins, A. (n.d.). id(1) - Linux man page. Retrieved January 11, 2024.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://lolbas-project.github.io/lolbas/Binaries/DeviceCredentialDeployment/ - Elliot Killick. (n.d.). /DeviceCredentialDeployment.exe. Retrieved July 22, 2025.
* https://lolbas-project.github.io/lolbas/Binaries/Diantz/ - Living Off The Land Binaries, Scripts and Libraries (LOLBAS). (n.d.). Diantz.exe. Retrieved October 25, 2021.
* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/ - LOLBAS. (n.d.). Regsvr32.exe. Retrieved July 31, 2019.
* https://lolbas-project.github.io/lolbas/Libraries/Ieframe/ - lolbas project. (n.d.). Ieframe.dll. Retrieved October 5, 2025.
* https://lolbas-project.github.io/lolbas/Libraries/Zipfldr/ - lolbas project. (n.d.). Zipfldr.dll. Retrieved October 5, 2025.
* https://man7.org/linux/man-pages//man7/libc.7.html - Kerrisk, M. (2016, December 12). libc(7) — Linux manual page. Retrieved June 25, 2020.
* https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF - Australian Cyber Security Centre. National Security Agency. (2020, April 21). Detect and Prevent Web Shell Malware. Retrieved February 9, 2024.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2018/03/07180722/Report_Shamoon_StoneDrill_final.pdf - Kaspersky Lab. (2017, March 7). From Shamoon to StoneDrill: Wipers attacking Saudi organizations and beyond. Retrieved March 14, 2019.
* https://medium.com/@knownsec404team/love-and-hate-under-war-the-gamacopy-organization-which-imitates-the-russian-gamaredon-uses-560ba5e633fa - Knownsec 404 Advanced Threat Intelligence team. (2025, January 21). Love and hate under war: The GamaCopy organization, which imitates the Russian Gamaredon, uses military — related bait to launch attacks on Russia. Retrieved June 14, 2025.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2 - Koczwara, M. (2021, September 7). Hunting Cobalt Strike C2 with Shodan. Retrieved October 12, 2021.
* https://news.risky.biz/risky-bulletin-threat-actor-impersonates-fsb-apt-for-months-to-target-russian-orgs/ - Catalin Cimpanu. (2025, January 22). Risky Bulletin: Threat actor impersonates FSB APT for months to target Russian orgs. Retrieved June 14, 2025.
* https://news.sophos.com/en-us/2023/05/03/doubled-dll-sideloading-dragon-breath/ - Gabor Szappanos. (2023, May 3). A doubled “Dragon Breath” adds new air to DLL sideloading attacks. Retrieved October 3, 2025.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://o365blog.com/post/just-looking/ - Dr. Nestori Syynimaa. (2020, June 13). Just looking: Azure Active Directory reconnaissance as an outsider. Retrieved May 27, 2022.
* https://objective-see.com/blog/blog_0x25.html - Patrick Wardle. (n.d.). Retrieved March 20, 2018.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ - de Plaa, C. (2019, June 19). Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR. Retrieved September 29, 2021.
* https://owasp.org/www-community/attacks/Binary_planting - OWASP. (n.d.). Binary Planting. Retrieved January 30, 2025.
* https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-014_Vulnerability_Scanning - OWASP. (n.d.). OAT-014 Vulnerability Scanning. Retrieved October 20, 2020.
* https://pentestlab.blog/2017/04/19/stored-credentials/ - netbiosX. (2017, April 19). Stored Credentials. Retrieved April 6, 2018.
* https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/ - Arthur Vaiselbuh, Peleg Cabra. (2024, November 7). Evasive ZIP Concatenation: Trojan Targets Windows Users. Retrieved March 3, 2025.
* https://posts.specterops.io/death-from-above-lateral-movement-from-azure-to-on-prem-ad-d18cb3959d4d - Andy Robbins. (2020, August 17). Death from Above: Lateral Movement from Azure to On-Prem AD. Retrieved March 13, 2023.
* https://posts.specterops.io/managed-identity-attack-paths-part-1-automation-accounts-82667d17187a?gi=6a9daedade1c - Andy Robbins. (2022, June 6). Managed Identity Attack Paths, Part 1: Automation Accounts. Retrieved March 18, 2025.
* https://powershellmagazine.com/2014/07/16/investigating-powershell-attacks/ - Hastings, M. (2014, July 16). Investigating PowerShell Attacks. Retrieved December 1, 2021.
* https://practical365.com/clients/office-365-proplus/outlook-cached-mode-ost-file-sizes/ - N. O'Bryan. (2018, May 30). Managing Outlook Cached Mode and OST File Sizes. Retrieved February 19, 2020.
* https://redcanary.com/threat-detection-report/techniques/powershell/ - Red Canary. (n.d.). 2022 Threat Detection Report: PowerShell. Retrieved March 17, 2023.
* https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls - Feichter, D. (2023, June 30). Direct Syscalls vs Indirect Syscalls. Retrieved September 27, 2023.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://researchcenter.paloaltonetworks.com/2018/09/unit42-oilrig-targets-middle-eastern-government-adds-evasion-techniques-oopsie/ - Falcone, R., et al. (2018, September 04). OilRig Targets a Middle Eastern Government and Adds Evasion Techniques to OopsIE. Retrieved September 24, 2018.
* https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/ - Gietzen, S. (n.d.). S3 Ransomware Part 1: Attack Vector. Retrieved April 14, 2021.
* https://rhinosecuritylabs.com/aws/s3-ransomware-part-2-prevention-and-defense/ - Spencer Gietzen. (n.d.). AWS Simple Storage Service S3 Ransomware Part 2: Prevention and Defense. Retrieved March 21, 2023.
* https://securelist.com/bluenoroff-methods-bypass-motw/108383/ - Seongsu Park. (2022, December 27). BlueNoroff introduces new methods bypassing MoTW. Retrieved July 22, 2025.
* https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/ - Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/other-blogs/mcafee-labs/stopping-malware-fake-virtual-machine/ - Roccia, T. (2017, January 19). Stopping Malware With a Fake Virtual Machine. Retrieved April 17, 2019.
* https://securityintelligence.com/anatomy-of-an-hvnc-attack/ - Keshet, Lior. Kessem, Limor. (2017, January 25). Anatomy of an hVNC Attack. Retrieved November 28, 2023.
* https://securityintelligence.com/posts/brazking-android-malware-upgraded-targeting-brazilian-banks/ - Shahar Tavor. (n.d.). BrazKing Android Malware Upgraded and Targeting Brazilian Banks. Retrieved March 24, 2023.
* https://securitylabs.datadoghq.com/articles/malicious-pypi-package-targeting-highly-specific-macos-machines/ -  Sebastian Obregoso  and Christophe Tafani-Dereeper. (2024, May 23). Malicious PyPI packages targeting highly specific MacOS machines. Retrieved May 22, 2025.
* https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved November 17, 2024.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://stackoverflow.com/questions/2913816/how-to-find-the-location-of-the-scheduled-tasks-folder - Stack Overflow. (n.d.). How to find the location of the Scheduled Tasks folder. Retrieved June 19, 2024.
* https://support.apple.com/guide/remote-desktop/set-up-a-computer-running-vnc-software-apdbed09830/mac - Apple Support. (n.d.). Set up a computer running VNC software for Remote Desktop. Retrieved August 18, 2021.
* https://support.google.com/chrome/answer/1649523 - Google. (n.d.). Retrieved March 14, 2024.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.microsoft.com/en-us/topic/partners-offer-delegated-administration-26530dc0-ebba-415b-86b1-b55bc06b073e?ui=en-us&rs=en-us&ad=us - Microsoft. (n.d.). Partners: Offer delegated administration. Retrieved May 27, 2022.
* https://support.office.com/en-us/article/configure-audit-settings-for-a-site-collection-a9920c97-38c0-44f2-8bcb-4cf1e2ae22d2 - Microsoft. (2017, July 19). Configure audit settings for a site collection. Retrieved April 4, 2018.
* https://support.office.com/en-us/article/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790 - Microsoft. (n.d.). Introduction to Outlook Data Files (.pst and .ost). Retrieved February 19, 2020.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://sysdig.com/blog/googles-vertex-ai-platform-freejacked/ - Clark, Michael. (2023, August 14). Google’s Vertex AI Platform Gets Freejacked. Retrieved February 28, 2024.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://techcommunity.microsoft.com/t5/windows-it-pro-blog/wmi-command-line-wmic-utility-deprecation-next-steps/ba-p/4039242 - Microsoft. (2024, January 26). WMIC Deprecation. Retrieved February 13, 2024.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc772408.aspx - Microsoft. (n.d.). Services. Retrieved June 7, 2016.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://thehackernews.com/2023/04/hackers-using-self-extracting-archives.html - Ravie Lakshmanan. (2023, April 5). Hackers Using Self-Extracting Archives Exploit for Stealthy Backdoor Attacks. Retrieved March 3, 2025.
* https://thehackernews.com/expert-insights/2024/05/github-abuse-flaw-shows-why-we-cant.html - Dvir Sasson. (2024, May 13). GitHub Abuse Flaw Shows Why We Can't Shrug Off Abuse Vulnerabilities in Security. Retrieved March 31, 2025.
* https://themittenmac.com/what-does-apt-activity-look-like-on-macos/ - Jaron Bradley. (2021, November 14). What does APT Activity Look Like on macOS?. Retrieved January 19, 2022.
* https://therecord.media/fbi-fin7-hackers-target-us-companies-with-badusb-devices-to-install-ransomware/ - The Record. (2022, January 7). FBI: FIN7 hackers target US companies with BadUSB devices to install ransomware. Retrieved January 14, 2022.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/ - Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.
* https://threatpost.com/hacker-puts-hosting-service-code-spaces-out-of-business/106761/ - Mimoso, M.. (2014, June 18). Hacker Puts Hosting Service Code Spaces Out of Business. Retrieved December 15, 2020.
* https://undocumented.ntinternals.net/ - The NTinterlnals.net team. (n.d.). Nowak, T. Retrieved June 25, 2020.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://unit42.paloaltonetworks.com/dll-hijacking-techniques/ - Tom Fakterman, Chen Erlich, & Assaf Dahan. (2024, February 22). Intruders in the Library: Exploring DLL Hijacking. Retrieved January 30, 2025.
* https://unit42.paloaltonetworks.com/dns-tunneling-how-dns-can-be-abused-by-malicious-actors/ - Hinchliffe, A. (2019, March 15). DNS Tunneling: how DNS can be (ab)used by malicious actors. Retrieved October 3, 2020.
* https://unit42.paloaltonetworks.com/examining-vba-initiated-infostealer-campaign/ - Vicky Ray and Rob Downs. (2014, October 29). Examining a VBA-Initiated Infostealer Campaign. Retrieved March 13, 2023.
* https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/ - Chen, J. et al. (2021, February 3). Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes. Retrieved April 5, 2021.
* https://unit42.paloaltonetworks.com/luna-moth-callback-phishing/ - Kristopher Russo. (n.d.). Luna Moth Callback Phishing Campaign. Retrieved February 2, 2023.
* https://unit42.paloaltonetworks.com/medusa-ransomware-escalation-new-leak-site/ - Anthony Galiette, Doel Santos. (2024, January 11). Medusa Ransomware Turning Your Files into Stone. Retrieved October 15, 2025.
* https://unit42.paloaltonetworks.com/purpleurchin-steals-cloud-resources/ - Gamazo, William. Quist, Nathaniel.. (2023, January 5). PurpleUrchin Bypasses CAPTCHA and Steals Cloud Platform Resources. Retrieved February 28, 2024.
* https://unit42.paloaltonetworks.com/shamoon-3-targets-oil-gas-organization/ - Falcone, R. (2018, December 13). Shamoon 3 Targets Oil and Gas Organization. Retrieved March 14, 2019.
* https://us-cert.cisa.gov/APTs-Targeting-IT-Service-Provider-Customers - CISA. (n.d.). APTs Targeting IT Service Provider Customers. Retrieved November 16, 2020.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a - CISA. (2021, May 6). Analysis Report (AR21-126A) FiveHands Ransomware. Retrieved June 7, 2021.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://wald0.com/?p=179 - Robbins, A. (2018, April 2). A Red Teamer’s Guide to GPOs and OUs. Retrieved March 5, 2019.
* https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://web.archive.org/web/20160226161828/https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Unraveling the Long Thread of the Sony Attack. Retrieved February 25, 2016.
* https://web.archive.org/web/20160303200515/https:/operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-Destructive-Malware-Report.pdf - Novetta Threat Research Group. (2016, February 24). Operation Blockbuster: Destructive Malware Report. Retrieved November 17, 2024.
* https://web.archive.org/web/20160327101330/http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* https://web.archive.org/web/20160629094859/https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved November 17, 2024.
* https://web.archive.org/web/20170923102302/https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://web.archive.org/web/20171223000420/https://www.riskiq.com/blog/labs/lazarus-group-cryptocurrency/ - RISKIQ. (2017, December 20). Mining Insights: Infrastructure Analysis of Lazarus Group Cyber Attacks on the Cryptocurrency Industry. Retrieved July 29, 2022.
* https://web.archive.org/web/20190508170150/https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://web.archive.org/web/20191115195333/https://www.crowdstrike.com/blog/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 17, 2024.
* https://web.archive.org/web/20200302085133/https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance_Operation_Cleaver_Report.pdf - Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.
* https://web.archive.org/web/20210126065851/https://www.fireeye.com/blog/threat-research/2016/11/fireeye_respondsto.html - FireEye. (2016, November 30). FireEye Responds to Wave of Destructive Cyber Attacks in Gulf Region. Retrieved November 17, 2024.
* https://web.archive.org/web/20210708014107/https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved November 17, 2024.
* https://web.archive.org/web/20211024160454/https://www.fireeye.com/content/dam/fireeye-www/current-threats/pdfs/rpt-mtrends-2016.pdf - Mandiant. (2016, February 25). Mandiant M-Trends 2016. Retrieved November 17, 2024.
* https://web.archive.org/web/20220224041316/https:/www.pwc.co.uk/cyber-security/pdf/cloud-hopper-report-final-v4.pdf - PwC and BAE Systems. (2017, April). Operation Cloud Hopper. Retrieved April 5, 2017.
* https://web.archive.org/web/20220527112908/https://www.riskiq.com/blog/labs/ukraine-malware-infrastructure/ - RISKIQ. (2022, March 15). RiskIQ Threat Intelligence Roundup: Campaigns Targeting Ukraine and Global Malware Infrastructure. Retrieved July 29, 2022.
* https://web.archive.org/web/20220629230035/https://www.prevailion.com/darkwatchman-new-fileless-techniques/ - Smith, S., Stafford, M. (2021, December 14). DarkWatchman: A new evolution in fileless techniques. Retrieved January 10, 2022.
* https://web.archive.org/web/20221203203722/https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved November 17, 2024.
* https://web.archive.org/web/20230602111604/https://www.opm.gov/cybersecurity/cybersecurity-incidents/ - Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved September 16, 2024.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.akamai.com/blog/security/catch-me-if-you-can-javascript-obfuscation - Katz, O. (2020, October 26). Catch Me if You Can—JavaScript Obfuscation. Retrieved March 17, 2023.
* https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/ - Amnesty International Security Lab. (2021, July 18). Forensic Methodology Report: How to catch NSO Group’s Pegasus. Retrieved February 22, 2022.
* https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/ - Michael Katchinskiy and Assaf Morag. (2023, April 21). First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters. Retrieved March 24, 2025.
* https://www.attackify.com/blog/rundll32_execution_order/ - Attackify. (n.d.). Rundll32.exe Obscurity. Retrieved August 23, 2021.
* https://www.bbc.com/news/technology-60933174 - Joe Tidy. (2022, March 30). Ronin Network: What a $600m hack says about the state of crypto. Retrieved August 18, 2023.
* https://www.blackhat.com/presentations/bh-dc-08/McFeters-Rios-Carter/Presentation/bh-dc-08-mcfeters-rios-carter.pdf - Nathan McFeters. Billy Kim Rios. Rob Carter.. (2008). URI Use and Abuse. Retrieved February 9, 2024.
* https://www.blackhillsinfosec.com/bypass-web-proxy-filtering/ - Fehrman, B. (2017, April 13). How to Bypass Web-Proxy Filtering. Retrieved September 20, 2019.
* https://www.bleepingcomputer.com/news/security/hackers-use-binance-smart-chain-contracts-to-store-malicious-scripts/ - Bill Toulas. (2023, October 13). Hackers use Binance Smart Chain contracts to store malicious scripts. Retrieved May 22, 2025.
* https://www.bleepingcomputer.com/news/security/new-godlua-malware-evades-traffic-monitoring-via-dns-over-https/ - Gatlan, S. (2019, July 3). New Godlua Malware Evades Traffic Monitoring via DNS over HTTPS. Retrieved March 15, 2020.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.broadcom.com/support/security-center/protection-bulletin/birdyclient-malware-leverages-microsoft-graph-api-for-c-c-communication - Broadcom. (2024, May 2). BirdyClient malware leverages Microsoft Graph API for C&C communication. Retrieved July 1, 2024.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/ - Baskin, B. (2020, July 8). TAU Threat Discovery: Conti Ransomware. Retrieved February 17, 2021.
* https://www.cisa.gov/sites/default/files/Ransomware_Trifold_e-version.pdf - FBI. (n.d.). Ransomware. Retrieved August 18, 2023.
* https://www.cisa.gov/uscert/ncas/alerts/aa22-074a - Cybersecurity and Infrastructure Security Agency. (2022, March 15). Russian State-Sponsored Cyber Actors Gain Network Access by Exploiting Default Multifactor Authentication Protocols and “PrintNightmare” Vulnerability. Retrieved March 16, 2022.
* https://www.cisa.gov/uscert/ncas/alerts/aa23-025a - CISA. (n.d.). Protecting Against Malicious Use of Remote Monitoring and Management Software. Retrieved February 2, 2023.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/F_through_K.html#wp2829794668 - Cisco. (2022, August 16). format - Cisco IOS Configuration Fundamentals Command Reference. Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_monitor_permit_list_through_show_process_memory.html#wp3599497760 - Cisco. (2022, August 16). show processes - . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_protocols_through_showmon.html#wp2760878733 - Cisco. (2022, August 16). show running-config - Cisco IOS Configuration Fundamentals Command Reference . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html - Cisco. (2023, March 7). Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.cloudflare.com/learning/email-security/what-is-vendor-email-compromise/#:~:text=Vendor%20email%20compromise%2C%20also%20referred,steal%20from%20that%20vendor%27s%20customers. - CloudFlare. (n.d.). What is vendor email compromise (VEC)?. Retrieved September 12, 2023.
* https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/ - Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.
* https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/ - Mudge, R. (2017, February 6). High-reputation Redirectors and Domain Fronting. Retrieved July 11, 2022.
* https://www.crowdstrike.com/blog/double-trouble-ransomware-data-leak-extortion-part-1/ - Crowdstrike. (2020, September 24). Double Trouble: Ransomware with Data Leak Extortion, Part 1. Retrieved December 6, 2023.
* https://www.crowdstrike.com/blog/how-crowdstrike-falcon-protects-against-wiper-malware-used-in-ukraine-attacks/ - Thomas, W. et al. (2022, February 25). CrowdStrike Falcon Protects from New Wiper Malware Used in Ukraine Cyberattacks. Retrieved March 25, 2022.
* https://www.crowdstrike.com/blog/observations-from-the-stellarparticle-campaign/ - CrowdStrike. (2022, January 27). Early Bird Catches the Wormhole: Observations from the StellarParticle Campaign. Retrieved February 7, 2022.
* https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/ - Jai Minton. (2023, March 31). How Falcon OverWatch Investigates Malicious Self-Extracting Archives, Decoy Files and Their Hidden Payloads. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/shlayer-malvertising-campaigns-still-using-flash-update-disguise/ - Aspen Lindblom, Joseph Goodwin, and Chris Sheldon. (2021, July 19). Shlayer Malvertising Campaigns Still Using Flash Update Disguise. Retrieved March 29, 2024.
* https://www.crowdstrike.com/en-us/blog/4-ways-adversaries-hijack-dlls/ -  falcon.overwatch.team. (2022, December 30). 4 Ways Adversaries Hijack DLLs — and How CrowdStrike Falcon OverWatch Fights Back. Retrieved January 30, 2025.
* https://www.crowdstrike.com/en-us/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/ - Michael Dawson. (2021, August 30). Hypervisor Jackpotting, Part 2: eCrime Actors Increase Targeting of ESXi Servers with Ransomware. Retrieved March 26, 2025.
* https://www.crowdstrike.com/en-us/cybersecurity-101/threat-intelligence/business-email-compromise-bec/ - Bart Lenaerts-Bergmans. (2023, August 8). What is Business Email Compromise?. Retrieved April 15, 2026.
* https://www.cyberbit.com/blog/endpoint-security/malware-mitigation-when-direct-system-calls-are-used/ - Gavriel, H. (2018, November 27). Malware Mitigation when Direct System Calls are Used. Retrieved September 29, 2021.
* https://www.cybereason.com/blog/behind-closed-doors-the-rise-of-hidden-malicious-remote-access - Cybereason Security Services Team. (n.d.). Behind Closed Doors: The Rise of Hidden Malicious Remote Access. Retrieved July 22, 2025.
* https://www.cybereason.com/blog/cybereason-vs.-blackcat-ransomware - Cybereason Nocturnus. (n.d.). Cybereason vs. BlackCat Ransomware. Retrieved March 26, 2025.
* https://www.cynet.com/attack-techniques-hands-on/defense-evasion-techniques/ - Ariel silver. (2022, February 1). Defense Evasion Techniques. Retrieved April 8, 2022.
* https://www.darkreading.com/attacks-breaches/code-hosting-service-shuts-down-after-cyber-attack -  Brian Prince. (2014, June 20). Code Hosting Service Shuts Down After Cyber Attack. Retrieved March 21, 2023.
* https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2 - Gilboa, A. (2021, February 16). LSASS Memory Dumps are Stealthier than Ever Before - Part 2. Retrieved December 27, 2023.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.elastic.co/security-labs/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 17, 2024.
* https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf - F-Secure Labs. (2015, September 17). The Dukes: 7 years of Russian cyberespionage. Retrieved December 10, 2015.
* https://www.fbi.gov/file-repository/fy-2022-fbi-congressional-report-business-email-compromise-and-real-estate-wire-fraud-111422.pdf/view - FBI. (2022). FBI 2022 Congressional Report on BEC and Real Estate Wire Fraud. Retrieved August 18, 2023.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html - Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
* https://www.fireeye.com/blog/threat-research/2017/07/hawkeye-malware-distributed-in-phishing-campaign.html - Swapnil Patil, Yogesh Londhe. (2017, July 25). HawkEye Credential Theft Malware Distributed in Recent Phishing Campaign. Retrieved June 18, 2019.
* https://www.fireeye.com/blog/threat-research/2021/06/darkside-affiliate-supply-chain-software-compromise.html - FireEye. (2021, June 16). Smoking Out a DARKSIDE Affiliate’s Supply Chain Software Compromise. Retrieved September 22, 2021.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.forbes.com/sites/runasandvik/2014/01/14/attackers-scrape-github-for-cloud-service-credentials-hijack-account-to-mine-virtual-currency/#242c479d3196 - Sandvik, R. (2014, January 14). Attackers Scrape GitHub For Cloud Service Credentials, Hijack Account To Mine Virtual Currency. Retrieved October 19, 2020.
* https://www.forescout.com/resources/analysis-of-conti-leaks/ - Vedere Labs. (2022, March 11). Analysis of Conti Leaks. Retrieved May 22, 2025.
* https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html - Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.gnu.org/software/libc/ - glibc developer community. (2020, February 1). The GNU C Library (glibc). Retrieved June 25, 2020.
* https://www.gnu.org/software/libc/manual/html_node/Creating-a-Process.html - Free Software Foundation, Inc.. (2020, June 18). Creating a Process. Retrieved June 25, 2020.
* https://www.hackers-arise.com/email-scraping-and-maltego - Hackers Arise. (n.d.). Email Scraping and Maltego. Retrieved October 20, 2020.
* https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c - Halcyon RISE Team. (2025, January 13). Abusing AWS Native Services: Ransomware Encrypting S3 Buckets with SSE-C. Retrieved March 18, 2025.
* https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/ - Hexacorn. (2013, December 8). Beyond good ol’ Run key, Part 5. Retrieved August 14, 2024.
* https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708 - Huntress. (n.d.). Retrieved March 14, 2024.
* https://www.ic3.gov/Media/News/2022/220818.pdf - FBI. (2022, August 18). Proxies and Configurations Used for Credential Stuffing Attacks on Online Customer Accounts . Retrieved July 6, 2023.
* https://www.ic3.gov/Media/PDF/AnnualReport/2022_IC3Report.pdf - IC3. (2022). 2022 Internet Crime Report. Retrieved August 18, 2023.
* https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me - Invictus Incident Response. (2024, January 31). The curious case of DangerDev@protonmail.me. Retrieved March 19, 2024.
* https://www.justice.gov/opa/press-release/file/1092091/download - Department of Justice. (2018, September 6). Criminal Complaint - United States of America v. PARK JIN HYOK. Retrieved March 29, 2019.
* https://www.justice.gov/usao-cdca/pr/3-north-korean-military-hackers-indicted-wide-ranging-scheme-commit-cyber-attacks-and - Department of Justice. (2021). 3 North Korean Military Hackers Indicted in Wide-Ranging Scheme to Commit Cyber-attacks and Financial Crimes Across the Globe. Retrieved August 18, 2023.
* https://www.justice.gov/usao-ndca/pr/san-jose-man-pleads-guilty-damaging-cisco-s-network - DOJ. (2020, August 26). San Jose Man Pleads Guilty To Damaging Cisco’s Network. Retrieved December 15, 2020.
* https://www.kernel.org/doc/html/v4.12/core-api/kernel-api.html - Linux Kernel Organization, Inc. (n.d.). The Linux Kernel API. Retrieved June 25, 2020.
* https://www.kroll.com/en/insights/publications/cyber/idatloader-distribution - Dave Truman. (2024, June 24). Novel Technique Combination Used In IDATLOADER Distribution. Retrieved January 30, 2025.
* https://www.malwaretech.com/2015/09/hidden-vnc-for-beginners.html - Hutchins, Marcus. (2015, September 13). Hidden VNC for Beginners. Retrieved November 28, 2023.
* https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits - Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022.
* https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft - Douglas Bienstock. (2022, August 18). You Can’t Audit Me: APT29 Continues Targeting Microsoft 365. Retrieved February 23, 2023.
* https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem - Marvi, A. et al.. (2023, March 16). Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation. Retrieved March 22, 2023.
* https://www.mandiant.com/resources/blog/ransomware-extortion-ot-docs - DANIEL KAPELLMANN ZAFRA, COREY HIDELBRANDT, NATHAN BRUBAKER, KEITH LUNDEN. (2022, January 31). 1 in 7 OT Ransomware Extortion Attacks Leak Critical Operational Technology Information. Retrieved August 18, 2023.
* https://www.mandiant.com/resources/blog/trojanized-windows-installers-ukrainian-government - Mandiant Intelligence. (2022, December 15). Trojanized Windows 10 Operating System Installers Targeted Ukrainian Government. Retrieved September 26, 2025.
* https://www.mandiant.com/resources/blog/unc3944-sms-phishing-sim-swapping-ransomware - Mandiant Intelligence. (2023, September 14). Why Are You Texting Me? UNC3944 Leverages SMS Phishing Campaigns for SIM Swapping, Ransomware, Extortion, and Notoriety. Retrieved January 2, 2024.
* https://www.mandiant.com/resources/blog/url-obfuscation-schema-abuse - Nick Simonian. (2023, May 22). Don't @ Me: URL Obfuscation Through Schema Abuse. Retrieved August 4, 2023.
* https://www.mandiant.com/resources/reports - Mandiant. (n.d.). Retrieved February 13, 2024.
* https://www.mandiant.com/resources/supply-chain-analysis-from-quartermaster-to-sunshop - FireEye. (2014). SUPPLY CHAIN ANALYSIS: From Quartermaster to SunshopFireEye. Retrieved March 6, 2017.
* https://www.mandiant.com/sites/default/files/2021-09/mtrends-2020.pdf - Mandiant. (2020, February). M-Trends 2020. Retrieved November 17, 2024.
* https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/ - MDSec Research. (2017, July). Categorisation is not a Security Boundary. Retrieved September 20, 2019.
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - MDSec Research. (2020, December). Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams. Retrieved September 29, 2021.
* https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/ - Microsoft. (2022, June 13). BlackCat. Retrieved February 13, 2024.
* https://www.microsoft.com/en-us/security/blog/2022/09/22/malicious-oauth-applications-used-to-compromise-email-servers-and-spread-spam/ - Microsoft. (2023, September 22). Malicious OAuth applications abuse cloud email services to spread spam. Retrieved March 13, 2023.
* https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/ - Microsoft Threat Intelligence. (2023, August 2). Midnight Blizzard conducts targeted social engineering over Microsoft Teams. Retrieved February 16, 2024.
* https://www.microsoft.com/en-us/security/blog/2024/10/31/chinese-threat-actor-storm-0940-uses-credentials-from-password-spray-attacks-from-a-covert-network/ - Microsoft Threat Intelligence. (2024, October 31). Chinese threat actor Storm-0940 uses credentials from password spray attacks from a covert network. Retrieved June 4, 2025.
* https://www.microsoft.com/en-us/security/blog/2025/02/12/the-badpilot-campaign-seashell-blizzard-subgroup-conducts-multiyear-global-access-operation/?ref=thestack.technology - Microsoft Threat Intelligence. (2025, February 12). The BadPilot campaign: Seashell Blizzard subgroup conducts multiyear global access operation. Retrieved June 18, 2025.
* https://www.microsoft.com/en-us/security/security-insider/intelligence-reports/russian-threat-actors-dig-in-prepare-to-seize-on-war-fatigue - Microsoft Threat Intelligence. (2023, December 7). Russian threat actors dig in, prepare to seize on war fatigue. Retrieved June 18, 2025.
* https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?name=Backdoor:Win32/Lamin.A - Microsoft. (2009, May 17). Backdoor:Win32/Lamin.A. Retrieved September 6, 2018.
* https://www.microsoft.com/security/blog/2016/06/01/hacking-team-breach-a-cyber-jurassic-park/ - Microsoft Secure Team. (2016, June 1). Hacking Team Breach: A Cyber Jurassic Park. Retrieved March 5, 2019.
* https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/ - Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.
* https://www.microsoft.com/security/blog/2021/10/25/nobelium-targeting-delegated-administrative-privileges-to-facilitate-broader-attacks/ - Microsoft Threat Intelligence Center. (2021, October 25). NOBELIUM targeting delegated administrative privileges to facilitate broader attacks. Retrieved March 25, 2022.
* https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/ - Microsoft. (2022, March 22). DEV-0537 criminal actor targeting organizations for data exfiltration and destruction. Retrieved March 23, 2022.
* https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ - Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.
* https://www.mitiga.io/blog/mitiga-security-advisory-abusing-the-ssm-agent-as-a-remote-access-trojan - Ariel Szarf, Or Aspir. (n.d.). Mitiga Security Advisory: Abusing the SSM Agent as a Remote Access Trojan. Retrieved January 31, 2024.
* https://www.netskope.com/blog/new-phishing-attacks-exploiting-oauth-authorization-flows-part-1 - Jenko Hwong. (2021, August 10). New Phishing Attacks Exploiting OAuth Authorization Flows (Part 1). Retrieved March 19, 2024.
* https://www.nytimes.com/2011/01/16/world/middleeast/16stuxnet.html - William J. Broad, John Markoff, and David E. Sanger. (2011, January 15). Israeli Test on Worm Called Crucial in Iran Nuclear Delay. Retrieved March 1, 2017.
* https://www.nytimes.com/2021/05/13/technology/colonial-pipeline-ransom.html - Nicole Perlroth. (2021, May 13). Colonial Pipeline paid 75 Bitcoin, or roughly $5 million, to hackers.. Retrieved August 18, 2023.
* https://www.obsidiansecurity.com/blog/behind-the-breach-self-service-password-reset-azure-ad/ - Noah Corradin and Shuyang Wang. (2023, August 1). Behind The Breach: Self-Service Password Reset (SSPR) Abuse in Azure AD. Retrieved March 28, 2024.
* https://www.optiv.com/insights/source-zero/blog/microsoft-365-oauth-device-code-flow-and-phishing - Optiv. (2021, August 17). Microsoft 365 OAuth Device Code Flow and Phishing. Retrieved March 19, 2024.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain - Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.
* https://www.proofpoint.com/us/threat-insight/post/new-vega-stealer-shines-brightly-targeted-campaign - Proofpoint. (2018, May 10). New Vega Stealer shines brightly in targeted campaign . Retrieved June 18, 2019.
* https://www.proofpoint.com/us/threat-reference/email-spoofing - Proofpoint. (n.d.). What Is Email Spoofing?. Retrieved February 24, 2023.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/blog/esxiargs-ransomware-targets-vmware-esxi-openslp-servers - German Hoeffner, Aaron Soehnen and Gianni Perez. (2023, February 7). ESXiArgs Ransomware Targets Publicly-Exposed ESXi OpenSLP Servers. Retrieved March 26, 2025.
* https://www.recordedfuture.com/blog/identifying-cobalt-strike-servers - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved September 16, 2024.
* https://www.reliaquest.com/blog/health-care-social-engineering-campaign/ - Hayden Evans. (2024, April 4). Health Care Social Engineering Campaign. Retrieved May 22, 2025.
* https://www.sans.org/blog/defense-spotlight-finding-hidden-windows-services/ - Joshua Wright. (2020, October 14). Retrieved March 22, 2024.
* https://www.sans.org/blog/red-team-tactics-hiding-windows-services/ - Joshua Wright. (2020, October 13). Retrieved March 22, 2024.
* https://www.secureworks.com/blog/oauths-device-code-flow-abused-in-phishing-attacks - SecureWorks Counter Threat Unit Research Team. (2021, June 3). OAuth’S Device Code Flow Abused in Phishing Attacks. Retrieved March 19, 2024.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.securityweek.com/iranian-hackers-targeted-us-officials-elaborate-social-media-attack-operation - Lennon, M. (2014, May 29). Iranian Hackers Targeted US Officials in Elaborate Social Media Attack Operation. Retrieved March 1, 2017.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.sentinelone.com/labs/fin7-reboot-cybercrime-gang-enhances-ops-with-new-edr-bypasses-and-automated-attacks/ - Cocomazzi, Antonio. (2024, July 17). FIN7 Reboot | Cybercrime Gang Enhances Ops with New EDR Bypasses and Automated Attacks. Retrieved September 24, 2025.
* https://www.sentinelone.com/labs/operation-tainted-love-chinese-apts-target-telcos-in-new-attacks/ - Aleksandar Milenkoski, Juan Andres Guerrero-Saade, and Joey Chen. (2023, March 23). Operation Tainted Love | Chinese APTs Target Telcos in New Attacks. Retrieved March 18, 2025.
* https://www.sentinelone.com/labs/top-tier-target-what-it-takes-to-defend-a-cybersecurity-company-from-todays-adversaries/ -  Tom Hegel, Aleksandar Milenkoski & Jim Walter. (2025, April 28). Top Tier Target | What It Takes to Defend a Cybersecurity Company from Today’s Adversaries. Retrieved May 22, 2025.
* https://www.ssh.com/ssh/tunneling - SSH.COM. (n.d.). SSH tunnel. Retrieved March 15, 2020.
* https://www.stormshield.com/news/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://www.sygnia.co/blog/abyss-locker-ransomware-attack-analysis/ - Abigail See, Zhongyuan (Aaron) Hau, Ren Jie Yow, Yoav Mazor, Omer Kidron, and Oren Biderman. (2025, February 4). The Anatomy of Abyss Locker Ransomware Attack. Retrieved April 4, 2025.
* https://www.sygnia.co/blog/esxi-ransomware-ssh-tunneling-defense-strategies/ - Zhongyuan Hau (Aaron), Ren Jie Yow, and Yoav Mazor. (2025, January 21). ESXi Ransomware Attacks: Stealthy Persistence through. Retrieved March 27, 2025.
* https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage - Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.
* https://www.symantec.com/connect/blogs/shamoon-attacks - Symantec. (2012, August 16). The Shamoon Attacks. Retrieved March 14, 2019.
* https://www.symantec.com/content/dam/symantec/docs/security-center/white-papers/istr-living-off-the-land-and-fileless-attack-techniques-en.pdf - Wueest, C., Anand, H. (2017, July). Living off the land and fileless attack techniques. Retrieved April 10, 2018.
* https://www.technologyreview.com/2013/08/21/83143/dropbox-and-similar-services-can-sync-malware/ - David Talbot. (2013, August 21). Dropbox and Similar Services Can Sync Malware. Retrieved May 31, 2023.
* https://www.techtarget.com/searchsecurity/tip/Preparing-for-uniform-resource-identifier-URI-exploits - Michael Cobb. (2007, October 11). Preparing for uniform resource identifier (URI) exploits. Retrieved February 9, 2024.
* https://www.theregister.com/2015/02/28/uber_subpoenas_github_for_hacker_details/ - McCarthy, K. (2015, February 28). FORK ME! Uber hauls GitHub into court to find who hacked database of 50,000 drivers. Retrieved October 19, 2020.
* https://www.theregister.com/2017/09/26/deloitte_leak_github_and_google/ - Thomson, I. (2017, September 26). Deloitte is a sitting duck: Key systems with RDP open, VPN and proxy 'login details leaked'. Retrieved October 19, 2020.
* https://www.trellix.com/blogs/research/beyond-file-search-a-novel-method/ -  Mathanraj Thangaraju, Sijo Jacob. (2023, July 26). Beyond File Search: A Novel Method for Exploiting the "search-ms" URI Protocol Handler. Retrieved March 15, 2024.
* https://www.trellix.com/en-au/blogs/research/ransomhouse-am-see/ - Pham Duy Phuc, Max Kersten, Noël Keijzer, and Michaël Schrijver. (2024, February 14). RansomHouse am See. Retrieved March 26, 2025.
* https://www.trendmicro.com/en_us/research.html - Trend Micro. (n.d.). Retrieved February 16, 2024.
* https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html - Remillano II, A., et al. (2020, June 20). XORDDoS, Kaiji Variants Target Exposed Docker Servers. Retrieved April 5, 2021.
* https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html - Hacquebord, F., Remorin, L. (2020, December 17). Pawn Storm’s Lack of Sophistication as a Strategy. Retrieved January 13, 2021.
* https://www.trendmicro.com/vinfo/us/security/news/cybercrime-and-digital-threats/emotet-now-spreads-via-wi-fi - Cybercrime & Digital Threat Team. (2020, February 13). Emotet Now Spreads via Wi-Fi. Retrieved February 16, 2022.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing - Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.
* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/pillowmint-fin7s-monkey-thief/ - Trustwave SpiderLabs. (2020, June 22). Pillowmint: FIN7’s Monkey Thief . Retrieved July 27, 2020.
* https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/event.aspx?eventID=4670 - Franklin Smith, R. (n.d.). Windows Security Log Event ID 4670. Retrieved November 4, 2019.
* https://www.us-cert.gov/ncas/alerts/AA18-337A - US-CERT. (2018, December 3). Alert (AA18-337A): SamSam Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.us-cert.gov/ncas/alerts/TA16-091A - US-CERT. (2016, March 31). Alert (TA16-091A): Ransomware and Recent Variants. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-086A - US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.varonis.com/blog/vmware-esxi-in-the-line-of-ransomware-fire - Jason Hill. (2023, February 8). VMware ESXi in the Line of Ransomware Fire. Retrieved March 26, 2025.
* https://www.virusbulletin.com/conference/vb2023/abstracts/unveiling-activities-tropic-trooper-2023-deep-analysis-xiangoop-loader-and-entryshell-payload/ - Suguru Ishimaru, Hajime Yanagishita, Yusuke Niwa. (2023, October 5). Unveiling activities of Tropic Trooper 2023: deep analysis of Xiangoop Loader and EntryShell payload. Retrieved October 3, 2025.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2020/11/06/oceanlotus-extending-cyber-espionage-operations-through-fake-websites/ - Adair, S. and Lancaster, T. (2020, November 6). OceanLotus: Extending Cyber Espionage Operations Through Fake Websites. Retrieved November 20, 2020.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/ - Adair, S., Lancaster, T., Volexity Threat Research. (2022, June 15). DriftingCloud: Zero-Day Sophos Firewall Exploitation and an Insidious Breach. Retrieved July 1, 2022.
* https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/ - Koessel, Sean. Adair, Steven. Lancaster, Tom. (2024, November 22). The Nearest Neighbor Attack: How A Russian APT Weaponized Nearby Wi-Fi Networks for Covert Access. Retrieved February 25, 2025.
* https://www.welivesecurity.com/2020/04/28/grandoreiro-how-engorged-can-exe-get/ - ESET. (2020, April 28). Grandoreiro: How engorged can an EXE get?. Retrieved November 13, 2020.
* https://www.welivesecurity.com/wp-content/uploads/2019/10/ESET_Attor.pdf - Hromcova, Z. (2019, October). AT COMMANDS, TOR-BASED COMMUNICATIONS: MEET ATTOR, A FANTASY CREATURE AND ALSO A SPY PLATFORM. Retrieved May 6, 2020.
* https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf - Hromcova, Z. and Cherpanov, A. (2020, June). INVISIMOLE: THE HIDDEN PART OF THE STORY. Retrieved July 16, 2020.
* https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows - Wietze Beukema. (2020, June 22). Hijacking DLLs in Windows. Retrieved April 8, 2025.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.wired.com/images_blogs/threatlevel/2010/11/w32_stuxnet_dossier.pdf - Nicolas Falliere, Liam O. Murchu, Eric Chien. (2011, February). W32.Stuxnet Dossier. Retrieved December 7, 2020.
* https://www.wired.com/story/pig-butchering-fbi-ic3-2022-report/ - Lily Hay Newman. (n.d.). ‘Pig Butchering’ Scams Are Now a $3 Billion Threat. Retrieved August 18, 2023.
* https://www.wired.com/story/russia-ukraine-cyberattacks-mandiant/ - Greenberg, A. (2022, November 10). Russia’s New Cyberwarfare in Ukraine Is Fast, Dirty, and Relentless. Retrieved March 22, 2023.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www.zdnet.com/article/ransomware-victims-thought-their-backups-were-safe-they-were-wrong/ - Steve Ranger. (2020, February 27). Ransomware victims thought their backups were safe. They were wrong. Retrieved March 21, 2023.
* https://www.zscaler.com/blogs/security-research/apt-31-leverages-covid-19-vaccine-theme-and-abuses-legitimate-online - Singh, S. and Antil, S. (2020, October 27). APT-31 Leverages COVID-19 Vaccine Theme and Abuses Legitimate Online Services. Retrieved March 24, 2021.
* https://www.zscaler.com/blogs/security-research/technical-analysis-crytox-ransomware - Romain Dumont . (2022, September 21). Technical Analysis of Crytox Ransomware. Retrieved November 22, 2023.
* https://x.com/TheDFIRReport/status/1498657590259109894 - TheDFIRReport. (2022, March 1). Disabling notifications on Synology servers before ransom. Retrieved September 12, 2024.
* https://x.com/TheDFIRReport/status/1498657772254240768 - The DFIR Report. (2022, March 1). "Change RDP port" #ContiLeaks. Retrieved September 12, 2024.
* https://x.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved September 12, 2024.
* https://x.com/rfackroyd/status/1639136000755765254 - Ackroyd, R. (2023, March 24). Twitter. Retrieved September 12, 2024.

# Validate the following tools

* BITSAdmin - 1
* Empire - 3
* Mimikatz - 2
* NBTscan - 1
* PoshC2 - 1
* PsExec - 1
* Rclone - 1

# Review the following tool references

* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/nettitude/PoshC2_Python - Nettitude. (2018, July 23). Python Server for PoshC2. Retrieved April 23, 2019.
* https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html - Bezroutchko, A. (2019, November 19). NBTscan man page. Retrieved March 17, 2021.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://rclone.org - Nick Craig-Wood. (n.d.). Rclone syncs your files to cloud storage. Retrieved August 30, 2022.
* https://redcanary.com/blog/rclone-mega-extortion/ - Justin Schoenfeld and Aaron Didier. (2021, May 4). Rclone Wars: Transferring leverage in a ransomware attack. Retrieved August 30, 2022.
* https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/ -  Aaron Greetham. (2021, May 27). Detecting Rclone – An Effective Tool for Exfiltration. Retrieved August 30, 2022.
* https://sectools.org/tool/nbtscan/ - SecTools. (2003, June 11). NBTscan. Retrieved March 17, 2021.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://thedfirreport.com/2021/11/29/continuing-the-bazar-ransomware-story/ - DFIR Report. (2021, November 29). CONTInuing the Bazar Ransomware Story. Retrieved September 29, 2022.
* https://unit42.paloaltonetworks.com/darkside-ransomware/ - Ramarcus Baylor. (2021, May 12). DarkSide Ransomware Gang: An Overview. Retrieved August 30, 2022.
* https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html - Hawley et al. (2019, January 29). APT39: An Iranian Cyber Espionage Group Focused on Personal Information. Retrieved February 19, 2019.
* https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive/ - Pilkington, M. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments - Symantec DeepSight Adversary Intelligence Team. (2019, June 20). Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments. Retrieved July 8, 2019.

# Validate the following malware

* ASPXSpy - 1
* Apostle - 1
* AshTag - 1
* BFG Agonizer - 1
* Cobalt Strike - 1
* CreepyDrive - 1
* CreepySnail - 1
* DCSrv - 1
* DEADWOOD - 1
* DanBot - 1
* DnsSystem - 1
* Ferocious - 1
* Havoc - 1
* IPsec Helper - 1
* IronWind - 1
* Kevin - 1
* LitePower - 1
* Matryoshka - 1
* Micropsia - 1
* Milan - 1
* Moneybird - 1
* MultiLayer Wiper - 1
* PyDCrypt - 1
* SameCoin - 1
* Shark - 1
* StrifeWater - 1
* TDTESS - 1

# Review the following malware references

* http://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf - ClearSky Cyber Security and Trend Micro. (2017, July). Operation Wilted Tulip: Exposing a cyber espionage apparatus. Retrieved August 21, 2017.
* https://assets.sentinelone.com/sentinellabs/evol-agrius - Amitai Ben & Shushan Ehrlich. (2021, May). From Wiper to Ransomware: The Evolution of Agrius. Retrieved May 21, 2024.
* https://blog.talosintelligence.com/2017/06/palestine-delphi.html - Rascagneres, P., Mercer, W. (2017, June 19). Delphi Used To Score Against Palestine. Retrieved November 13, 2018.
* https://cdn2.hubspot.net/hubfs/1903456/Whitepapers/CopyKittens.pdf - Minerva Labs LTD and ClearSky Cyber Security. (2015, November 23). CopyKittens Attack Group. Retrieved November 17, 2024.
* https://research.checkpoint.com/2021/mosesstaff-targeting-israeli-companies/ - Checkpoint Research. (2021, November 15). Uncovering MosesStaff techniques: Ideology over Money. Retrieved August 11, 2022.
* https://research.checkpoint.com/2023/agrius-deploys-moneybird-in-targeted-attacks-against-israeli-organizations/ - Marc  Salinas Fernandez & Jiri  Vinopal. (2023, May 23). AGRIUS DEPLOYS MONEYBIRD IN TARGETED ATTACKS AGAINST ISRAELI ORGANIZATIONS. Retrieved May 21, 2024.
* https://research.checkpoint.com/2024/hamas-affiliated-threat-actor-expands-to-disruptive-activity/ - Check Point. (2024, November 12). Hamas-affiliated Threat Actor WIRTE Continues its Middle East Operations and Moves to Disruptive Activity. Retrieved April 20, 2026.
* https://securelist.com/wirtes-campaign-in-the-middle-east-living-off-the-land-since-at-least-2019/105044 - Yamout, M. (2021, November 29). WIRTE’s campaign in the Middle East ‘living off the land’ since at least 2019. Retrieved February 1, 2022.
* https://unit42.paloaltonetworks.com/agonizing-serpens-targets-israeli-tech-higher-ed-sectors/ - Or Chechik, Tom Fakterman, Daniel Frank & Assaf Dahan. (2023, November 6). Agonizing Serpens (Aka Agrius) Targeting the Israeli Higher Education and Tech Sectors. Retrieved May 22, 2024.
* https://unit42.paloaltonetworks.com/hamas-affiliate-ashen-lepus-uses-new-malware-suite-ashtag/ - Unit 42. (2025, December 11). Hamas-Affiliated Ashen Lepus Targets Middle Eastern Diplomatic Entities With New AshTag Malware Suite. Retrieved April 20, 2026.
* https://vblocalhost.com/uploads/VB2021-Kayal-etal.pdf - Kayal, A. et al. (2021, October). LYCEUM REBORN: COUNTERINTELLIGENCE IN THE MIDDLE EAST. Retrieved June 14, 2022.
* https://web.archive.org/web/20210825130434/https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://www.accenture.com/us-en/blogs/cyber-defense/iran-based-lyceum-campaigns - Accenture. (2021, November 9). Who are latest targets of cyber group Lyceum?. Retrieved June 16, 2022.
* https://www.clearskysec.com/siamesekitten/ - ClearSky Cyber Security . (2021, August). New Iranian Espionage Campaign By “Siamesekitten” - Lyceum. Retrieved June 6, 2022.
* https://www.cybereason.com/blog/research/strifewater-rat-iranian-apt-moses-staff-adds-new-trojan-to-ransomware-operations - Cybereason Nocturnus. (2022, February 1). StrifeWater RAT: Iranian APT Moses Staff Adds New Trojan to Ransomware Operations. Retrieved August 15, 2022.
* https://www.microsoft.com/security/blog/2022/06/02/exposing-polonium-activity-and-infrastructure-targeting-israeli-organizations/ - Microsoft. (2022, June 2). Exposing POLONIUM activity and infrastructure targeting Israeli organizations. Retrieved July 1, 2022.
* https://www.radware.com/blog/security/2018/07/micropsia-malware/ - Tsarfaty, Y. (2018, July 25). Micropsia Malware. Retrieved November 13, 2018.
* https://www.secureworks.com/blog/lyceum-takes-center-stage-in-middle-east-campaign - SecureWorks 2019, August 27 LYCEUM Takes Center Stage in Middle East Campaign Retrieved. 2019/11/19 
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.zscaler.com/blogs/security-research/lyceum-net-dns-backdoor - Shivtarkar, N. and Kumar, A. (2022, June 9). Lyceum .NET DNS Backdoor. Retrieved June 23, 2022.

