threat-crank.py 0.2.1
I: searching for industries that match .* teach.*|.* academi.*|.* school.*|.* universit.*|.* college.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v17.0/enterprise-attack/enterprise-attack.json
# Threat groups

* APT39
* Leviathan
* Magic Hound
* Metador
* Silent Librarian
* Star Blizzard

# Validate the following attacks

* Acquire Infrastructure - 1
* Additional Email Delegate Permissions - 1
* Additional Local or Domain Groups - 1
* AppInit DLLs - 1
* Application Layer Protocol - 1
* Archive Collected Data - 1
* Archive via Utility - 2
* AutoHotKey & AutoIT - 1
* BITS Jobs - 2
* Bidirectional Communication - 2
* Binary Padding - 1
* Brute Force - 1
* Clear Command History - 1
* Clipboard Data - 1
* Code Signing - 1
* Code Signing Policy Modification - 1
* Command Obfuscation - 1
* Command and Scripting Interpreter - 1
* Compression - 1
* Credentials - 2
* Credentials from Password Stores - 1
* DNS - 1
* Data Encrypted for Impact - 1
* Data from Local System - 2
* Default Accounts - 1
* Deobfuscate/Decode Files or Information - 2
* Determine Physical Locations - 1
* Digital Certificates - 1
* Disable Windows Event Logging - 1
* Disable or Modify System Firewall - 1
* Disable or Modify Tools - 1
* Domain Accounts - 1
* Domain Trust Discovery - 1
* Domains - 5
* Drive-by Compromise - 2
* Dynamic Data Exchange - 1
* Dynamic-link Library Injection - 1
* Email Account - 1
* Email Accounts - 7
* Email Addresses - 2
* Email Collection - 2
* Email Forwarding Rule - 2
* Employee Names - 1
* Encrypted Channel - 1
* Encrypted/Encoded File - 4
* Exfiltration Over C2 Channel - 2
* Exfiltration Over Web Service - 1
* Exfiltration to Cloud Storage - 1
* Exploit Public-Facing Application - 3
* Exploitation for Client Execution - 1
* Exploits - 1
* External Proxy - 1
* External Remote Services - 1
* File Deletion - 3
* File and Directory Discovery - 2
* Gather Victim Identity Information - 2
* Hidden Window - 1
* IP Addresses - 1
* Impair Defenses - 1
* Ingress Tool Transfer - 4
* Input Capture - 1
* Internal Proxy - 1
* Internal Spearphishing - 1
* Internet Connection Discovery - 1
* JavaScript - 1
* Keylogging - 2
* LSASS Memory - 3
* Lateral Tool Transfer - 1
* Link Target - 1
* Local Account - 2
* Local Data Staging - 2
* Local Email Collection - 1
* Malicious File - 4
* Malicious Link - 3
* Malware - 1
* Masquerade Account Name - 1
* Masquerade Task or Service - 1
* Match Legitimate Resource Name or Location - 2
* Modify Registry - 1
* Multi-hop Proxy - 1
* Network Devices - 1
* Network Service Discovery - 2
* Network Share Discovery - 1
* Non-Application Layer Protocol - 1
* Non-Standard Port - 1
* OS Credential Dumping - 2
* One-Way Communication - 1
* Password Spraying - 1
* PowerShell - 3
* Process Discovery - 1
* Protocol Tunneling - 2
* Proxy - 1
* Python - 1
* Query Registry - 1
* Registry Run Keys / Startup Folder - 3
* Regsvr32 - 1
* Remote Data Staging - 1
* Remote Desktop Protocol - 3
* Remote Email Collection - 2
* Remote System Discovery - 2
* Rundll32 - 1
* SMB/Windows Admin Shares - 1
* SSH - 2
* Scheduled Task - 2
* Screen Capture - 2
* Search Open Websites/Domains - 1
* Search Victim-Owned Websites - 1
* Server - 1
* Service Execution - 1
* Shortcut Modification - 2
* Social Media Accounts - 4
* Software - 1
* Software Packing - 1
* Spearphishing Attachment - 4
* Spearphishing Link - 6
* Spearphishing via Service - 1
* Steal Web Session Cookie - 1
* Steganography - 1
* System Information Discovery - 1
* System Network Configuration Discovery - 1
* System Network Connections Discovery - 1
* System Owner/User Discovery - 2
* Tool - 5
* Upload Malware - 1
* Valid Accounts - 4
* Visual Basic - 3
* Vulnerability Scanning - 2
* Web Protocols - 3
* Web Services - 1
* Web Session Cookie - 1
* Web Shell - 3
* Wi-Fi Discovery - 1
* Windows Command Shell - 2
* Windows Management Instrumentation - 2
* Windows Management Instrumentation Event Subscription - 2

# Validate the following phases

* collection - 21
* command-and-control - 21
* credential-access - 12
* defense-evasion - 39
* discovery - 18
* execution - 26
* exfiltration - 4
* impact - 1
* initial-access - 19
* lateral-movement - 9
* persistence - 27
* privilege-escalation - 19
* reconnaissance - 18
* resource-development - 30

# Validate the following platforms

* Android - 1
* Containers - 20
* ESXi - 68
* IaaS - 22
* Identity Provider - 15
* Linux - 141
* Network Devices - 52
* Office Suite - 25
* PRE - 48
* SaaS - 15
* Windows - 213
* macOS - 143

# Validate the following defences


# Validate the following data sources

* Active Directory: Active Directory Object Access - 4
* Application Log: Application Log Content - 35
* Certificate: Certificate Registration - 1
* Cloud Service: Cloud Service Disable - 1
* Cloud Service: Cloud Service Enumeration - 3
* Cloud Service: Cloud Service Metadata - 2
* Cloud Service: Cloud Service Modification - 1
* Cloud Storage: Cloud Storage Modification - 1
* Command: Command Execution - 97
* Domain Name: Active DNS - 6
* Domain Name: Domain Registration - 6
* Domain Name: Passive DNS - 6
* Driver: Driver Load - 5
* File: File Access - 20
* File: File Creation - 44
* File: File Deletion - 5
* File: File Metadata - 14
* File: File Modification - 18
* Firewall: Firewall Disable - 2
* Firewall: Firewall Rule Modification - 2
* Group: Group Modification - 1
* Image: Image Metadata - 2
* Internet Scan: Response Content - 8
* Internet Scan: Response Metadata - 2
* Logon Session: Logon Session Creation - 19
* Logon Session: Logon Session Metadata - 9
* Malware Repository: Malware Content - 1
* Malware Repository: Malware Metadata - 6
* Module: Module Load - 14
* Named Pipe: Named Pipe Metadata - 1
* Network Share: Network Share Access - 3
* Network Traffic: Network Connection Creation - 40
* Network Traffic: Network Traffic Content - 65
* Network Traffic: Network Traffic Flow - 58
* Persona: Social Media - 4
* Process: OS API Execution - 30
* Process: Process Access - 10
* Process: Process Creation - 88
* Process: Process Metadata - 9
* Process: Process Modification - 2
* Process: Process Termination - 2
* Scheduled Job: Scheduled Job Creation - 2
* Scheduled Job: Scheduled Job Metadata - 1
* Scheduled Job: Scheduled Job Modification - 1
* Script: Script Execution - 20
* Sensor Health: Host Status - 3
* Service: Service Creation - 2
* Service: Service Metadata - 5
* User Account: User Account Authentication - 9
* User Account: User Account Creation - 3
* User Account: User Account Modification - 3
* WMI: WMI Creation - 4
* Web Credential: Web Credential Usage - 1
* Windows Registry: Windows Registry Key Access - 5
* Windows Registry: Windows Registry Key Creation - 7
* Windows Registry: Windows Registry Key Deletion - 3
* Windows Registry: Windows Registry Key Modification - 20

# Review the following attack references

* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf - Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://en.wikipedia.org/wiki/List_of_network_protocols_%28OSI_model%29 - Wikipedia. (n.d.). List of network protocols (OSI model). Retrieved December 4, 2014.
* http://media.blackhat.com/bh-us-10/whitepapers/Ryan/BlackHat-USA-2010-Ryan-Getting-In-Bed-With-Robin-Sage-v1.0.pdf - Ryan, T. (2010). “Getting In Bed with Robin Sage.”. Retrieved March 6, 2017.
* http://opensecuritytraining.info/Keylogging_files/The%20Adventures%20of%20a%20Keystroke.pdf - Tinaztepe,  E. (n.d.). The Adventures of a Keystroke:  An in-depth look into keyloggers on Windows. Retrieved April 27, 2016.
* http://researchcenter.paloaltonetworks.com/2016/11/unit42-shamoon-2-return-disttrack-wiper/ - Falcone, R.. (2016, November 30). Shamoon 2: Return of the Disttrack Wiper. Retrieved January 11, 2017.
* http://support.microsoft.com/KB/170292 - Microsoft. (n.d.). Internet Control Message Protocol (ICMP) Basics. Retrieved December 1, 2014.
* http://support.microsoft.com/kb/314984 - Microsoft. (n.d.). How to create and delete hidden or administrative shares on client computers. Retrieved November 20, 2014.
* http://www.blackhillsinfosec.com/?p=4645 - Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* https://adsecurity.org/?p=1588 - Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arstechnica.com/information-technology/2007/05/malware-piggybacks-on-windows-background-intelligent-transfer-service/ - Mondok, M. (2007, May 11). Malware piggybacks on Windows’ Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://arstechnica.com/information-technology/2021/02/armed-with-exploits-hackers-on-the-prowl-for-a-critical-vmware-vulnerability/ - Dan Goodin . (2021, February 25). Code-execution flaw in VMware has a severity rating of 9.8 out of 10. Retrieved April 8, 2025.
* https://arstechnica.com/tech-policy/2011/02/anonymous-speaks-the-inside-story-of-the-hbgary-hack/ - Bright, P. (2011, February 15). Anonymous speaks: the inside story of the HBGary hack. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://arxiv.org/pdf/2102.04796 - Javier Yuste and Sergio Pastrana. (2021). Avaddon ransomware: an in-depth analysis and decryption of infected systems. Retrieved March 24, 2025.
* https://bashfuscator.readthedocs.io/en/latest/Mutators/command_obfuscators/index.html - LeFevre, A. (n.d.). Bashfuscator Command Obfuscators. Retrieved March 17, 2023.
* https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://blog.aquasec.com/leveraging-kubernetes-rbac-to-backdoor-clusters - Michael Katchinskiy, Assaf Morag. (2023, April 21). First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters. Retrieved July 14, 2023.
* https://blog.compass-security.com/2018/09/hidden-inbox-rules-in-microsoft-exchange/ - Damian Pfammatter. (2018, September 17). Hidden Inbox Rules in Microsoft Exchange. Retrieved October 12, 2021.
* https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/ - Aliz Hammond. (2019, August 15). Hiding Malicious Code with "Module Stomping": Part 1. Retrieved July 14, 2022.
* https://blog.malwarebytes.com/cybercrime/2013/10/hiding-in-plain-sight/ - Arntz, P. (2016, March 30). Hiding in Plain Sight. Retrieved August 3, 2020.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/malwarebytes-news/2020/10/silent-librarian-apt-phishing-attack/ - Malwarebytes Threat Intelligence Team. (2020, October 14). Silent Librarian APT right on schedule for 20/21 academic year. Retrieved February 3, 2021.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/ - NVISO Labs. (2017, October 11). Detecting DDE in MS Office documents. Retrieved November 21, 2017.
* https://blog.qualys.com/vulnerabilities-threat-research/2022/06/20/defending-against-scheduled-task-attacks-in-windows-environments - Harshal Tupsamudre. (2022, June 20). Defending Against Scheduled Tasks. Retrieved July 5, 2022.
* https://blog.reversinglabs.com/blog/mining-for-malicious-ruby-gems - Maljic, T. (2020, April 16). Mining for malicious Ruby gems. Retrieved October 15, 2022.
* https://blog.securelayer7.net/how-to-perform-csv-excel-macro-injection/ -  Ishaq Mohammed . (2021, January 10). Everything about CSV Injection and CSV Excel Macro Injection. Retrieved February 7, 2022.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A., McKay, K. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal . Retrieved July 29, 2022.
* https://blog.talosintelligence.com/2021/11/kimsuky-abuses-blogs-delivers-malware.html - An, J and Malhotra, A. (2021, November 10). North Korean attackers use malicious blogs to deliver malware to high-profile South Korean targets. Retrieved December 29, 2021.
* https://blog.talosintelligence.com/2022/03/transparent-tribe-new-campaign.html - Malhotra, A., Thattil, J. et al. (2022, March 29). Transparent Tribe campaign uses new bespoke malware to target Indian government officials . Retrieved September 6, 2022.
* https://blog.talosintelligence.com/ipfs-abuse/ - Edmund Brumaghin. (2022, November 9). Threat Spotlight: Cyber Criminal Adoption of IPFS for Phishing, Malware Campaigns. Retrieved March 8, 2023.
* https://blog.talosintelligence.com/roblox-scam-overview/ - Tiago Pereira. (2023, November 2). Attackers use JavaScript URLs, API forms and more to scam users in popular online game “Roblox”. Retrieved January 2, 2024.
* https://blog.trendmicro.com/phishing-starts-inside/ - Chris Taylor. (2017, October 5). When Phishing Starts from the Inside. Retrieved October 8, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blog.trendmicro.com/trendlabs-security-intelligence/r980-ransomware-disposable-email-service/ - Antazo, F. and Yambao, M. (2016, August 10). R980 Ransomware Found Abusing Disposable Email Address Service. Retrieved October 13, 2020.
* https://blogs.blackberry.com/en/2022/02/threat-spotlight-whispergate-wiper-wreaks-havoc-in-ukraine - BlackBerry Research and Intelligence Team. (2022, February 3). Threat Spotlight: WhisperGate Wiper Wreaks Havoc in Ukraine. Retrieved March 18, 2025.
* https://blogs.cisco.com/security/evolution-of-attacks-on-cisco-ios-devices - Graham Holmes. (2015, October 8). Evolution of attacks on Cisco IOS devices. Retrieved October 19, 2020.
* https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://blogs.technet.microsoft.com/timmcmic/2015/06/08/exchange-and-office-365-mail-forwarding-2/ - McMichael, T.. (2015, June 8). Exchange and Office 365 Mail Forwarding. Retrieved October 8, 2019.
* https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16 - Bromiley, M. (2016, December 27). Malware Monday: VBScript and VBE Files. Retrieved March 17, 2023.
* https://cantoriscomputing.wordpress.com/2016/07/22/powershell-malware/ - Cantoris. (2016, July 22). PowerShell Malware. Retrieved December 12, 2024.
* https://cdn.cnn.com/cnn/2018/images/07/13/gru.indictment.pdf - Mueller, R. (2018, July 13). Indictment - United States of America vs. VIKTOR BORISOVICH NETYKSHO, et al. Retrieved November 17, 2024.
* https://cdn.logic-control.com/docs/scadafence/Anatomy-Of-A-Targeted-Ransomware-Attack-WP.pdf - Shaked, O. (2020, January 20). Anatomy of a Targeted Ransomware Attack. Retrieved June 18, 2022.
* https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-orb-networks - Raggi, Michael. (2024, May 22). IOC Extinction? China-Nexus Cyber Espionage Actors Use ORB Networks to Raise Cost on Defenders. Retrieved July 8, 2024.
* https://cloud.google.com/blog/topics/threat-intelligence/cosmicenergy-ot-malware-russian-response/ - COSMICENERGY: New OT Malware Possibly Related To Russian Emergency Response Exercises. (2023, May 25). Ken Proska, Daniel Kapellmann Zafra, Keith Lunden, Corey Hildebrandt, Rushikesh Nandedkar, Nathan Brubaker. Retrieved March 18, 2025.
* https://cloud.google.com/blog/topics/threat-intelligence/fin13-cybercriminal-mexico/ - Van Ta, Jake Nicastro, Rufus Brown, and Nick Richard. (2021, December 7). FIN13: A Cybercriminal Threat Actor Focused on Mexico. Retrieved March 18, 2025.
* https://cloud.google.com/blog/topics/threat-intelligence/scandalous-external-detection-using-network-scan-data-and-automation/ - Stephens, A. (2020, July 13). SCANdalous! (External Detection Using Network Scan Data and Automation). Retrieved November 17, 2024.
* https://cloud.google.com/blog/topics/threat-intelligence/uncovering-unc3886-espionage-operations -  Punsaen Boonyakarn, Shawn Chew, Logeswaran Nadarajan, Mathew Potaczek, Jakub Jozwiak, and Alex Marvi. (2024, June 18). Cloaked and Covert: Uncovering UNC3886 Espionage Operations. Retrieved September 24, 2024.
* https://cloud.google.com/blog/topics/threat-intelligence/vmware-esxi-zero-day-bypass/ - Alexander Marvi, Brad Slaybaugh, Ron Craft, and Rufus Brown. (2023, June 13). VMware ESXi Zero-Day Used by Chinese Espionage Actor to Perform Privileged Guest Operations on Compromised Hypervisors. Retrieved March 26, 2025.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://cofense.com/blog/major-energy-company-targeted-in-large-qr-code-campaign/ - Raymond, Nathaniel. (2023, August 16). Major Energy Company Targeted in Large QR Code Phishing Campaign. Retrieved January 17, 2024.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://community.sophos.com/products/intercept/early-access-program/f/live-discover-response-queries/121529/live-discover---powershell-command-audit - jak. (2020, June 27). Live Discover - PowerShell command audit. Retrieved August 21, 2020.
* https://community.sophos.com/sophos-labs/b/blog/posts/powershell-command-history-forensics - Vikas, S. (2020, August 26). PowerShell Command History Forensics. Retrieved November 17, 2024.
* https://csrc.nist.gov/glossary/term/web_bug - NIST Information Technology Laboratory. (n.d.). web bug. Retrieved March 22, 2023.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://cybersecurity.att.com/blogs/labs-research/scanbox-a-reconnaissance-framework-used-on-watering-hole-attacks - Blasco, J. (2014, August 28). Scanbox: A Reconnaissance Framework Used with Watering Hole Attacks. Retrieved October 19, 2020.
* https://cyware.com/news/how-hackers-exploit-social-media-to-break-into-your-company-88e8da8e - Cyware Hacker News. (2019, October 2). How Hackers Exploit Social Media To Break Into Your Company. Retrieved October 20, 2020.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection - Apple. (n.d.). Disabling and Enabling System Integrity Protection. Retrieved April 22, 2021.
* https://developer.apple.com/library/archive/documentation/Cocoa/Conceptual/NetServices/Introduction.html - Apple Inc. (2013, April 23). Bonjour Overview. Retrieved October 11, 2021.
* https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html - Apple. (2016, June 13). About Mac Scripting. Retrieved April 14, 2021.
* https://digital.nhs.uk/cyber-alerts/2020/cc-3681#summary - NHS Digital. (2020, November 26). Egregor Ransomware The RaaS successor to Maze. Retrieved December 29, 2020.
* https://dmcxblue.gitbook.io/red-team-notes-2-0/red-team-techniques/defense-evasion/t1562-impair-defenses/disable-windows-event-logging -  dmcxblue. (n.d.). Disable Windows Event Logging. Retrieved September 10, 2021.
* https://dnsdumpster.com/ - Hacker Target. (n.d.). DNS Dumpster. Retrieved October 20, 2020.
* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html - Amazon. (n.d.). AWS Account Root User. Retrieved April 5, 2021.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/archive/blogs/gauravseth/the-world-of-jscript-javascript-ecmascript - Microsoft. (2007, August 15). The World of JScript, JavaScript, ECMAScript …. Retrieved June 23, 2020.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/monitoring-what-matters-windows-event-forwarding-for-everyone-even-if-you-already-have-a-siem - Payne, J. (2015, November 23). Monitoring what matters - Windows Event Forwarding for everyone (even if you already have a SIEM.). Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/archive/blogs/jepayne/tracking-lateral-movement-part-one-special-groups-and-specific-service-accounts - Payne, J. (2015, November 26). Tracking Lateral Movement Part One - Special Groups and Specific Service Accounts. Retrieved February 1, 2016.
* https://docs.microsoft.com/en-us/azure/security/fundamentals/subdomain-takeover - Microsoft. (2020, September 29). Prevent dangling DNS entries and avoid subdomain takeover. Retrieved October 12, 2020.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships - Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.drawing.graphics.copyfromscreen?view=netframework-4.8 - Microsoft. (n.d.). Graphics.CopyFromScreen Method. Retrieved March 24, 2020.
* https://docs.microsoft.com/en-us/exchange/email-addresses-and-address-books/address-lists/address-lists?view=exchserver-2019 - Microsoft. (2020, February 7). Address lists in Exchange Server. Retrieved March 26, 2020.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1 - Wheeler, S. et al.. (2019, May 1). About PowerShell.exe. Retrieved October 11, 2019.
* https://docs.microsoft.com/en-us/powershell/module/exchange/email-addresses-and-address-books/get-globaladdresslist - Microsoft. (n.d.). Get-GlobalAddressList. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/powershell/module/exchange/mailboxes/add-mailboxpermission?view=exchange-ps - Microsoft. (n.d.). Add-Mailbox Permission. Retrieved September 13, 2019.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_history?view=powershell-7 - Microsoft. (2020, May 13). About History. Retrieved September 4, 2020.
* https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/register-wmievent?view=powershell-5.1 - Microsoft. (n.d.). Retrieved January 24, 2020.
* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1 - Microsoft. (2020, August 21). Running Remote Commands. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653559(v=vs.85)?redirectedfrom=MSDN - Microsoft. (2017, June 1). Digital Signatures for Kernel Modules on Windows. Retrieved April 22, 2021.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10) - Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete - Russinovich, M. (2016, July 4). SDelete v2.0. Retrieved February 8, 2018.
* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/installing-an-unsigned-driver-during-development-and-test - Microsoft. (2017, April 20). Installing an Unsigned Driver during Development and Test. Retrieved April 22, 2021.
* https://docs.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option - Microsoft. (2021, February 15). Enable Loading of Test Signed Drivers. Retrieved April 22, 2021.
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol - Jason Gerend, et al. (2017, October 16). auditpol. Retrieved September 1, 2021.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-accounts - Microsoft. (2019, August 23). Active Directory Accounts. Retrieved March 13, 2020.
* https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/local-accounts - Microsoft. (2018, December 9). Local Accounts. Retrieved February 11, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings - Simpson, D. et al. (2017, April 19). Advanced security audit policy settings. Retrieved September 14, 2021.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-other-object-access-events - Microsoft. (2017, May 28). Audit Other Object Access Events. Retrieved June 27, 2019.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720 - Lich, B., Miroshnikov, A. (2017, April 5). 4720(S): A user account was created. Retrieved June 30, 2017.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/audit-policy - Daniel Simpson. (2017, April 19). Audit Policy. Retrieved September 13, 2021.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/sysinfo/32-bit-and-64-bit-application-data-in-the-registry - Microsoft. (2018, May 31). 32-bit and 64-bit Application Data in the Registry. Retrieved August 3, 2020.
* https://docs.microsoft.com/en-us/windows/win32/wmisdk/managed-object-format--mof- - Satran, M. (2018, May 30). Managed Object Format (MOF). Retrieved January 24, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/scripting/winscript/windows-script-interfaces - Microsoft. (2017, January 18). Windows Script Interfaces. Retrieved June 23, 2020.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/win32/com/translating-to-jscript - Microsoft. (2018, May 31). Translating to JScript. Retrieved June 23, 2020.
* https://docs.microsoft.com/windows/win32/services/service-control-manager - Microsoft. (2018, May 31). Service Control Manager. Retrieved March 28, 2020.
* https://docs.ostorlab.co/kb/IPA_URL_SCHEME_HIJACKING/index.html - Ostorlab. (n.d.). iOS URL Scheme Hijacking. Retrieved February 9, 2024.
* https://documents.trendmicro.com/assets/wp/wp-criminal-hideouts-for-lease.pdf - Max Goncharov. (2015, July 15). Criminal Hideouts for Lease: Bulletproof Hosting Services. Retrieved March 6, 2017.
* https://eclecticlight.co/2020/11/16/checks-on-executable-code-in-catalina-and-big-sur-a-first-draft/ - Howard Oakley. (2020, November 16). Checks on executable code in Catalina and Big Sur: a first draft. Retrieved September 21, 2022.
* https://en.ryte.com/wiki/Tracking_Pixel/ - Ryte Wiki. (n.d.). Retrieved November 17, 2024.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Onion_routing - Wikipedia. (n.d.). Onion Routing. Retrieved October 20, 2020.
* https://en.wikipedia.org/wiki/Server_Message_Block - Wikipedia. (2017, December 16). Server Message Block. Retrieved December 21, 2017.
* https://en.wikipedia.org/wiki/Shared_resource - Wikipedia. (2017, April 15). Shared resource. Retrieved June 30, 2017.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://en.wikipedia.org/wiki/Windows_Registry - Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.
* https://github.com/Exploit-install/PSAttack-1 - Haight, J. (2016, April 21). PS>Attack. Retrieved September 27, 2024.
* https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_delete/registry_delete_schtasks_hide_task_via_sd_value_removal.yml - Sittikorn S. (2022, April 15). Removal Of SD Value to Hide Schedule Task - Registry. Retrieved June 1, 2022.
* https://github.com/danielbohannon/Invoke-DOSfuscation - Bohannon, D. (2018, March 19). Invoke-DOSfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Invoke-Obfuscation - Bohannon, D. (2016, September 24). Invoke-Obfuscation. Retrieved March 17, 2023.
* https://github.com/dhondta/awesome-executable-packing - Alexandre D'Hondt. (n.d.). Awesome Executable Packing. Retrieved March 11, 2022.
* https://github.com/dxa4481/truffleHog - Dylan Ayrey. (2016, December 31). truffleHog. Retrieved October 19, 2020.
* https://github.com/gremwell/o365enum - gremwell. (2020, March 24). Office 365 User Enumeration. Retrieved May 27, 2022.
* https://github.com/gtworek/PSBits/tree/master/NoRunDll - gtworek. (2019, December 17). NoRunDll. Retrieved August 23, 2021.
* https://github.com/hfiref0x/TDL - TDL Project. (2016, February 4). TDL (Turla Driver Loader). Retrieved April 22, 2021.
* https://github.com/kgretzky/evilginx2 - Gretzky, Kuba. (2019, April 10). Retrieved October 8, 2019.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://github.com/michenriksen/gitrob - Michael Henriksen. (2018, June 9). Gitrob: Putting the Open Source in OSINT. Retrieved October 19, 2020.
* https://github.com/muraenateam/muraena - Orrù, M., Trotta, G.. (2019, September 11). Muraena. Retrieved October 14, 2019.
* https://github.com/nsacyber/Mitigating-Web-Shells -  NSA Cybersecurity Directorate. (n.d.). Mitigating Web Shells. Retrieved July 22, 2021.
* https://github.com/rapid7/metasploit-framework/tree/master/modules/exploits/linux/ssh - undefined. (n.d.). Retrieved April 12, 2019.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.005/T1053.005.md - Red Canary - Atomic Red Team. (n.d.). T1053.005 - Scheduled Task/Job: Scheduled Task. Retrieved June 19, 2024.
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.002/T1562.002.md - redcanaryco. (2021, September 3). T1562.002 - Disable Windows Event Logging. Retrieved September 13, 2021.
* https://github.com/ryhanson/phishery - Ryan Hanson. (2016, September 24). phishery. Retrieved October 23, 2020.
* https://googleblog.blogspot.com/2011/06/ensuring-your-information-is-safe.html - Google. (2011, June 1). Ensuring your information is safe online. Retrieved April 1, 2022.
* https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/ - GrimHacker. (2017, July 24). Office365 ActiveSync Username Enumeration. Retrieved December 9, 2021.
* https://iapp.org/resources/article/web-beacon/ - IAPP. (n.d.). Retrieved March 5, 2024.
* https://info.lookout.com/rs/051-ESQ-475/images/Lookout_Dark-Caracal_srr_20180118_us_v.1.0.pdf - Blaich, A., et al. (2018, January 18). Dark Caracal: Cyber-espionage at a Global Scale. Retrieved April 11, 2018.
* https://insight-jp.nttsecurity.com/post/102hf3q/flagpro-the-new-malware-used-by-blacktech - Hada, H. (2021, December 28).  Flagpro The new malware used by BlackTech. Retrieved March 25, 2022.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://knowledge.broadcom.com/external/article/321910/auditing-esxi-shell-logins-and-commands.html - Broadcom. (2025, February 20). Auditing ESXi Shell logins and commands. Retrieved March 26, 2025.
* https://krebsonsecurity.com/2018/11/that-domain-you-forgot-to-renew-yeah-its-now-stealing-credit-cards/ - Krebs, B. (2018, November 13). That Domain You Forgot to Renew? Yeah, it’s Now Stealing Credit Cards. Retrieved September 20, 2019.
* https://krebsonsecurity.com/2019/02/a-deep-dive-on-the-recent-widespread-dns-hijacking-attacks/ - Brian Krebs. (2019, February 18). A Deep Dive on the Recent Widespread DNS Hijacking Attacks. Retrieved February 14, 2022.
* https://krebsonsecurity.com/2023/05/discord-admins-hacked-by-malicious-bookmarks/ - Brian Krebs. (2023, May 30). Discord Admins Hacked by Malicious Bookmarks. Retrieved January 2, 2024.
* https://kubernetes.io/docs/concepts/security/service-accounts/ - Kubernetes. (n.d.). Service Accounts. Retrieved July 14, 2023.
* https://labs.detectify.com/writeups/slack-bot-token-leakage-exposing-business-critical-information/ - Detectify. (2016, April 28). Slack bot token leakage exposing business critical information. Retrieved November 17, 2024.
* https://labs.portcullis.co.uk/download/eu-18-Wadhwa-Brown-Where-2-worlds-collide-Bringing-Mimikatz-et-al-to-UNIX.pdf - Tim Wadhwa-Brown. (2018, November). Where 2 worlds collide Bringing Mimikatz et al to UNIX. Retrieved October 13, 2021.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://learn.microsoft.com/en-us/exchange/security-and-compliance/mail-flow-rules/mail-flow-rules - Microsoft. (2023, February 22). Mail flow rules (transport rules) in Exchange Online. Retrieved March 13, 2023.
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/allow-log-on-through-remote-desktop-services - Microsoft. (2017, April 9). Allow log on through Remote Desktop Services. Retrieved August 5, 2024.
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc725622(v=ws.11) - Microsoft. (2016, August 31). Net Localgroup. Retrieved August 5, 2024.
* https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc754051(v=ws.11) - Microsoft. (2016, August 31). Net group. Retrieved August 5, 2024.
* https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/clip - Microsoft, JasonGerend, et al. (2023, February 3). clip. Retrieved June 21, 2022.
* https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys - Microsoft. (n.d.). Run and RunOnce Registry Keys. Retrieved September 12, 2024.
* https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-start-page?redirectedfrom=MSDN - Microsoft. (2023, March 7). Retrieved February 13, 2024.
* https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedcommand-base64encodedcommand - Microsoft. (2023, February 8). about_PowerShell_exe: EncodedCommand. Retrieved March 17, 2023.
* https://letsencrypt.org/docs/faq/ - Let's Encrypt. (2020, April 23). Let's Encrypt FAQ. Retrieved October 15, 2020.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://lolbas-project.github.io/lolbas/Binaries/Diantz/ - Living Off The Land Binaries, Scripts and Libraries (LOLBAS). (n.d.). Diantz.exe. Retrieved October 25, 2021.
* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/ - LOLBAS. (n.d.). Regsvr32.exe. Retrieved July 31, 2019.
* https://mackeeper.com/blog/find-wi-fi-password-on-mac/ - Ruslana Lishchuk. (2021, March 26). How to Find a Saved Wi-Fi Password on a Mac. Retrieved September 8, 2023.
* https://media.defense.gov/2020/Jun/09/2002313081/-1/-1/0/CSI-DETECT-AND-PREVENT-WEB-SHELL-MALWARE-20200422.PDF - Australian Cyber Security Centre. National Security Agency. (2020, April 21). Detect and Prevent Web Shell Malware. Retrieved February 9, 2024.
* https://medium.com/@adimenia/how-attackers-can-misuse-sitemaps-to-enumerate-users-and-discover-sensitive-information-361a5065857a - Adi Perez. (2023, February 22). How Attackers Can Misuse Sitemaps to Enumerate Users and Discover Sensitive Information. Retrieved July 18, 2024.
* https://medium.com/@galolbardes/learn-how-easy-is-to-bypass-firewalls-using-dns-tunneling-and-also-how-to-block-it-3ed652f4a000 - Galobardes, R. (2018, October 30). Learn how easy is to bypass firewalls using DNS tunneling (and also how to block it). Retrieved March 15, 2020.
* https://medium.com/rvrsh3ll/operating-with-empyre-ea764eda3363 - rvrsh3ll. (2016, May 18). Operating with EmPyre. Retrieved July 12, 2017.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://medium.com/threatpunter/detecting-removing-wmi-persistence-60ccbb7dff96 - French, D. (2018, October 9). Detecting & Removing an Attacker’s WMI Persistence. Retrieved October 11, 2019.
* https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2 - Koczwara, M. (2021, September 7). Hunting Cobalt Strike C2 with Shodan. Retrieved October 12, 2021.
* https://mrd0x.com/browser-in-the-browser-phishing-attack/ - mr.d0x. (2022, March 15). Browser In The Browser (BITB) Attack. Retrieved March 8, 2023.
* https://msdn.microsoft.com/en-us/library/dn280412 - Microsoft. (n.d.). AppInit DLLs and Secure Boot. Retrieved July 15, 2015.
* https://msdn.microsoft.com/en-us/library/ms649012 - Microsoft. (n.d.). About the Clipboard. Retrieved March 29, 2016.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/windows/desktop/bb968799.aspx - Microsoft. (n.d.). Background Intelligent Transfer Service. Retrieved January 12, 2018.
* https://msdn.microsoft.com/library/windows/desktop/ms680573.aspx - Microsoft. (n.d.). Component Object Model (COM). Retrieved November 22, 2017.
* https://nakedsecurity.sophos.com/2020/10/02/serious-security-phishing-without-links-when-phishers-bring-along-their-own-web-pages/ - Ducklin, P. (2020, October 2). Serious Security: Phishing without links – when phishers bring along their own web pages. Retrieved October 20, 2020.
* https://nodejs.org/ - OpenJS Foundation. (n.d.). Node.js. Retrieved June 23, 2020.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://o365blog.com/post/just-looking/ - Dr. Nestori Syynimaa. (2020, June 13). Just looking: Azure Active Directory reconnaissance as an outsider. Retrieved May 27, 2022.
* https://oddvar.moe/2018/03/21/persistence-using-runonceex-hidden-from-autoruns-exe/ - Moe, O. (2018, March 21). Persistence using RunOnceEx - Hidden from Autoruns.exe. Retrieved June 29, 2018.
* https://outflank.nl/blog/2019/06/19/red-team-tactics-combining-direct-system-calls-and-srdi-to-bypass-av-edr/ - de Plaa, C. (2019, June 19). Red Team Tactics: Combining Direct System Calls and sRDI to bypass AV/EDR. Retrieved September 29, 2021.
* https://owasp.org/www-community/attacks/CSV_Injection -  Albinowax Timo Goosen. (n.d.). CSV Injection. Retrieved February 7, 2022.
* https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-014_Vulnerability_Scanning - OWASP. (n.d.). OAT-014 Vulnerability Scanning. Retrieved October 20, 2020.
* https://pentera.io/blog/information-disclosure-in-vmware-vcenter/ - Yuval Lazar. (2022, March 29). Mitigating VMware vCenter Information Disclosure. Retrieved March 26, 2025.
* https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/ - Arthur Vaiselbuh, Peleg Cabra. (2024, November 7). Evasive ZIP Concatenation: Trojan Targets Windows Users. Retrieved March 3, 2025.
* https://portal.msrc.microsoft.com/security-guidance/advisory/ADV170021 - Microsoft. (2017, December 12). ADV170021 - Microsoft Office Defense in Depth Update. Retrieved February 3, 2018.
* https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944 - Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5 - Pitt, L. (2020, August 6). Persistent JXA. Retrieved April 14, 2021.
* https://posts.specterops.io/reviving-dde-using-onenote-and-excel-for-code-execution-d7226864caee - Nelson, M. (2018, January 29). Reviving DDE: Using OneNote and Excel for Code Execution. Retrieved February 3, 2018.
* https://powershellmagazine.com/2014/07/16/investigating-powershell-attacks/ - Hastings, M. (2014, July 16). Investigating PowerShell Attacks. Retrieved December 1, 2021.
* https://practical365.com/clients/office-365-proplus/outlook-cached-mode-ost-file-sizes/ - N. O'Bryan. (2018, May 30). Managing Outlook Cached Mode and OST File Sizes. Retrieved February 19, 2020.
* https://ptylu.github.io/content/report/report.html?report=25 - Heiligenstein, L. (n.d.). REP-25: Disable Windows Event Logging. Retrieved April 7, 2022.
* https://redcanary.com/blog/clipping-silver-sparrows-wings/ - Tony Lambert. (2021, February 18). Clipping Silver Sparrow’s wings: Outing macOS malware before it takes flight. Retrieved April 20, 2021.
* https://redcanary.com/threat-detection-report/techniques/powershell/ - Red Canary. (n.d.). 2022 Threat Detection Report: PowerShell. Retrieved March 17, 2023.
* https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/ - Check Point. (2022, January 11). APT35 exploits Log4j vulnerability to distribute new modular PowerShell toolkit. Retrieved January 24, 2022.
* https://researchcenter.paloaltonetworks.com/2017/11/unit42-uboatrat-navigates-east-asia/ - Hayashi, K. (2017, November 28). UBoatRAT Navigates East Asia. Retrieved January 12, 2018.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/ - Gietzen, S. (n.d.). S3 Ransomware Part 1: Attack Vector. Retrieved April 14, 2021.
* https://rootdse.org/posts/monitoring-realtime-activedirectory-domain-scenarios - Scarred Monk. (2022, May 6). Real-time detection scenarios in Active Directory environments. Retrieved August 5, 2024.
* https://sarah-edwards-xzkc.squarespace.com/blog/2020/4/30/analysis-of-apple-unified-logs-quarantine-edition-entry-6-working-from-home-remote-logins - Sarah Edwards. (2020, April 30). Analysis of Apple Unified Logs: Quarantine Edition [Entry 6] – Working From Home? Remote Logins. Retrieved August 19, 2021.
* https://sec.okta.com/scatterswine - Okta. (2022, August 25). Detecting Scatter Swine: Insights into a Relentless Phishing Campaign. Retrieved February 24, 2023.
* https://securelist.com/old-malware-tricks-to-bypass-detection-in-the-age-of-big-data/78010/ - Ishimaru, S.. (2017, April 13). Old Malware Tricks To Bypass Detection in the Age of Big Data. Retrieved May 30, 2019.
* https://securelist.com/project-tajmahal/90240/ - GReAT. (2019, April 10). Project TajMahal – a sophisticated new APT framework. Retrieved October 14, 2019.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://securityintelligence.com/anatomy-of-an-hvnc-attack/ - Keshet, Lior. Kessem, Limor. (2017, January 25). Anatomy of an hVNC Attack. Retrieved November 28, 2023.
* https://securityintelligence.com/posts/brazking-android-malware-upgraded-targeting-brazilian-banks/ - Shahar Tavor. (n.d.). BrazKing Android Malware Upgraded and Targeting Brazilian Banks. Retrieved March 24, 2023.
* https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within/ - El-Sherei, S. (2016, May 20). PowerShell, C-Sharp and DDE The Power Within. Retrieved November 22, 2017.
* https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/ - Stalmans, E., El-Sherei, S. (2017, October 9). Macro-less Code Exec in MSWord. Retrieved November 21, 2017.
* https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved November 17, 2024.
* https://social.technet.microsoft.com/Forums/en-US/e5bca729-52e7-4fcb-ba12-3225c564674c/scheduled-tasks-history-retention-settings?forum=winserver8gen - Satyajit321. (2015, November 3). Scheduled Tasks History Retention settings. Retrieved December 12, 2017.
* https://stackoverflow.com/questions/2913816/how-to-find-the-location-of-the-scheduled-tasks-folder - Stack Overflow. (n.d.). How to find the location of the Scheduled Tasks folder. Retrieved June 19, 2024.
* https://static.carahsoft.com/concrete/files/1015/2779/3571/M-Trends-2018-Report.pdf - Mandiant. (2018). Mandiant M-Trends 2018. Retrieved November 17, 2024.
* https://strontic.github.io/xcyclopedia/library/auditpol.exe-214E0EA1F7F7C27C82D23F183F9D23F1.html - STRONTIC. (n.d.). auditpol.exe. Retrieved September 9, 2021.
* https://support.apple.com/guide/mail/reply-to-forward-or-redirect-emails-mlhlp1010/mac - Apple. (n.d.). Reply to, forward, or redirect emails in Mail on Mac. Retrieved June 22, 2021.
* https://support.apple.com/guide/remote-desktop/set-up-a-computer-running-vnc-software-apdbed09830/mac - Apple Support. (n.d.). Set up a computer running VNC software for Remote Desktop. Retrieved August 18, 2021.
* https://support.google.com/a/answer/166870?hl=en - Google. (n.d.). Retrieved March 16, 2021.
* https://support.google.com/a/answer/7223765?hl=en - Google. (n.d.). Turn Gmail delegation on or off. Retrieved April 1, 2022.
* https://support.microsoft.com/en-us/kb/197571 - Microsoft. (2006, October). Working with the AppInit_DLLs registry value. Retrieved July 15, 2015.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://support.office.com/en-us/article/introduction-to-outlook-data-files-pst-and-ost-222eaf92-a995-45d9-bde2-f331f60e2790 - Microsoft. (n.d.). Introduction to Outlook Data Files (.pst and .ost). Retrieved February 19, 2020.
* https://svch0st.medium.com/event-log-tampering-part-1-disrupting-the-eventlog-service-8d4b7d67335c - svch0st. (2020, September 30). Event Log Tampering Part 1: Disrupting the EventLog Service. Retrieved September 14, 2021.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://techcommunity.microsoft.com/t5/core-infrastructure-and-security/demystifying-ransomware-attacks-against-microsoft-defender/ba-p/1928947 - Tran, T. (2020, November 24). Demystifying Ransomware Attacks Against Microsoft Defender Solution. Retrieved January 26, 2022.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://techcommunity.microsoft.com/t5/windows-it-pro-blog/wmi-command-line-wmic-utility-deprecation-next-steps/ba-p/4039242 - Microsoft. (2024, January 26). WMIC Deprecation. Retrieved February 13, 2024.
* https://techdocs.broadcom.com/us/en/vmware-cis/vsphere/vsphere/7-0/add-allowed-ip-addresses-for-an-esxi-host-by-using-the-vmware-host-client.html - Broadcom. (2025, March 24). Add Allowed IP Addresses for an ESXi Host by Using the VMware Host Client. Retrieved March 26, 2025.
* https://technet.microsoft.com/en-us/library/bb490996.aspx - Microsoft. (n.d.). Schtasks. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://technet.microsoft.com/library/cc770880.aspx - Microsoft. (n.d.). Share a Folder or Drive. Retrieved June 30, 2017.
* https://technet.microsoft.com/library/dd315590.aspx - Microsoft. (n.d.). General Task Registration. Retrieved December 12, 2017.
* https://technet.microsoft.com/library/dd939934.aspx - Microsoft. (2011, July 19). Issues with BITS. Retrieved January 12, 2018.
* https://technet.microsoft.com/library/security/4053440 - Microsoft. (2017, November 8). Microsoft Security Advisory 4053440 - Securely opening Microsoft Office documents that contain Dynamic Data Exchange (DDE) fields. Retrieved November 21, 2017.
* https://thedfirreport.com/2022/11/28/emotet-strikes-again-lnk-file-leads-to-domain-wide-ransomware/ - The DFIR Report. (2022, November 8). Emotet Strikes Again – LNK File Leads to Domain Wide Ransomware. Retrieved March 6, 2023.
* https://thehackernews.com/2022/05/avoslocker-ransomware-variant-using-new.html - Lakshmanan, R. (2022, May 2). AvosLocker Ransomware Variant Using New Trick to Disable Antivirus Protection. Retrieved May 17, 2022.
* https://thehackernews.com/2023/04/hackers-using-self-extracting-archives.html - Ravie Lakshmanan. (2023, April 5). Hackers Using Self-Extracting Archives Exploit for Stealthy Backdoor Attacks. Retrieved March 3, 2025.
* https://thehackernews.com/expert-insights/2024/05/github-abuse-flaw-shows-why-we-cant.html - Dvir Sasson. (2024, May 13). GitHub Abuse Flaw Shows Why We Can't Shrug Off Abuse Vulnerabilities in Security. Retrieved March 31, 2025.
* https://themittenmac.com/what-does-apt-activity-look-like-on-macos/ - Jaron Bradley. (2021, November 14). What does APT Activity Look Like on macOS?. Retrieved January 19, 2022.
* https://therecord.media/phishing-campaign-used-qr-codes-to-target-energy-firm - Jonathan Greig. (2023, August 16). Phishing campaign used QR codes to target large energy company. Retrieved November 27, 2023.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://threatpost.com/broadvoice-leaks-350m-records-voicemail-transcripts/160158/ - Seals, T. (2020, October 15). Broadvoice Leak Exposes 350M Records, Personal Voicemail Transcripts. Retrieved October 20, 2020.
* https://threatpost.com/final-report-diginotar-hack-shows-total-compromise-ca-servers-103112/77170/ - Fisher, D. (2012, October 31). Final Report on DigiNotar Hack Shows Total Compromise of CA Servers. Retrieved March 6, 2017.
* https://tools.cisco.com/security/center/resources/integrity_assurance.html#23 - Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.
* https://trustedsec.com/blog/to-oob-or-not-to-oob-why-out-of-band-communications-are-essential-for-incident-response - Tyler Hudak. (2022, December 29). To OOB, or Not to OOB?: Why Out-of-Band Communications are Essential for Incident Response. Retrieved August 30, 2024.
* https://ubuntu.com/server/docs/service-sssd - Ubuntu. (n.d.). SSSD. Retrieved September 23, 2021.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://unit42.paloaltonetworks.com/domain-shadowing/ - Janos Szurdi, Rebekah Houser and Daiping Liu. (2022, September 21). Domain Shadowing: A Stealthy Use of DNS Compromise for Cybercrime. Retrieved March 7, 2023.
* https://unit42.paloaltonetworks.com/hildegard-malware-teamtnt/ - Chen, J. et al. (2021, February 3). Hildegard: New TeamTNT Cryptojacking Malware Targeting Kubernetes. Retrieved April 5, 2021.
* https://unit42.paloaltonetworks.com/mac-malware-steals-cryptocurrency-exchanges-cookies/ - Chen, Y., Hu, W., Xu, Z., et. al. (2019, January 31). Mac Malware Steals Cryptocurrency Exchanges’ Cookies. Retrieved October 14, 2019.
* https://unit42.paloaltonetworks.com/manageengine-godzilla-nglite-kdcsponge/ - Robert Falcone, Jeff White, and Peter Renals. (2021, November 7). Targeted Attack Campaign Against ManageEngine ADSelfService Plus Delivers Godzilla Webshells, NGLite Trojan and KdcSponge Stealer. Retrieved February 8, 2024.
* https://unit42.paloaltonetworks.com/new-babyshark-malware-targets-u-s-national-security-think-tanks/ - Unit 42. (2019, February 22). New BabyShark Malware Targets U.S. National Security Think Tanks. Retrieved October 7, 2019.
* https://unit42.paloaltonetworks.com/purpleurchin-steals-cloud-resources/ - Gamazo, William. Quist, Nathaniel.. (2023, January 5). PurpleUrchin Bypasses CAPTCHA and Steals Cloud Platform Resources. Retrieved February 28, 2024.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a - CISA. (2021, May 6). Analysis Report (AR21-126A) FiveHands Ransomware. Retrieved June 7, 2021.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://viruspositive.com/resources/blogs/the-dark-side-of-web-push-notifications - Gaurav Sethi. (2021, December 14). The Dark Side of Web Push Notifications. Retrieved March 14, 2025.
* https://vms.drweb.com/virus/?i=4276269 - Doctor Web. (2014, November 21). Linux.BackDoor.Fysbis.1. Retrieved December 7, 2017.
* https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://web.archive.org/web/20160327101330/http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* https://web.archive.org/web/20160629094859/https://www2.fireeye.com/rs/fireye/images/rpt-m-trends-2015.pdf - Mandiant. (2015, February 24). M-Trends 2015: A View from the Front Lines. Retrieved November 17, 2024.
* https://web.archive.org/web/20170923102302/https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://web.archive.org/web/20171223000420/https://www.riskiq.com/blog/labs/lazarus-group-cryptocurrency/ - RISKIQ. (2017, December 20). Mining Insights: Infrastructure Analysis of Lazarus Group Cyber Attacks on the Cryptocurrency Industry. Retrieved July 29, 2022.
* https://web.archive.org/web/20190508170150/https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://web.archive.org/web/20191115195333/https://www.crowdstrike.com/blog/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 17, 2024.
* https://web.archive.org/web/20210708014107/https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved November 17, 2024.
* https://web.archive.org/web/20210920172620/https://www.fireeye.com/blog/threat-research/2012/08/hikit-rootkit-advanced-persistent-attack-techniques-part-2.html - Glyer, C., Kazanciyan, R. (2012, August 22). The “Hikit” Rootkit: Advanced and Persistent Attack Techniques (Part 2). Retrieved November 17, 2024.
* https://web.archive.org/web/20211107115646/https://twitter.com/klinix5/status/1457316029114327040 - Naceri, A. (2021, November 7). Windows Server 2019 file overwrite bug. Retrieved April 7, 2022.
* https://web.archive.org/web/20220527112908/https://www.riskiq.com/blog/labs/ukraine-malware-infrastructure/ - RISKIQ. (2022, March 15). RiskIQ Threat Intelligence Roundup: Campaigns Targeting Ukraine and Global Malware Infrastructure. Retrieved July 29, 2022.
* https://web.archive.org/web/20220629230035/https://www.prevailion.com/darkwatchman-new-fileless-techniques/ - Smith, S., Stafford, M. (2021, December 14). DarkWatchman: A new evolution in fileless techniques. Retrieved January 10, 2022.
* https://web.archive.org/web/20221203203722/https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved November 17, 2024.
* https://web.archive.org/web/20230602111604/https://www.opm.gov/cybersecurity/cybersecurity-incidents/ - Cybersecurity Resource Center. (n.d.). CYBERSECURITY INCIDENTS. Retrieved September 16, 2024.
* https://who.is/ - NTT America. (n.d.). Whois Lookup. Retrieved November 17, 2024.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://wunderwuzzi23.github.io/blog/passthecookie.html - Rehberger, J. (2018, December). Pivot to the Cloud using Pass the Cookie. Retrieved April 5, 2019.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.akamai.com/blog/security/catch-me-if-you-can-javascript-obfuscation - Katz, O. (2020, October 26). Catch Me if You Can—JavaScript Obfuscation. Retrieved March 17, 2023.
* https://www.amnesty.org/en/latest/research/2021/07/forensic-methodology-report-how-to-catch-nso-groups-pegasus/ - Amnesty International Security Lab. (2021, July 18). Forensic Methodology Report: How to catch NSO Group’s Pegasus. Retrieved February 22, 2022.
* https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/ - Michael Katchinskiy and Assaf Morag. (2023, April 21). First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters. Retrieved March 24, 2025.
* https://www.attackify.com/blog/rundll32_execution_order/ - Attackify. (n.d.). Rundll32.exe Obscurity. Retrieved August 23, 2021.
* https://www.autohotkey.com/docs/v1/Program.htm - AutoHotkey Foundation LLC. (n.d.). Using the Program. Retrieved March 29, 2024.
* https://www.autoitscript.com/autoit3/docs/intro/running.htm - AutoIT. (n.d.). Running Scripts. Retrieved March 29, 2024.
* https://www.binarydefense.com/resources/blog/emotet-evolves-with-new-wi-fi-spreader/ - Binary Defense. (n.d.). Emotet Evolves With new Wi-Fi Spreader. Retrieved September 8, 2023.
* https://www.blackhat.com/presentations/bh-dc-08/McFeters-Rios-Carter/Presentation/bh-dc-08-mcfeters-rios-carter.pdf - Nathan McFeters. Billy Kim Rios. Rob Carter.. (2008). URI Use and Abuse. Retrieved February 9, 2024.
* https://www.blackhillsinfosec.com/attacking-exchange-with-mailsniper/ - Bullock, B.. (2016, October 3). Attacking Exchange with MailSniper. Retrieved October 6, 2019.
* https://www.blackhillsinfosec.com/bypass-web-proxy-filtering/ - Fehrman, B. (2017, April 13). How to Bypass Web-Proxy Filtering. Retrieved September 20, 2019.
* https://www.bleepingcomputer.com/news/microsoft/microsoft-disables-dde-feature-in-word-to-prevent-further-malware-attacks/ - Cimpanu, C. (2017, December 15). Microsoft Disables DDE Feature in Word to Prevent Further Malware Attacks. Retrieved December 19, 2017.
* https://www.bleepingcomputer.com/news/security/2easy-now-a-significant-dark-web-marketplace-for-stolen-data/ - Bill Toulas. (2021, December 21). 2easy now a significant dark web marketplace for stolen data. Retrieved October 7, 2024.
* https://www.bleepingcomputer.com/news/security/dissecting-the-dark-web-supply-chain-stealer-logs-in-context/ - Flare. (2023, June 6). Dissecting the Dark Web Supply Chain: Stealer Logs in Context. Retrieved October 10, 2024.
* https://www.bleepingcomputer.com/news/security/hackers-steal-wifi-passwords-using-upgraded-agent-tesla-malware/ - Sergiu Gatlan. (2020, April 16). Hackers steal WiFi passwords using upgraded Agent Tesla malware. Retrieved September 8, 2023.
* https://www.bleepingcomputer.com/news/security/new-godlua-malware-evades-traffic-monitoring-via-dns-over-https/ - Gatlan, S. (2019, July 3). New Godlua Malware Evades Traffic Monitoring via DNS over HTTPS. Retrieved March 15, 2020.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/ - Baskin, B. (2020, July 8). TAU Threat Discovery: Conti Ransomware. Retrieved February 17, 2021.
* https://www.circl.lu/services/passive-dns/ - CIRCL Computer Incident Response Center. (n.d.). Passive DNS. Retrieved October 20, 2020.
* https://www.cisa.gov/news-events/alerts/2018/03/15/russian-government-cyber-activity-targeting-energy-and-other-critical-infrastructure-sectors - CISA. (2018, March 16). Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved March 24, 2025.
* https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a - CISA. (2021, April 15). Advanced Persistent Threat Compromise of Government Agencies, Critical Infrastructure, and Private Sector Organizations. Retrieved August 30, 2024.
* https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a - CISA. (2023, March 16). #StopRansomware: LockBit 3.0. Retrieved March 24, 2025.
* https://www.cisa.gov/uscert/ncas/alerts/aa21-200b - CISA. (2021, August 20). Alert (AA21-200B) Chinese State-Sponsored Cyber Operations: Observed TTPs. Retrieved June 21, 2022.
* https://www.cisa.gov/uscert/ncas/alerts/aa22-074a - Cybersecurity and Infrastructure Security Agency. (2022, March 15). Russian State-Sponsored Cyber Actors Gain Network Access by Exploiting Default Multifactor Authentication Protocols and “PrintNightmare” Vulnerability. Retrieved March 16, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_monitor_permit_list_through_show_process_memory.html#wp3599497760 - Cisco. (2022, August 16). show processes - . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_protocols_through_showmon.html#wp2760878733 - Cisco. (2022, August 16). show running-config - Cisco IOS Configuration Fundamentals Command Reference . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html - Cisco. (2023, March 7). Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-t2.html#wp1047035630 - Cisco. (2023, March 6). username - Cisco IOS Security Command Reference: Commands S to Z. Retrieved July 13, 2022.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/ - Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.
* https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/ - Mudge, R. (2017, February 6). High-reputation Redirectors and Domain Fronting. Retrieved July 11, 2022.
* https://www.comparitech.com/blog/vpn-privacy/350-million-customer-records-exposed-online/ - Bischoff, P. (2020, October 15). Broadvoice database of more than 350 million customer records exposed online. Retrieved October 20, 2020.
* https://www.contextis.com/blog/comma-separated-vulnerabilities - Kettle, J. (2014, August 29). Comma Separated Vulnerabilities. Retrieved November 22, 2017.
* https://www.coretechnologies.com/blog/windows-services/eventlog/ - Core Technologies. (2021, May 24). Essential Windows Services: EventLog / Windows Event Log. Retrieved September 14, 2021.
* https://www.crowdstrike.com/blog/hiding-in-plain-sight-using-the-office-365-activities-api-to-investigate-business-email-compromises/ - Crowdstrike. (2018, July 18). Hiding in Plain Sight: Using the Office 365 Activities API to Investigate Business Email Compromises. Retrieved January 19, 2020.
* https://www.crowdstrike.com/blog/how-doppelpaymer-hunts-and-kills-windows-processes/ - Hurley, S. (2021, December 7). Critical Hit: How DoppelPaymer Hunts and Kills Windows Processes. Retrieved January 26, 2022.
* https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/ - Jai Minton. (2023, March 31). How Falcon OverWatch Investigates Malicious Self-Extracting Archives, Decoy Files and Their Hidden Payloads. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/shlayer-malvertising-campaigns-still-using-flash-update-disguise/ - Aspen Lindblom, Joseph Goodwin, and Chris Sheldon. (2021, July 19). Shlayer Malvertising Campaigns Still Using Flash Update Disguise. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/targeted-dharma-ransomware-intrusions-exhibit-consistent-techniques/ - Loui, E. Scheuerman, K. et al. (2020, April 16). Targeted Dharma Ransomware Intrusions Exhibit Consistent Techniques. Retrieved January 26, 2022.
* https://www.crowdstrike.com/en-us/blog/hypervisor-jackpotting-ecrime-actors-increase-targeting-of-esxi-servers/ - Michael Dawson. (2021, August 30). Hypervisor Jackpotting, Part 2: eCrime Actors Increase Targeting of ESXi Servers with Ransomware. Retrieved March 26, 2025.
* https://www.cynet.com/attack-techniques-hands-on/defense-evasion-techniques/ - Ariel silver. (2022, February 1). Defense Evasion Techniques. Retrieved April 8, 2022.
* https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2 - Gilboa, A. (2021, February 16). LSASS Memory Dumps are Stealthier than Ever Before - Part 2. Retrieved December 27, 2023.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.
* https://www.elastic.co/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.elastic.co/blog/hunting-for-persistence-using-elastic-security-part-1 - French, D., Murphy, B. (2020, March 24). Adversary tradecraft 101: Hunting for persistence using Elastic Security (Part 1). Retrieved December 21, 2020.
* https://www.elastic.co/guide/en/security/7.17/shortcut-file-written-or-modified-for-persistence.html#shortcut-file-written-or-modified-for-persistence - Elastic. (n.d.). Shortcut File Written or Modified for Persistence. Retrieved June 1, 2022.
* https://www.elastic.co/security-labs/cuba-ransomware-campaign-analysis - Daniel Stepanic, Derek Ditch, Seth Goodwin, Salim Bitam, Andrew Pease. (2022, September 7). CUBA Ransomware Campaign Analysis. Retrieved August 5, 2024.
* https://www.elastic.co/security-labs/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 17, 2024.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.exploit-db.com/google-hacking-database - Offensive Security. (n.d.). Google Hacking Database. Retrieved October 23, 2020.
* https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf - F-Secure Labs. (2015, September 17). The Dukes: 7 years of Russian cyberespionage. Retrieved December 10, 2015.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/05/wannacry-malware-profile.html - Berry, A., Homan, J., and Eitzman, R. (2017, May 23). WannaCry Malware Profile. Retrieved March 15, 2019.
* https://www.fireeye.com/blog/threat-research/2019/06/hunting-com-objects.html - Hamilton, C. (2019, June 4). Hunting COM Objects. Retrieved June 10, 2019.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.forbes.com/sites/runasandvik/2014/01/14/attackers-scrape-github-for-cloud-service-credentials-hijack-account-to-mine-virtual-currency/#242c479d3196 - Sandvik, R. (2014, January 14). Attackers Scrape GitHub For Cloud Service Credentials, Hijack Account To Mine Virtual Currency. Retrieved October 19, 2020.
* https://www.fortinet.com/blog/psirt-blogs/fg-ir-22-369-psirt-analysis -  Guillaume Lovet and Alex Kong. (2023, March 9). Analysis of FG-IR-22-369. Retrieved May 15, 2023.
* https://www.fortinet.com/blog/threat-research/analysis-of-new-agent-tesla-spyware-variant.html - Zhang, X. (2018, April 05). Analysis of New Agent Tesla Spyware Variant. Retrieved November 5, 2018.
* https://www.freedesktop.org/software/systemd/man/systemd.service.html - Freedesktop.org. (n.d.). systemd.service — Service unit configuration. Retrieved March 16, 2020.
* https://www.geeksforgeeks.org/wi-fi-password-connected-networks-windowslinux/ - Geeks for Geeks. (n.d.). Wi-Fi Password of All Connected Networks in Windows/Linux. Retrieved September 8, 2023.
* https://www.hackers-arise.com/email-scraping-and-maltego - Hackers Arise. (n.d.). Email Scraping and Maltego. Retrieved October 20, 2020.
* https://www.hackingarticles.in/defense-evasion-windows-event-logging-t1562-002/ - Chandel, R. (2021, April 22). Defense Evasion: Windows Event Logging (T1562.002). Retrieved September 14, 2021.
* https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c - Halcyon RISE Team. (2025, January 13). Abusing AWS Native Services: Ransomware Encrypting S3 Buckets with SSE-C. Retrieved March 18, 2025.
* https://www.huntress.com/blog/blackcat-ransomware-affiliate-ttps - Carvey, H. (2024, February 28). BlackCat Ransomware Affiliate TTPs. Retrieved March 27, 2024.
* https://www.huntress.com/blog/moveit-transfer-critical-vulnerability-rapid-response - John Hammond. (2023, June 1). MOVEit Transfer Critical Vulnerability CVE-2023-34362 Rapid Response. Retrieved August 5, 2024.
* https://www.huntress.com/blog/smugglers-gambit-uncovering-html-smuggling-adversary-in-the-middle-tradecraft - Matt Kiely. (2024, July 5). Smuggler’s Gambit: Uncovering HTML Smuggling Adversary in the Middle Tradecraft. Retrieved March 18, 2025.
* https://www.ic3.gov/Media/News/2022/220818.pdf - FBI. (2022, August 18). Proxies and Configurations Used for Credential Stuffing Attacks on Online Customer Accounts . Retrieved July 6, 2023.
* https://www.icann.org/en/ssac/registration-services/documents/sac-007-domain-name-hijacking-incidents-threats-risks-and-remediation-12-07-2005-en - ICANN Security and Stability Advisory Committee. (2005, July 12). Domain Name Hijacking: Incidents, Threats, Risks and Remediation. Retrieved November 17, 2024.
* https://www.intezer.com/blog/malware-analysis/kud-i-enter-your-server-new-vulnerabilities-in-microsoft-azure/ - Paul Litvak. (2020, October 8). Kud I Enter Your Server? New Vulnerabilities in Microsoft Azure. Retrieved August 18, 2022.
* https://www.invictus-ir.com/news/ransomware-in-the-cloud - Invictus IR. (2024, January 11). Ransomware in the cloud. Retrieved August 5, 2024.
* https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me - Invictus Incident Response. (2024, January 31). The curious case of DangerDev@protonmail.me. Retrieved March 19, 2024.
* https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection - Red Teaming Experiments. (n.d.). Module Stomping for Shellcode Injection. Retrieved July 14, 2022.
* https://www.irongeek.com/i.php?page=videos/bsidescharm2017/bsidescharm-2017-t111-microsoft-patch-analysis-for-exploitation-stephen-sims - Stephen Sims. (2017, April 30). Microsoft Patch Analysis for Exploitation. Retrieved October 16, 2020.
* https://www.justice.gov/opa/pr/justice-department-conducts-court-authorized-disruption-botnet-controlled-russian - Office of Public Affairs. (2024, February 15). Justice Department Conducts Court-Authorized Disruption of Botnet Controlled by the Russian Federation’s Main Intelligence Directorate of the General Staff (GRU). Retrieved March 28, 2024.
* https://www.kaspersky.com/blog/malicious-redirect-methods/50045/ - Dedenok, Roman. (2023, December 12). How cybercriminals disguise URLs. Retrieved January 17, 2024.
* https://www.malwarebytes.com/blog/news/2019/01/browser-push-notifications-feature-asking-abused - Pieter Arntz. (2019, January 22). Browser push notifications: a feature asking to be abused. Retrieved March 14, 2025.
* https://www.malwarebytes.com/blog/news/2020/04/new-agenttesla-variant-steals-wifi-credentials - Hossein Jazi. (2020, April 16). New AgentTesla variant steals WiFi credentials. Retrieved September 8, 2023.
* https://www.malwaretech.com/2015/09/hidden-vnc-for-beginners.html - Hutchins, Marcus. (2015, September 13). Hidden VNC for Beginners. Retrieved November 28, 2023.
* https://www.man7.org/linux/man-pages/man8/usermod.8.html - Man7. (n.d.). Usermod. Retrieved August 5, 2024.
* https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits - Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022.
* https://www.mandiant.com/resources/blog/apt29-continues-targeting-microsoft - Douglas Bienstock. (2022, August 18). You Can’t Audit Me: APT29 Continues Targeting Microsoft 365. Retrieved February 23, 2023.
* https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem - Marvi, A. et al.. (2023, March 16). Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation. Retrieved March 22, 2023.
* https://www.mandiant.com/resources/blog/remediation-and-hardening-strategies-for-microsoft-365-to-defend-against-unc2452 - Mandiant. (2021, January 19). Remediation and Hardening Strategies for Microsoft 365 to Defend Against UNC2452. Retrieved January 22, 2021.
* https://www.mandiant.com/resources/blog/unc3524-eye-spy-email - Mandiant. (2022, May 2). UNC3524: Eye Spy on Your Email. Retrieved August 17, 2023.
* https://www.mandiant.com/resources/blog/url-obfuscation-schema-abuse - Nick Simonian. (2023, May 22). Don't @ Me: URL Obfuscation Through Schema Abuse. Retrieved August 4, 2023.
* https://www.mandiant.com/resources/chasing-avaddon-ransomware - Hernandez, A. S. Tarter, P. Ocamp, E. J. (2022, January 19). One Source to Rule Them All: Chasing AVADDON Ransomware. Retrieved January 26, 2022.
* https://www.mandiant.com/resources/reports - Mandiant. (n.d.). Retrieved February 13, 2024.
* https://www.mandiant.com/resources/supply-chain-analysis-from-quartermaster-to-sunshop - FireEye. (2014). SUPPLY CHAIN ANALYSIS: From Quartermaster to SunshopFireEye. Retrieved March 6, 2017.
* https://www.mandiant.com/sites/default/files/2021-09/mtrends-2020.pdf - Mandiant. (2020, February). M-Trends 2020. Retrieved November 17, 2024.
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/scammers-impersonating-windows-defender-to-push-malicious-windows-apps/ - Craig Schmugar. (2021, May 17). Scammers Impersonating Windows Defender to Push Malicious Windows Apps. Retrieved March 14, 2025.
* https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/ - MDSec Research. (2017, July). Categorisation is not a Security Boundary. Retrieved September 20, 2019.
* https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/ - MDSec Research. (2020, December). Bypassing User-Mode Hooks and Direct Invocation of System Calls for Red Teams. Retrieved September 29, 2021.
* https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/ - Dominic Chell. (2021, January 1). macOS Post-Exploitation Shenanigans with VSCode Extensions. Retrieved April 20, 2021.
* https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/ - Microsoft. (2022, June 13). BlackCat. Retrieved February 13, 2024.
* https://www.microsoft.com/en-us/security/blog/2023/08/02/midnight-blizzard-conducts-targeted-social-engineering-over-microsoft-teams/ - Microsoft Threat Intelligence. (2023, August 2). Midnight Blizzard conducts targeted social engineering over Microsoft Teams. Retrieved February 16, 2024.
* https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/ - Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.
* https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/ - Weizman, Y. (2020, April 2). Threat Matrix for Kubernetes. Retrieved March 30, 2021.
* https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/ - Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.
* https://www.microsoft.com/security/blog/2022/03/22/dev-0537-criminal-actor-targeting-organizations-for-data-exfiltration-and-destruction/ - Microsoft. (2022, March 22). DEV-0537 criminal actor targeting organizations for data exfiltration and destruction. Retrieved March 23, 2022.
* https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ - Microsoft Threat Intelligence Team & Detection and Response Team . (2022, April 12). Tarrask malware uses scheduled tasks for defense evasion. Retrieved June 1, 2022.
* https://www.netskope.com/blog/a-big-catch-cloud-phishing-from-google-app-engine-and-azure-app-service - Ashwin Vamshi. (2020, August 12). A Big Catch: Cloud Phishing from Google App Engine and Azure App Service. Retrieved August 18, 2022.
* https://www.netskope.com/blog/new-phishing-attacks-exploiting-oauth-authorization-flows-part-1 - Jenko Hwong. (2021, August 10). New Phishing Attacks Exploiting OAuth Authorization Flows (Part 1). Retrieved March 19, 2024.
* https://www.netskope.com/blog/targeted-attacks-abusing-google-cloud-platform-open-redirection - Ashwin Vamshi. (2019, January 24). Targeted Attacks Abusing Google Cloud Platform Open Redirection. Retrieved August 18, 2022.
* https://www.nytimes.com/2011/01/16/world/middleeast/16stuxnet.html - William J. Broad, John Markoff, and David E. Sanger. (2011, January 15). Israeli Test on Worm Called Crucial in Iran Nuclear Delay. Retrieved March 1, 2017.
* https://www.obsidiansecurity.com/blog/behind-the-breach-self-service-password-reset-azure-ad/ - Noah Corradin and Shuyang Wang. (2023, August 1). Behind The Breach: Self-Service Password Reset (SSPR) Abuse in Azure AD. Retrieved March 28, 2024.
* https://www.optiv.com/insights/source-zero/blog/microsoft-365-oauth-device-code-flow-and-phishing - Optiv. (2021, August 17). Microsoft 365 OAuth Device Code Flow and Phishing. Retrieved March 19, 2024.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.paloaltonetworks.com/cyberpedia/what-is-dns-tunneling - Palo Alto Networks. (n.d.). What Is DNS Tunneling?. Retrieved March 15, 2020.
* https://www.pcmag.com/news/hackers-try-to-phish-united-nations-staffers-with-fake-login-pages - Kan, M. (2019, October 24). Hackers Try to Phish United Nations Staffers With Fake Login Pages. Retrieved October 20, 2020.
* https://www.proofpoint.com/sites/default/files/threat-reports/pfpt-us-tr-human-factor-report.pdf - Proofpoint. (n.d.). The Human Factor 2023: Analyzing the cyber attack chain. Retrieved July 20, 2023.
* https://www.proofpoint.com/us/blog/email-and-cloud-threats/cybersecurity-stop-month-qr-code-phishing - Tim Bedard and Tyler Johnson. (2023, October 4). QR Code Scams & Phishing. Retrieved November 27, 2023.
* https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain - Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.
* https://www.proofpoint.com/us/threat-insight/post/threat-actor-profile-ta407-silent-librarian - Proofpoint Threat Insight Team. (2019, September 5). Threat Actor Profile: TA407, the Silent Librarian. Retrieved February 3, 2021.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/blog/esxiargs-ransomware-targets-vmware-esxi-openslp-servers - German Hoeffner, Aaron Soehnen and Gianni Perez. (2023, February 7). ESXiArgs Ransomware Targets Publicly-Exposed ESXi OpenSLP Servers. Retrieved March 26, 2025.
* https://www.recordedfuture.com/blog/identifying-cobalt-strike-servers - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved September 16, 2024.
* https://www.recordedfuture.com/research/cobalt-strike-servers - Insikt Group. (2019, June 18). A Multi-Method Approach to Identifying Rogue Cobalt Strike Servers. Retrieved September 16, 2024.
* https://www.recordedfuture.com/threat-intelligence-101/threat-analysis-techniques/google-dorks - Borges, E. (2019, March 5). Exploring Google Hacking Techniques. Retrieved September 12, 2024.
* https://www.sec.gov/edgar/search/ - U.S. SEC. (n.d.). EDGAR - Search and Access. Retrieved November 17, 2024.
* https://www.secureworks.com/blog/malware-lingers-with-bits - Counter Threat Unit Research Team. (2016, June 6). Malware Lingers with BITS. Retrieved January 12, 2018.
* https://www.secureworks.com/blog/oauths-device-code-flow-abused-in-phishing-attacks - SecureWorks Counter Threat Unit Research Team. (2021, June 3). OAuth’S Device Code Flow Abused in Phishing Attacks. Retrieved March 19, 2024.
* https://www.secureworks.com/blog/wmi-persistence - Dell SecureWorks Counter Threat Unit™ (CTU) Research Team. (2016, March 28). A Novel WMI Persistence Implementation. Retrieved March 30, 2016.
* https://www.secureworks.com/research/the-growing-threat-from-infostealers - SecureWorks Counter Threat Unit Research Team. (2023, May 16). The Growing Threat from Infostealers. Retrieved October 10, 2024.
* https://www.securityweek.com/iranian-hackers-targeted-us-officials-elaborate-social-media-attack-operation - Lennon, M. (2014, May 29). Iranian Hackers Targeted US Officials in Elaborate Social Media Attack Operation. Retrieved March 1, 2017.
* https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/ - Phil Stokes. (2019, December 5). macOS Red Team: Calling Apple APIs Without Building Binaries. Retrieved July 17, 2020.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.sentinelone.com/labs/operation-tainted-love-chinese-apts-target-telcos-in-new-attacks/ - Aleksandar Milenkoski, Juan Andres Guerrero-Saade, and Joey Chen. (2023, March 23). Operation Tainted Love | Chinese APTs Target Telcos in New Attacks. Retrieved March 18, 2025.
* https://www.slideshare.net/slideshow/shmoocon-2019-becs-and-beyond-investigating-and-defending-office-365/128744511 - Bienstock, D.. (2019). BECS and Beyond: Investigating and Defending O365. Retrieved November 17, 2024.
* https://www.splunk.com/en_us/blog/security/enter-the-gates-an-analysis-of-the-darkgate-autoit-loader.html - Splunk Threat Research Team. (2024, January 17). Enter The Gates: An Analysis of the DarkGate AutoIt Loader. Retrieved March 29, 2024.
* https://www.splunk.com/en_us/blog/security/tall-tales-of-hunting-with-tls-ssl-certificates.html - Kovar, R. (2017, December 11). Tall Tales of Hunting with TLS/SSL Certificates. Retrieved October 16, 2020.
* https://www.ssh.com/ssh/tunneling - SSH.COM. (n.d.). SSH tunnel. Retrieved March 15, 2020.
* https://www.stormshield.com/news/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://www.sygnia.co/blog/abyss-locker-ransomware-attack-analysis/ - Abigail See, Zhongyuan (Aaron) Hau, Ren Jie Yow, Yoav Mazor, Omer Kidron, and Oren Biderman. (2025, February 4). The Anatomy of Abyss Locker Ransomware Attack. Retrieved April 4, 2025.
* https://www.sygnia.co/blog/esxi-ransomware-ssh-tunneling-defense-strategies/ - Zhongyuan Hau (Aaron), Ren Jie Yow, and Yoav Mazor. (2025, January 21). ESXi Ransomware Attacks: Stealthy Persistence through. Retrieved March 27, 2025.
* https://www.symantec.com/blogs/threat-intelligence/elfin-apt33-espionage - Security Response attack Investigation Team. (2019, March 27). Elfin: Relentless Espionage Group Targets Multiple Organizations in Saudi Arabia and U.S.. Retrieved April 10, 2019.
* https://www.symantec.com/connect/blogs/malware-update-windows-update - Florio, E. (2007, May 9). Malware Update with Windows Update. Retrieved January 12, 2018.
* https://www.technologyreview.com/2013/08/21/83143/dropbox-and-similar-services-can-sync-malware/ - David Talbot. (2013, August 21). Dropbox and Similar Services Can Sync Malware. Retrieved May 31, 2023.
* https://www.techtarget.com/searchsecurity/tip/Preparing-for-uniform-resource-identifier-URI-exploits - Michael Cobb. (2007, October 11). Preparing for uniform resource identifier (URI) exploits. Retrieved February 9, 2024.
* https://www.thepythoncode.com/article/executing-bash-commands-remotely-in-python - Abdou Rockikz. (2020, July). How to Execute Shell Commands in a Remote Machine in Python. Retrieved July 26, 2021.
* https://www.theregister.com/2015/02/28/uber_subpoenas_github_for_hacker_details/ - McCarthy, K. (2015, February 28). FORK ME! Uber hauls GitHub into court to find who hacked database of 50,000 drivers. Retrieved October 19, 2020.
* https://www.theregister.com/2015/05/19/robotstxt/ - Darren Pauli. (2015, May 19). Robots.txt tells hackers the places you don't want them to look. Retrieved July 18, 2024.
* https://www.theregister.com/2017/09/26/deloitte_leak_github_and_google/ - Thomson, I. (2017, September 26). Deloitte is a sitting duck: Key systems with RDP open, VPN and proxy 'login details leaked'. Retrieved October 19, 2020.
* https://www.trellix.com/blogs/research/beyond-file-search-a-novel-method/ -  Mathanraj Thangaraju, Sijo Jacob. (2023, July 26). Beyond File Search: A Novel Method for Exploiting the "search-ms" URI Protocol Handler. Retrieved March 15, 2024.
* https://www.trellix.com/en-au/blogs/research/ransomhouse-am-see/ - Pham Duy Phuc, Max Kersten, Noël Keijzer, and Michaël Schrijver. (2024, February 14). RansomHouse am See. Retrieved March 26, 2025.
* https://www.trendmicro.com/content/dam/trendmicro/global/en/research/22/a/earth-lusca-employs-sophisticated-infrastructure-varied-tools-and-techniques/technical-brief-delving-deep-an-analysis-of-earth-lusca-operations.pdf - Chen, J., et al. (2022). Delving Deep: An Analysis of Earth Lusca’s Operations. Retrieved July 1, 2022.
* https://www.trendmicro.com/en_us/research.html - Trend Micro. (n.d.). Retrieved February 16, 2024.
* https://www.trendmicro.com/en_us/research/20/f/xorddos-kaiji-botnet-malware-variants-target-exposed-docker-servers.html - Remillano II, A., et al. (2020, June 20). XORDDoS, Kaiji Variants Target Exposed Docker Servers. Retrieved April 5, 2021.
* https://www.trendmicro.com/en_us/research/20/i/tricky-forms-of-phishing.html - Babon, P. (2020, September 3). Tricky 'Forms' of Phishing. Retrieved October 20, 2020.
* https://www.trendmicro.com/en_us/research/20/l/pawn-storm-lack-of-sophistication-as-a-strategy.html - Hacquebord, F., Remorin, L. (2020, December 17). Pawn Storm’s Lack of Sophistication as a Strategy. Retrieved January 13, 2021.
* https://www.trendmicro.com/en_us/research/22/a/analysis-and-Impact-of-lockbit-ransomwares-first-linux-and-vmware-esxi-variant.html - Junestherry Dela Cruz. (2022, January 24). Analysis and Impact of LockBit Ransomware’s First Linux and VMware ESXi Variant. Retrieved March 26, 2025.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing - Metcalf, S. (2018, May 6). Trimarc Research: Detecting Password Spraying with Security Event Auditing. Retrieved January 16, 2019.
* https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/pillowmint-fin7s-monkey-thief/ - Trustwave SpiderLabs. (2020, June 22). Pillowmint: FIN7’s Monkey Thief . Retrieved July 27, 2020.
* https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/ - Franklin Smith. (n.d.). Windows Security Log Events. Retrieved February 21, 2020.
* https://www.us-cert.gov/ncas/alerts/AA18-337A - US-CERT. (2018, December 3). Alert (AA18-337A): SamSam Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.us-cert.gov/ncas/alerts/TA16-091A - US-CERT. (2016, March 31). Alert (TA16-091A): Ransomware and Recent Variants. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-086A - US-CERT. (2018, March 27). TA18-068A Brute Force Attacks Conducted by Cyber Actors. Retrieved October 2, 2019.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.varonis.com/blog/vmware-esxi-in-the-line-of-ransomware-fire - Jason Hill. (2023, February 8). VMware ESXi in the Line of Ransomware Fire. Retrieved March 26, 2025.
* https://www.virustotal.com/en/faq/ - VirusTotal. (n.d.). VirusTotal FAQ. Retrieved May 23, 2019.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2020/11/06/oceanlotus-extending-cyber-espionage-operations-through-fake-websites/ - Adair, S. and Lancaster, T. (2020, November 6). OceanLotus: Extending Cyber Espionage Operations Through Fake Websites. Retrieved November 20, 2020.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.volexity.com/blog/2022/06/15/driftingcloud-zero-day-sophos-firewall-exploitation-and-an-insidious-breach/ - Adair, S., Lancaster, T., Volexity Threat Research. (2022, June 15). DriftingCloud: Zero-Day Sophos Firewall Exploitation and an Insidious Breach. Retrieved July 1, 2022.
* https://www.welivesecurity.com/2018/03/13/oceanlotus-ships-new-backdoor/ - Foltýn, T. (2018, March 13). OceanLotus ships new backdoor using old tricks. Retrieved May 22, 2018.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf - Kafka, F. (2018, January). ESET's Guide to Deobfuscating and Devirtualizing FinFisher. Retrieved August 12, 2019.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.wired.com/story/russia-ukraine-cyberattacks-mandiant/ - Greenberg, A. (2022, November 10). Russia’s New Cyberwarfare in Ukraine Is Fast, Dirty, and Relentless. Retrieved March 22, 2023.
* https://www.youtube.com/watch?v=nJ0UsyiUEqQ - French, D., Filar, B.. (2020, March 21). A Chain Is No Stronger Than Its Weakest LNK. Retrieved November 30, 2020.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.
* https://www.zscaler.com/blogs/security-research/apt-31-leverages-covid-19-vaccine-theme-and-abuses-legitimate-online - Singh, S. and Antil, S. (2020, October 27). APT-31 Leverages COVID-19 Vaccine Theme and Abuses Legitimate Online Services. Retrieved March 24, 2021.
* https://www.zscaler.com/blogs/security-research/fake-sites-stealing-steam-credentials - ZScaler. (2020, February 11). Fake Sites Stealing Steam Credentials. Retrieved March 8, 2023.
* https://x.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved September 12, 2024.
* https://x.com/TheDFIRReport/status/1498657772254240768 - The DFIR Report. (2022, March 1). "Change RDP port" #ContiLeaks. Retrieved September 12, 2024.
* https://x.com/leoloobeek/status/939248813465853953 - Loobeek, L. (2017, December 8). leoloobeek Status. Retrieved September 12, 2024.
* https://x.com/rfackroyd/status/1639136000755765254 - Ackroyd, R. (2023, March 24). Twitter. Retrieved September 12, 2024.

# Validate the following tools

* BITSAdmin - 1
* CrackMapExec - 1
* Empire - 1
* FRP - 1
* Impacket - 1
* Mimikatz - 2
* NBTscan - 1
* Net - 2
* PowerSploit - 1
* PsExec - 2
* Pupy - 1
* Tor - 1
* Windows Credential Editor - 2
* at - 1
* ftp - 1
* netsh - 1
* pwdump - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://www.dtic.mil/dtic/tr/fulltext/u2/a465464.pdf - Roger Dingledine, Nick Mathewson and Paul Syverson. (2004). Tor: The Second-Generation Onion Router. Retrieved December 21, 2017.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/ftp - Microsoft. (2021, July 21). ftp. Retrieved February 25, 2022.
* https://en.wikipedia.org/wiki/Pwdump - Wikipedia. (2007, August 9). pwdump. Retrieved June 22, 2016.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/byt3bl33d3r/CrackMapExec/wiki/SMB-Command-Reference - byt3bl33d3r. (2018, September 8). SMB: Command Reference. Retrieved July 17, 2020.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/fatedier/frp - fatedier. (n.d.). What is frp?. Retrieved July 10, 2024.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://github.com/n1nj4sec/pupy - Nicolas Verdier. (n.d.). Retrieved January 29, 2018.
* https://linux.die.net/man/1/ftp - N/A. (n.d.). ftp(1) - Linux man page. Retrieved February 25, 2022.
* https://man7.org/linux/man-pages/man1/at.1p.html - IEEE/The Open Group. (2017). at(1p) — Linux manual page. Retrieved February 25, 2022.
* https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html - Bezroutchko, A. (2019, November 19). NBTscan man page. Retrieved March 17, 2021.
* https://media.defense.gov/2023/May/24/2003229517/-1/-1/0/CSA_Living_off_the_Land.PDF - NSA et al. (2023, May 24). People's Republic of China State-Sponsored Cyber Actor Living off the Land to Evade Detection. Retrieved July 27, 2023.
* https://msdn.microsoft.com/en-us/library/aa939914 - Microsoft. (2006, October 18). Net.exe Utility. Retrieved September 22, 2015.
* https://msdn.microsoft.com/library/aa362813.aspx - Microsoft. (n.d.). BITSAdmin Tool. Retrieved January 12, 2018.
* https://redcanary.com/blog/blue-mockingbird-cryptominer/ - Lambert, T. (2020, May 7). Introducing Blue Mockingbird. Retrieved May 26, 2020.
* https://sectools.org/tool/nbtscan/ - SecTools. (2003, June 11). NBTscan. Retrieved March 17, 2021.
* https://technet.microsoft.com/en-us/library/bb490866.aspx - Microsoft. (n.d.). At. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb897553.aspx - Russinovich, M. (2014, May 2). Windows Sysinternals PsExec v2.11. Retrieved May 13, 2015.
* https://technet.microsoft.com/library/bb490939.aspx - Microsoft. (n.d.). Using Netsh. Retrieved February 13, 2017.
* https://thedfirreport.com/2021/11/15/exchange-exploit-leads-to-domain-wide-ransomware/ - DFIR Report. (2021, November 15). Exchange Exploit Leads to Domain Wide Ransomware. Retrieved January 5, 2023.
* https://web.archive.org/web/20150511162820/http://windowsitpro.com/windows/netexe-reference - Savill, J. (1999, March 4). Net.exe reference. Retrieved September 22, 2015.
* https://web.archive.org/web/20240904163410/https://www.ampliasecurity.com/research/wcefaq.html - Amplia Security. (n.d.). Windows Credentials Editor (WCE) F.A.Q.. Retrieved September 12, 2024.
* https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html - Hawley et al. (2019, January 29). APT39: An Iranian Cyber Espionage Group Focused on Personal Information. Retrieved February 19, 2019.
* https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://www.sans.org/blog/protecting-privileged-domain-accounts-psexec-deep-dive/ - Pilkington, M. (2012, December 17). Protecting Privileged Domain Accounts: PsExec Deep-Dive. Retrieved August 17, 2016.
* https://www.secureauth.com/labs/open-source-tools/impacket - SecureAuth. (n.d.).  Retrieved January 15, 2019.
* https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments - Symantec DeepSight Adversary Intelligence Team. (2019, June 20). Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments. Retrieved July 8, 2019.

# Validate the following malware

* ASPXSpy - 1
* BADFLICK - 1
* BLACKCOFFEE - 1
* Cadelspy - 1
* CharmPower - 1
* China Chopper - 1
* Cobalt Strike - 1
* Derusbi - 1
* DownPaper - 1
* HOMEFRY - 1
* MURKYTOP - 1
* Mafalda - 1
* MechaFlounder - 1
* NanHaiShu - 1
* Orz - 1
* PowerLess - 1
* Remexi - 1
* Spica - 1
* gh0st RAT - 1
* metaMain - 1

# Review the following malware references

* http://www.clearskysec.com/wp-content/uploads/2017/12/Charming_Kitten_2017.pdf - ClearSky Cyber Security. (2017, December). Charming Kitten. Retrieved December 27, 2017.
* https://assets.sentinelone.com/sentinellabs22/metador#page=1 - Ehrlich, A., et al. (2022, September). THE MYSTERY OF METADOR | AN UNATTRIBUTED THREAT HIDING IN TELCOS, ISPS, AND UNIVERSITIES. Retrieved January 23, 2023.
* https://blog.google/threat-analysis-group/google-tag-coldriver-russian-phishing-malware/ - Shields, W. (2024, January 18). Russian threat group COLDRIVER expands its targeting of Western officials to include the use of malware. Retrieved June 13, 2024.
* https://docs.google.com/document/d/1e9ZTW9b71YwFWS_18ZwDAxa-cYbV8q1wUefmKZLYVsA/edit#heading=h.lmnbtht1ikzm - SentinelLabs. (2022, September 22). Metador Technical Appendix. Retrieved April 4, 2023.
* https://paper.seebug.org/papers/APT/APT_CyberCriminal_Campagin/2016/2016.02.29.Turbo_Campaign_Derusbi/TA_Fidelis_Turbo_1602_0.pdf - Fidelis Cybersecurity. (2016, February 29). The Turbo Campaign, Featuring Derusbi for 64-bit Linux. Retrieved March 2, 2016.
* https://research.checkpoint.com/2022/apt35-exploits-log4j-vulnerability-to-distribute-new-modular-powershell-toolkit/ - Check Point. (2022, January 11). APT35 exploits Log4j vulnerability to distribute new modular PowerShell toolkit. Retrieved January 24, 2022.
* https://research.nccgroup.com/2018/04/17/decoding-network-data-from-a-gh0st-rat-variant/ - Pantazopoulos, N. (2018, April 17). Decoding network data from a Gh0st RAT variant. Retrieved November 2, 2018.
* https://securelist.com/chafer-used-remexi-malware/89538/ - Legezo, D. (2019, January 30). Chafer used Remexi malware to spy on Iran-based foreign diplomatic entities. Retrieved April 17, 2019.
* https://unit42.paloaltonetworks.com/new-python-based-payload-mechaflounder-used-by-chafer/ - Falcone, R. (2019, March 4). New Python-Based Payload MechaFlounder Used by Chafer. Retrieved May 27, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa21-200a - CISA. (2021, July 19). (AA21-200A) Joint Cybersecurity Advisory – Tactics, Techniques, and Procedures of Indicted APT40 Actors Associated with China’s MSS Hainan State Security Department. Retrieved August 12, 2021.
* https://web.archive.org/web/20210825130434/https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://web.archive.org/web/20230115144216/http://www.novetta.com/wp-content/uploads/2014/11/Executive_Summary-Final_1.pdf - Novetta. (n.d.). Operation SMN: Axiom Threat Actor Group Report. Retrieved November 12, 2014.
* https://web.archive.org/web/20240119213200/https://www2.fireeye.com/rs/fireye/images/APT17_Report.pdf - FireEye Labs/FireEye Threat Intelligence. (2015, May 14). Hiding in Plain Sight: FireEye and Microsoft Expose Obfuscation Tactic. Retrieved November 17, 2024.
* https://www.accenture.com/us-en/blogs/cyber-defense/mudcarps-focus-on-submarine-technologies - Accenture iDefense Unit. (2019, March 5). Mudcarp's Focus on Submarine Technologies. Retrieved August 24, 2021.
* https://www.arbornetworks.com/blog/asert/musical-chairs-playing-tetris/ - Sabo, S. (2018, February 15). Musical Chairs Playing Tetris. Retrieved February 19, 2018.
* https://www.cybereason.com/blog/research/powerless-trojan-iranian-apt-phosphorus-adds-new-powershell-backdoor-for-espionage - Cybereason Nocturnus. (2022, February 1). PowerLess Trojan: Iranian APT Phosphorus Adds New PowerShell Backdoor for Espionage. Retrieved June 1, 2022.
* https://www.f-secure.com/documents/996508/1030745/nanhaishu_whitepaper.pdf - F-Secure Labs. (2016, July). NANHAISHU RATing the South China Sea. Retrieved July 6, 2018.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2015/07/demonstrating_hustle.html - FireEye Threat Intelligence. (2015, July 13). Demonstrating Hustle, Chinese APT Groups Quickly Use Zero-Day Vulnerability (CVE-2015-5119) Following Hacking Team Leak. Retrieved January 25, 2016.
* https://www.fireeye.com/blog/threat-research/2018/03/suspected-chinese-espionage-group-targeting-maritime-and-engineering-industries.html - FireEye. (2018, March 16). Suspected Chinese Cyber Espionage Group (TEMP.Periscope) Targeting U.S. Engineering and Maritime Industries. Retrieved April 11, 2018.
* https://www.proofpoint.com/us/threat-insight/post/leviathan-espionage-actor-spearphishes-maritime-and-defense-targets - Axel F, Pierre T. (2017, October 16). Leviathan: Espionage actor spearphishes maritime and defense targets. Retrieved February 15, 2018.
* https://www.rapid7.com/blog/post/2021/03/23/defending-against-the-zero-day-analyzing-attacker-behavior-post-exploitation-of-microsoft-exchange/ - Eoin Miller. (2021, March 23). Defending Against the Zero Day: Analyzing Attacker Behavior Post-Exploitation of Microsoft Exchange. Retrieved October 27, 2022.
* https://www.secureworks.com/research/threat-group-3390-targets-organizations-for-cyberespionage - Dell SecureWorks Counter Threat Unit Threat Intelligence. (2015, August 5). Threat Group-3390 Targets Organizations for Cyberespionage. Retrieved August 18, 2018.
* https://www.symantec.com/connect/blogs/iran-based-attackers-use-back-door-threats-spy-middle-eastern-targets - Symantec Security Response. (2015, December 7). Iran-based attackers use back door threats to spy on Middle Eastern targets. Retrieved April 17, 2019.
* https://www.threatconnect.com/the-anthem-hack-all-roads-lead-to-china/ - ThreatConnect Research Team. (2015, February 27). The Anthem Hack: All Roads Lead to China. Retrieved January 26, 2016.

