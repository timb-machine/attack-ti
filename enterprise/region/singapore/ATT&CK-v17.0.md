threat-crank.py 0.2.1
I: searching for regions that match .* singapore.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v17.0/enterprise-attack/enterprise-attack.json
# Threat groups

* Aoqin Dragon
* Whitefly

# Validate the following attacks

* Command and Scripting Interpreter - 1
* DLL - 1
* Encrypted/Encoded File - 1
* Exploitation for Client Execution - 1
* Exploitation for Privilege Escalation - 1
* File and Directory Discovery - 1
* Ingress Tool Transfer - 1
* LSASS Memory - 1
* Lateral Tool Transfer - 1
* Malicious File - 2
* Malware - 1
* Masquerading - 1
* Match Legitimate Resource Name or Location - 1
* Replication Through Removable Media - 1
* Software Packing - 1
* Tool - 2

# Validate the following phases

* command-and-control - 1
* credential-access - 1
* defense-evasion - 5
* discovery - 1
* execution - 4
* initial-access - 1
* lateral-movement - 2
* persistence - 1
* privilege-escalation - 2
* resource-development - 3

# Validate the following platforms

* Containers - 3
* ESXi - 6
* IaaS - 1
* Identity Provider - 1
* Linux - 12
* Network Devices - 3
* Office Suite - 1
* PRE - 3
* Windows - 18
* macOS - 12

# Validate the following defences


# Validate the following data sources

* Application Log: Application Log Content - 1
* Command: Command Execution - 6
* Drive: Drive Creation - 1
* Driver: Driver Load - 1
* File: File Access - 1
* File: File Creation - 8
* File: File Metadata - 5
* File: File Modification - 3
* Image: Image Metadata - 2
* Logon Session: Logon Session Creation - 1
* Malware Repository: Malware Content - 1
* Malware Repository: Malware Metadata - 3
* Module: Module Load - 2
* Named Pipe: Named Pipe Metadata - 1
* Network Share: Network Share Access - 1
* Network Traffic: Network Connection Creation - 1
* Network Traffic: Network Traffic Content - 2
* Network Traffic: Network Traffic Flow - 3
* Process: OS API Execution - 3
* Process: Process Access - 1
* Process: Process Creation - 12
* Process: Process Metadata - 3
* Scheduled Job: Scheduled Job Metadata - 1
* Scheduled Job: Scheduled Job Modification - 1
* Script: Script Execution - 1
* Service: Service Creation - 1
* Service: Service Metadata - 1
* User Account: User Account Creation - 1
* Windows Registry: Windows Registry Key Modification - 1

# Review the following attack references

* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* https://arstechnica.com/information-technology/2014/06/active-malware-operation-let-attackers-sabotage-us-energy-industry/ - Dan Goodin. (2014, June 30). Active malware operation let attackers sabotage US energy industry. Retrieved March 9, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blogs.jpcert.or.jp/en/2016/01/windows-commands-abused-by-attackers.html - Tomonaga, S. (2016, January 26). Windows Commands Abused by Attackers. Retrieved February 2, 2016.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.226.3427&rep=rep1&type=pdf - Zhaohui Wang & Angelos Stavrou. (n.d.). Exploiting Smart-Phone USB Connectivity For Fun And Profit. Retrieved May 25, 2022.
* https://cloud.google.com/blog/topics/threat-intelligence/cosmicenergy-ot-malware-russian-response/ - COSMICENERGY: New OT Malware Possibly Related To Russian Emergency Response Exercises. (2023, May 25). Ken Proska, Daniel Kapellmann Zafra, Keith Lunden, Corey Hildebrandt, Rushikesh Nandedkar, Nathan Brubaker. Retrieved March 18, 2025.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands?view=powershell-7.1 - Microsoft. (2020, August 21). Running Remote Commands. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/microsoft-recommended-driver-block-rules - Microsoft. (2020, October 15). Microsoft recommended driver block rules. Retrieved March 16, 2021.
* https://github.com/dhondta/awesome-executable-packing - Alexandre D'Hondt. (n.d.). Awesome Executable Packing. Retrieved March 11, 2022.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://learn.microsoft.com/en-us/security-updates/securityadvisories/2010/2269637 - Microsoft. (2014, May 13). Microsoft Security Advisory 2269637: Insecure Library Loading Could Allow Remote Code Execution. Retrieved January 30, 2025.
* https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection?redirectedfrom=MSDN - Microsoft. (2023, October 12). Dynamic-link library redirection. Retrieved January 30, 2025.
* https://learn.microsoft.com/en-us/windows/win32/sbscs/manifests?redirectedfrom=MSDN - Microsoft. (2021, January 7). Manifests. Retrieved January 30, 2025.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://owasp.org/www-community/attacks/Binary_planting - OWASP. (n.d.). Binary Planting. Retrieved January 30, 2025.
* https://securelist.com/sofacy-apt-hits-high-profile-targets-with-updated-toolset/72924/ - Kaspersky Lab's Global Research and Analysis Team. (2015, December 4). Sofacy APT hits high profile targets with updated toolset. Retrieved December 10, 2015.
* https://services.google.com/fh/files/misc/rpt-apt29-hammertoss-stealthy-tactics-define-en.pdf - FireEye Labs. (2015, July). HAMMERTOSS: Stealthy Tactics Define a Russian Cyber Threat Group. Retrieved November 17, 2024.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://techcrunch.com/2019/08/12/iphone-charging-cable-hack-computer-def-con/ - Zack Whittaker. (2019, August 12). This hacker’s iPhone charging cable can hijack your computer. Retrieved May 25, 2022.
* https://therecord.media/fbi-fin7-hackers-target-us-companies-with-badusb-devices-to-install-ransomware/ - The Record. (2022, January 7). FBI: FIN7 hackers target US companies with BadUSB devices to install ransomware. Retrieved January 14, 2022.
* https://tools.cisco.com/security/center/resources/integrity_assurance.html#23 - Cisco. (n.d.). Cisco IOS Software Integrity Assurance - Command History. Retrieved October 21, 2020.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://unit42.paloaltonetworks.com/dll-hijacking-techniques/ - Tom Fakterman, Chen Erlich, & Assaf Dahan. (2024, February 22). Intruders in the Library: Exploring DLL Hijacking. Retrieved January 30, 2025.
* https://www.aquasec.com/blog/leveraging-kubernetes-rbac-to-backdoor-clusters/ - Michael Katchinskiy and Assaf Morag. (2023, April 21). First-Ever Attack Leveraging Kubernetes RBAC to Backdoor Clusters. Retrieved March 24, 2025.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.computerworld.com/article/2486903/windows-malware-tries-to-infect-android-devices-connected-to-pcs.html - Lucian Constantin. (2014, January 23). Windows malware tries to infect Android devices connected to PCs. Retrieved May 25, 2022.
* https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/ - Jai Minton. (2023, March 31). How Falcon OverWatch Investigates Malicious Self-Extracting Archives, Decoy Files and Their Hidden Payloads. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/shlayer-malvertising-campaigns-still-using-flash-update-disguise/ - Aspen Lindblom, Joseph Goodwin, and Chris Sheldon. (2021, July 19). Shlayer Malvertising Campaigns Still Using Flash Update Disguise. Retrieved March 29, 2024.
* https://www.crowdstrike.com/en-us/blog/4-ways-adversaries-hijack-dlls/ -  falcon.overwatch.team. (2022, December 30). 4 Ways Adversaries Hijack DLLs — and How CrowdStrike Falcon OverWatch Fights Back. Retrieved January 30, 2025.
* https://www.deepinstinct.com/blog/lsass-memory-dumps-are-stealthier-than-ever-before-part-2 - Gilboa, A. (2021, February 16). LSASS Memory Dumps are Stealthier than Ever Before - Part 2. Retrieved December 27, 2023.
* https://www.elastic.co/blog/how-hunt-masquerade-ball - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.hexacorn.com/blog/2013/12/08/beyond-good-ol-run-key-part-5/ - Hexacorn. (2013, December 8). Beyond good ol’ Run key, Part 5. Retrieved August 14, 2024.
* https://www.kroll.com/en/insights/publications/cyber/idatloader-distribution - Dave Truman. (2024, June 24). Novel Technique Combination Used In IDATLOADER Distribution. Retrieved January 30, 2025.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.recordedfuture.com/blog/identifying-cobalt-strike-servers - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved September 16, 2024.
* https://www.technologyreview.com/2013/08/21/83143/dropbox-and-similar-services-can-sync-malware/ - David Talbot. (2013, August 21). Dropbox and Similar Services Can Sync Malware. Retrieved May 31, 2023.
* https://www.thepythoncode.com/article/executing-bash-commands-remotely-in-python - Abdou Rockikz. (2020, July). How to Execute Shell Commands in a Remote Machine in Python. Retrieved July 26, 2021.
* https://www.trellix.com/blogs/research/beyond-file-search-a-novel-method/ -  Mathanraj Thangaraju, Sijo Jacob. (2023, July 26). Beyond File Search: A Novel Method for Exploiting the "search-ms" URI Protocol Handler. Retrieved March 15, 2024.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.welivesecurity.com/wp-content/uploads/2018/01/WP-FinFisher.pdf - Kafka, F. (2018, January). ESET's Guide to Deobfuscating and Devirtualizing FinFisher. Retrieved August 12, 2019.
* https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf - Hromcova, Z. and Cherpanov, A. (2020, June). INVISIMOLE: THE HIDDEN PART OF THE STORY. Retrieved July 16, 2020.
* https://www.wietzebeukema.nl/blog/hijacking-dlls-in-windows - Wietze Beukema. (2020, June 22). Hijacking DLLs in Windows. Retrieved April 8, 2025.
* https://x.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved September 12, 2024.

# Validate the following tools

* Mimikatz - 1

# Review the following tool references

* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.

# Validate the following malware

* Heyoka Backdoor - 1
* Mongall - 1

# Review the following malware references

* https://heyoka.sourceforge.net/ - Sourceforge. (n.d.). Heyoka POC Exfiltration Tool. Retrieved October 11, 2022.
* https://www.sentinelone.com/labs/aoqin-dragon-newly-discovered-chinese-linked-apt-has-been-quietly-spying-on-organizations-for-10-years/ - Chen, Joey. (2022, June 9). Aoqin Dragon | Newly-Discovered Chinese-linked APT Has Been Quietly Spying On Organizations For 10 Years. Retrieved July 14, 2022.

