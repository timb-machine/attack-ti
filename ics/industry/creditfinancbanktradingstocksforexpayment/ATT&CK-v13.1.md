threat-crank.py 0.2.1
I: searching for industries that match .* credit.*|.* financ.*|.* bank.*|.* trading.*|.* stocks.*|.* forex.*|.* payment.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v13.1/ics-attack/ics-attack.json
# Threat groups

* APT38
* FIN6
* FIN7
* GOLD SOUTHFIELD
* OilRig
* Wizard Spider

# Validate the following attacks

* Drive-by Compromise - 1
* Scripting - 1
* Spearphishing Attachment - 1
* Standard Application Layer Protocol - 1
* Valid Accounts - 1

# Validate the following phases

* command-and-control - 1
* execution - 1
* initial-access - 2
* lateral-movement - 1
* persistence - 1

# Validate the following platforms

* Control Server - 3
* Data Historian - 3
* Engineering Workstation - 4
* Field Controller/RTU/PLC/IED - 1
* Human-Machine Interface - 3
* Input/Output Server - 1
* Linux - 1
* None - 1
* Safety Instrumented System/Protection Relay - 1
* Windows - 6

# Validate the following defences


# Validate the following data sources

* Application Log: Application Log Content - 2
* Command: Command Execution - 1
* File: File Creation - 2
* Logon Session: Logon Session Creation - 1
* Logon Session: Logon Session Metadata - 1
* Module: Module Load - 1
* Network Traffic: Network Connection Creation - 1
* Network Traffic: Network Traffic Content - 3
* Network Traffic: Network Traffic Flow - 1
* Process: Process Creation - 3
* Process: Process Metadata - 1
* Script: Script Execution - 1
* User Account: User Account Authentication - 1

# Review the following attack references

* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK 2019, October 25 Spearphishing Attachment Retrieved. 2019/10/25 
* https://us-cert.cisa.gov/ncas/alerts/TA18-074A - Cybersecurity & Infrastructure Security Agency 2018, March 15 Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors Retrieved. 2019/10/11 
* https://us-cert.cisa.gov/sites/default/files/publications/AA21-201A_Chinese_Gas_Pipeline_Intrusion_Campaign_2011_to_2013%20(1).pdf - Department of Justice (DOJ), DHS Cybersecurity & Infrastructure Security Agency (CISA) 2021, July 20 Chinese Gas Pipeline Intrusion Campaign, 2011 to 2013 Retrieved. 2021/10/08 
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton   When The Lights Went Out Retrieved. 2019/10/22 

# Validate the following tools


# Review the following tool references


# Validate the following malware

* KillDisk - 1
* LockerGoga - 1
* REvil - 2
* Ryuk - 2

# Review the following malware references

* http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/ - Cherepanov, A.. (2016, January 3). BlackEnergy by the SSHBearDoor: attacks against Ukrainian news media and electric industry. Retrieved May 18, 2016.
* https://blog.talosintelligence.com/2019/04/sodinokibi-ransomware-exploits-weblogic.html - Cadieux, P, et al (2019, April 30). Sodinokibi ransomware exploits WebLogic Server vulnerability. Retrieved August 4, 2020.
* https://intel471.com/blog/revil-ransomware-as-a-service-an-analysis-of-a-ransomware-affiliate-operation/ - Intel 471 Malware Intelligence team. (2020, March 31). REvil Ransomware-as-a-Service – An analysis of a ransomware affiliate operation. Retrieved August 4, 2020.
* https://securelist.com/sodin-ransomware/91473/ - Mamedov, O, et al. (2019, July 3). Sodin ransomware exploits Windows vulnerability and processor architecture. Retrieved August 4, 2020.
* https://threatvector.cylance.com/en_us/home/threat-spotlight-sodinokibi-ransomware.html - Cylance. (2019, July 3). hreat Spotlight: Sodinokibi Ransomware. Retrieved August 4, 2020.
* https://unit42.paloaltonetworks.com/born-this-way-origins-of-lockergoga/ - Harbison, M. (2019, March 26). Born This Way? Origins of LockerGoga. Retrieved April 16, 2019.
* https://www.bleepingcomputer.com/news/security/killdisk-disk-wiping-malware-adds-ransomware-component/ - Catalin Cimpanu. (2016, December 29). KillDisk Disk-Wiping Malware Adds Ransomware Component. Retrieved January 12, 2021.
* https://www.bleepingcomputer.com/news/security/ryuk-ransomware-uses-wake-on-lan-to-encrypt-offline-devices/ - Abrams, L. (2021, January 14). Ryuk Ransomware Uses Wake-on-Lan To Encrypt Offline Devices. Retrieved February 11, 2021.
* https://www.carbonblack.com/2019/03/22/tau-threat-intelligence-notification-lockergoga-ransomware/ - CarbonBlack Threat Analysis Unit. (2019, March 22). TAU Threat Intelligence Notification – LockerGoga Ransomware. Retrieved April 16, 2019.
* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ - Hanel, A. (2019, January 10). Big Game Hunting with Ryuk: Another Lucrative Targeted Ransomware. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html - Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html - McKeague, B. et al. (2019, April 5). Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware. Retrieved April 17, 2019.
* https://www.gdatasoftware.com/blog/2019/06/31724-strange-bits-sodinokibi-spam-cinarat-and-fake-g-data - Han, Karsten. (2019, June 4). Strange Bits: Sodinokibi Spam, CinaRAT, and Fake G DATA. Retrieved August 4, 2020.
* https://www.group-ib.com/whitepapers/ransomware-uncovered.html - Group IB. (2020, May). Ransomware Uncovered: Attackers’ Latest Methods. Retrieved August 5, 2020.
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-crescendo/ - Saavedra-Morales, J, et al. (2019, October 20). McAfee ATR Analyzes Sodinokibi aka REvil Ransomware-as-a-Service – Crescendo. Retrieved August 5, 2020.
* https://www.mcafee.com/blogs/other-blogs/mcafee-labs/mcafee-atr-analyzes-sodinokibi-aka-revil-ransomware-as-a-service-what-the-code-tells-us/ - McAfee. (2019, October 2). McAfee ATR Analyzes Sodinokibi aka REvil Ransomware-as-a-Service – What The Code Tells Us. Retrieved August 4, 2020.
* https://www.picussecurity.com/blog/a-brief-history-and-further-technical-analysis-of-sodinokibi-ransomware - Ozarslan, S. (2020, January 15). A Brief History of Sodinokibi. Retrieved August 5, 2020.
* https://www.secureworks.com/blog/revil-the-gandcrab-connection - Secureworks . (2019, September 24). REvil: The GandCrab Connection. Retrieved August 4, 2020.
* https://www.secureworks.com/research/revil-sodinokibi-ransomware - Counter Threat Unit Research Team. (2019, September 24). REvil/Sodinokibi Ransomware. Retrieved August 4, 2020.
* https://www.tetradefense.com/incident-response-services/cause-and-effect-sodinokibi-ransomware-analysis - Tetra Defense. (2020, March). CAUSE AND EFFECT: SODINOKIBI RANSOMWARE ANALYSIS. Retrieved December 14, 2020.
* https://www.trendmicro.com/en_us/research/18/a/new-killdisk-variant-hits-financial-organizations-in-latin-america.html - Gilbert Sison, Rheniel Ramos, Jay Yaneza, Alfredo Oliveira. (2018, January 15). KillDisk Variant Hits Latin American Financial Groups. Retrieved January 12, 2021.
* https://www.trendmicro.com/en_us/research/18/f/new-killdisk-variant-hits-latin-american-financial-organizations-again.html - Fernando Merces, Byron Gelera, Martin Co. (2018, June 7). KillDisk Variant Hits Latin American Finance Industry. Retrieved January 12, 2021.

