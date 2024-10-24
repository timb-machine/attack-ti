threat-crank.py 0.2.1
I: searching for regions that match .* russia.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v13.0/ics-attack/ics-attack.json
# Threat groups

* ALLANITE
* Dragonfly
* Sandworm Team
* TEMP.Veles
* Wizard Spider

# Validate the following attacks

* Block Command Message - 1
* Block Reporting Message - 1
* Command-Line Interface - 1
* Connection Proxy - 1
* Device Restart/Shutdown - 1
* Drive-by Compromise - 3
* Exploit Public-Facing Application - 1
* External Remote Services - 1
* Graphical User Interface - 1
* Remote Services - 1
* Screen Capture - 1
* Spearphishing Attachment - 2
* Supply Chain Compromise - 2
* System Firmware - 1
* Unauthorized Command Message - 1
* Valid Accounts - 3

# Validate the following phases

* collection - 1
* command-and-control - 1
* execution - 2
* impair-process-control - 1
* inhibit-response-function - 4
* initial-access - 10
* lateral-movement - 4
* persistence - 4

# Validate the following platforms

* Control Server - 10
* Data Historian - 8
* Device Configuration/Parameters - 2
* Engineering Workstation - 7
* Field Controller/RTU/PLC/IED - 12
* Human-Machine Interface - 12
* Input/Output Server - 9
* Linux - 1
* None - 4
* Safety Instrumented System/Protection Relay - 6
* Windows - 7

# Validate the following defences


# Validate the following data sources

* Application Log: Application Log Content - 13
* Command: Command Execution - 4
* File: File Creation - 5
* File: File Metadata - 2
* Firmware: Firmware Modification - 1
* Logon Session: Logon Session Creation - 5
* Logon Session: Logon Session Metadata - 4
* Module: Module Load - 2
* Network Share: Network Share Access - 1
* Network Traffic: Network Connection Creation - 4
* Network Traffic: Network Traffic Content - 10
* Network Traffic: Network Traffic Flow - 7
* Operational Databases: Device Alarm - 2
* Operational Databases: Process History/Live Data - 3
* Operational Databases: Process/Event Alarm - 3
* Process: OS API Execution - 1
* Process: Process Creation - 8
* Process: Process Termination - 2
* User Account: User Account Authentication - 3

# Review the following attack references

* http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6142258 - Bonnie Zhu, Anthony Joseph, Shankar Sastry 2011 A Taxonomy of Cyber Attacks on SCADA Systems Retrieved. 2018/01/12 
* http://www.sciencedirect.com/science/article/pii/S1874548213000231 - Basnight, Zachry, et al. 2013 Retrieved. 2017/10/17 
* https://assets.contentstack.io/v3/assets/blt36c2e63521272fdc/blt6a77276749b76a40/607f235992f0063e5c070fff/E-ISAC_SANS_Ukraine_DUC_5%5b73%5d.pdf - Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems 2016, March 18 Analysis of the Cyber Attack on the Ukranian Power Grid: Defense Use Case Retrieved. 2018/03/27 
* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK 2019, October 25 Spearphishing Attachment Retrieved. 2019/10/25 
* https://attack.mitre.org/wiki/Technique/T1059 - Enterprise ATT&CK 2018, January 11 Command-Line Interface Retrieved. 2018/05/17 
* https://attack.mitre.org/wiki/Technique/T1090 - Enterprise ATT&CK 2018, January 11 Connection Proxy Retrieved. 2018/05/17 
* https://attack.mitre.org/wiki/Technique/T1133 - Daniel Oakley, Travis Smith, Tripwire   Retrieved. 2018/05/30 
* https://dragos.com/blog/industry-news/implications-of-it-ransomware-for-ics-environments/ - Joe Slowik 2019, April 10 Implications of IT Ransomware for ICS Environments Retrieved. 2019/10/27 
* https://dragos.com/blog/trisis/TRISIS-01.pdf - Dragos 2017, December 13 TRISIS Malware Analysis of Safety System Targeted Malware Retrieved. 2018/01/12 
* https://statescoop.com/tornado-sirens-in-dallas-suburbs-deactivated-after-being-hacked-and-set-off/ - Benjamin Freed 2019, March 13 Tornado sirens in Dallas suburbs deactivated after being hacked and set off Retrieved. 2020/11/06 
* https://us-cert.cisa.gov/ncas/alerts/TA18-074A - Cybersecurity & Infrastructure Security Agency 2018, March 15 Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors Retrieved. 2019/10/11 
* https://us-cert.cisa.gov/sites/default/files/publications/AA21-201A_Chinese_Gas_Pipeline_Intrusion_Campaign_2011_to_2013%20(1).pdf - Department of Justice (DOJ), DHS Cybersecurity & Infrastructure Security Agency (CISA) 2021, July 20 Chinese Gas Pipeline Intrusion Campaign, 2011 to 2013 Retrieved. 2021/10/08 
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton   When The Lights Went Out Retrieved. 2019/10/22 
* https://www.controlglobal.com/industrynews/2019/yokogawa-announcement-warns-of-counterfeit-transmitters/ - Control Global 2019, May 29 Yokogawa announcement warns of counterfeit transmitters Retrieved. 2021/04/09 
* https://www.f-secure.com/weblog/archives/00002718.html - Daavid Hentunen, Antti Tikkanen 2014, June 23 Havex Hunts For ICS/SCADA Systems Retrieved. 2019/04/01 
* https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html - Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer 2017, December 14 Attackers Deploy New ICS Attack Framework TRITON and Cause Operational Disruption to Critical Infrastructure Retrieved. 2018/01/12 
* https://www.us-cert.gov/ncas/alerts/TA17-293A - ICS-CERT 2017, October 21 Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors Retrieved. 2017/10/23 
* https://www.zdnet.com/article/experts-think-they-know-how-dallas-emergency-sirens-were-hacked/ - Zack Whittaker 2017, April 12 Dallas' emergency sirens were hacked with a rogue radio signal Retrieved. 2020/11/06 

# Validate the following tools


# Review the following tool references


# Validate the following malware

* Backdoor.Oldrea - 1
* Bad Rabbit - 1
* BlackEnergy - 1
* Industroyer - 1
* Industroyer2 - 1
* KillDisk - 1
* NotPetya - 1
* Ryuk - 1

# Review the following malware references

* http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/ - Cherepanov, A.. (2016, January 3). BlackEnergy by the SSHBearDoor: attacks against Ukrainian news media and electric industry. Retrieved May 18, 2016.
* https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html - Chiu, A. (2016, June 27). New Ransomware Variant "Nyetya" Compromises Systems Worldwide. Retrieved March 26, 2019.
* https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=7382dce7-0260-4782-84cc-890971ed3f17&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments - Symantec Security Response. (2014, June 30). Dragonfly: Cyberespionage Attacks Against Energy Suppliers. Retrieved April 8, 2016.
* https://docs.broadcom.com/doc/dragonfly_threat_against_western_energy_suppliers - Symantec Security Response. (2014, July 7). Dragonfly: Western energy sector targeted by sophisticated attack group. Retrieved September 9, 2017.
* https://dragos.com/blog/crashoverride/CrashOverride-01.pdf - Dragos Inc.. (2017, June 13). CRASHOVERRIDE Analysis of the Threat to Electric Grid Operations. Retrieved December 18, 2020.
* https://securelist.com/bad-rabbit-ransomware/82851/ - Mamedov, O. Sinitsyn, F.  Ivanov, A.. (2017, October 24). Bad Rabbit ransomware. Retrieved January 28, 2021.
* https://vblocalhost.com/uploads/VB2021-Slowik.pdf - Slowik, J. (2021, October). THE BAFFLING BERSERK BEAR: A DECADE’S ACTIVITY TARGETING CRITICAL INFRASTRUCTURE. Retrieved December 6, 2021.
* https://www.bleepingcomputer.com/news/security/killdisk-disk-wiping-malware-adds-ransomware-component/ - Catalin Cimpanu. (2016, December 29). KillDisk Disk-Wiping Malware Adds Ransomware Component. Retrieved January 12, 2021.
* https://www.bleepingcomputer.com/news/security/ryuk-ransomware-uses-wake-on-lan-to-encrypt-offline-devices/ - Abrams, L. (2021, January 14). Ryuk Ransomware Uses Wake-on-Lan To Encrypt Offline Devices. Retrieved February 11, 2021.
* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ - Hanel, A. (2019, January 10). Big Game Hunting with Ryuk: Another Lucrative Targeted Ransomware. Retrieved May 12, 2020.
* https://www.dragos.com/blog/industry-news/implications-of-it-ransomware-for-ics-environments/ - Slowik, J.. (2019, April 10). Implications of IT Ransomware for ICS Environments. Retrieved January 28, 2021.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.
* https://www.fireeye.com/blog/threat-research/2019/01/a-nasty-trick-from-credential-theft-malware-to-business-disruption.html - Goody, K., et al (2019, January 11). A Nasty Trick: From Credential Theft Malware to Business Disruption. Retrieved May 12, 2020.
* https://www.fireeye.com/blog/threat-research/2019/04/pick-six-intercepting-a-fin6-intrusion.html - McKeague, B. et al. (2019, April 5). Pick-Six: Intercepting a FIN6 Intrusion, an Actor Recently Tied to Ryuk and LockerGoga Ransomware. Retrieved April 17, 2019.
* https://www.justice.gov/opa/press-release/file/1328521/download - Scott W. Brady. (2020, October 15). United States vs. Yuriy Sergeyevich Andrienko et al.. Retrieved November 25, 2020.
* https://www.trendmicro.com/en_us/research/18/a/new-killdisk-variant-hits-financial-organizations-in-latin-america.html - Gilbert Sison, Rheniel Ramos, Jay Yaneza, Alfredo Oliveira. (2018, January 15). KillDisk Variant Hits Latin American Financial Groups. Retrieved January 12, 2021.
* https://www.trendmicro.com/en_us/research/18/f/new-killdisk-variant-hits-latin-american-financial-organizations-again.html - Fernando Merces, Byron Gelera, Martin Co. (2018, June 7). KillDisk Variant Hits Latin American Finance Industry. Retrieved January 12, 2021.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/ - Cherepanov, A.. (2017, June 30). TeleBots are back: Supply chain attacks against Ukraine. Retrieved June 11, 2020.
* https://www.welivesecurity.com/2017/10/24/bad-rabbit-not-petya-back/ - M.Léveille, M-E.. (2017, October 24). Bad Rabbit: Not‑Petya is back with improved ransomware. Retrieved January 28, 2021.
* https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf - Anton Cherepanov. (2017, June 12). Win32/Industroyer: A new threat for industrial controls systems. Retrieved December 18, 2020.
* https://www.youtube.com/watch?v=xC9iM5wVedQ - Anton Cherepanov, Robert Lipovsky. (2022, August). Industroyer2: Sandworm's Cyberwarfare Targets Ukraine's Power Grid. Retrieved April 6, 2023.

