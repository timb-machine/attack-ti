threat-crank.py 0.2.1
I: searching for industries that match .* military.*|.* defen[cs]e.*|.* armed.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v16.1/ics-attack/ics-attack.json
# Threat groups

* Dragonfly
* Sandworm Team

# Validate the following attacks

* Command-Line Interface - 1
* Connection Proxy - 1
* Drive-by Compromise - 1
* Exploit Public-Facing Application - 1
* Supply Chain Compromise - 1

# Validate the following phases

* command-and-control - 1
* execution - 1
* initial-access - 3

# Validate the following platforms

* Engineering Workstation - 1
* Field Controller/RTU/PLC/IED - 1
* Linux - 2
* Network - 1
* None - 5
* Windows - 6

# Validate the following defences


# Validate the following data sources

* Application Log: Application Log Content - 3
* Command: Command Execution - 1
* File: File Creation - 1
* File: File Metadata - 1
* Network Traffic: Network Connection Creation - 1
* Network Traffic: Network Traffic Content - 3
* Network Traffic: Network Traffic Flow - 1
* Process: Process Creation - 2

# Review the following attack references

* https://attack.mitre.org/wiki/Technique/T1059 - Enterprise ATT&CK 2018, January 11 Command-Line Interface Retrieved. 2018/05/17 
* https://attack.mitre.org/wiki/Technique/T1090 - Enterprise ATT&CK 2018, January 11 Connection Proxy Retrieved. 2018/05/17 
* https://us-cert.cisa.gov/ncas/alerts/TA18-074A - Cybersecurity & Infrastructure Security Agency 2018, March 15 Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors Retrieved. 2019/10/11 
* https://www.controlglobal.com/industrynews/2019/yokogawa-announcement-warns-of-counterfeit-transmitters/ - Control Global 2019, May 29 Yokogawa announcement warns of counterfeit transmitters Retrieved. 2021/04/09 
* https://www.f-secure.com/weblog/archives/00002718.html - Daavid Hentunen, Antti Tikkanen 2014, June 23 Havex Hunts For ICS/SCADA Systems Retrieved. 2019/04/01 

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
* VPNFilter - 1

# Review the following malware references

* http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/ - Cherepanov, A.. (2016, January 3). BlackEnergy by the SSHBearDoor: attacks against Ukrainian news media and electric industry. Retrieved May 18, 2016.
* https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html - Chiu, A. (2016, June 27). New Ransomware Variant "Nyetya" Compromises Systems Worldwide. Retrieved March 26, 2019.
* https://blog.talosintelligence.com/2018/06/vpnfilter-update.html - William Largent 2018, June 06 VPNFilter Update - VPNFilter exploits endpoints, targets new devices Retrieved. 2019/03/28 
* https://community.broadcom.com/symantecenterprise/communities/community-home/librarydocuments/viewdocument?DocumentKey=7382dce7-0260-4782-84cc-890971ed3f17&CommunityKey=1ecf5f55-9545-44d6-b0f4-4e4a7f5f5e68&tab=librarydocuments - Symantec Security Response. (2014, June 30). Dragonfly: Cyberespionage Attacks Against Energy Suppliers. Retrieved April 8, 2016.
* https://docs.broadcom.com/doc/dragonfly_threat_against_western_energy_suppliers - Symantec Security Response. (2014, July 7). Dragonfly: Western energy sector targeted by sophisticated attack group. Retrieved September 9, 2017.
* https://dragos.com/blog/crashoverride/CrashOverride-01.pdf - Dragos Inc.. (2017, June 13). CRASHOVERRIDE Analysis of the Threat to Electric Grid Operations. Retrieved December 18, 2020.
* https://securelist.com/bad-rabbit-ransomware/82851/ - Mamedov, O. Sinitsyn, F.  Ivanov, A.. (2017, October 24). Bad Rabbit ransomware. Retrieved January 28, 2021.
* https://vblocalhost.com/uploads/VB2021-Slowik.pdf - Slowik, J. (2021, October). THE BAFFLING BERSERK BEAR: A DECADE’S ACTIVITY TARGETING CRITICAL INFRASTRUCTURE. Retrieved December 6, 2021.
* https://www.bleepingcomputer.com/news/security/killdisk-disk-wiping-malware-adds-ransomware-component/ - Catalin Cimpanu. (2016, December 29). KillDisk Disk-Wiping Malware Adds Ransomware Component. Retrieved January 12, 2021.
* https://www.dragos.com/blog/industry-news/implications-of-it-ransomware-for-ics-environments/ - Slowik, J.. (2019, April 10). Implications of IT Ransomware for ICS Environments. Retrieved January 28, 2021.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.
* https://www.justice.gov/opa/press-release/file/1328521/download - Scott W. Brady. (2020, October 15). United States vs. Yuriy Sergeyevich Andrienko et al.. Retrieved November 25, 2020.
* https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter - NCSC, CISA, FBI, NSA. (2022, February 23). New Sandworm malware Cyclops Blink replaces VPNFilter. Retrieved March 3, 2022.
* https://www.trendmicro.com/en_us/research/18/a/new-killdisk-variant-hits-financial-organizations-in-latin-america.html - Gilbert Sison, Rheniel Ramos, Jay Yaneza, Alfredo Oliveira. (2018, January 15). KillDisk Variant Hits Latin American Financial Groups. Retrieved January 12, 2021.
* https://www.trendmicro.com/en_us/research/18/f/new-killdisk-variant-hits-latin-american-financial-organizations-again.html - Fernando Merces, Byron Gelera, Martin Co. (2018, June 7). KillDisk Variant Hits Latin American Finance Industry. Retrieved January 12, 2021.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/ - Cherepanov, A.. (2017, June 30). TeleBots are back: Supply chain attacks against Ukraine. Retrieved June 11, 2020.
* https://www.welivesecurity.com/2017/10/24/bad-rabbit-not-petya-back/ - M.Léveille, M-E.. (2017, October 24). Bad Rabbit: Not‑Petya is back with improved ransomware. Retrieved January 28, 2021.
* https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf - Anton Cherepanov. (2017, June 12). Win32/Industroyer: A new threat for industrial controls systems. Retrieved December 18, 2020.
* https://www.youtube.com/watch?v=xC9iM5wVedQ - Anton Cherepanov, Robert Lipovsky. (2022, August). Industroyer2: Sandworm's Cyberwarfare Targets Ukraine's Power Grid. Retrieved April 6, 2023.
* https://www.youtube.com/watch?v=yuZazP22rpI - Carl Hurd 2019, March 26 VPNFilter Deep Dive Retrieved. 2019/03/28 

