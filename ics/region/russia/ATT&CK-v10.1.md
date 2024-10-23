threat-crank.py 0.2.1
I: searching for regions that match .* russia.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v10.1/ics-attack/ics-attack.json
# Threat groups

* ALLANITE
* Dragonfly 2.0
* Sandworm Team
* TEMP.Veles

# Validate the following attacks

* Block Command Message - 1
* Block Reporting Message - 1
* Command-Line Interface - 1
* Commonly Used Port - 1
* Connection Proxy - 1
* Data from Information Repositories - 1
* Device Restart/Shutdown - 1
* Drive-by Compromise - 3
* Exploit Public-Facing Application - 1
* External Remote Services - 2
* Graphical User Interface - 1
* Indicator Removal on Host - 1
* Lateral Tool Transfer - 1
* Masquerading - 1
* Remote Services - 3
* Screen Capture - 2
* Scripting - 2
* Spearphishing Attachment - 3
* Supply Chain Compromise - 2
* System Firmware - 1
* Theft of Operational Information - 1
* Unauthorized Command Message - 1
* Valid Accounts - 4

# Validate the following phases

* collection-ics - 3
* command-and-control-ics - 2
* evasion-ics - 2
* execution-ics - 4
* impact-ics - 1
* impair-process-control - 1
* inhibit-response-function - 4
* initial-access-ics - 14
* lateral-movement-ics - 8
* persistence-ics - 5

# Validate the following platforms

* Control Server - 19
* Data Historian - 12
* Device Configuration/Parameters - 2
* Engineering Workstation - 14
* Field Controller/RTU/PLC/IED - 13
* Human-Machine Interface - 22
* Input/Output Server - 11
* Linux - 1
* None - 5
* Safety Instrumented System/Protection Relay - 9
* Windows - 5

# Validate the following defences


# Validate the following data sources

* Application Log: Application Log Content - 14
* Command: Command Execution - 11
* File: File Access - 1
* File: File Creation - 4
* File: File Deletion - 1
* File: File Metadata - 3
* File: File Modification - 2
* Firmware: Firmware Modification - 1
* Logon Session: Logon Session Creation - 8
* Logon Session: Logon Session Metadata - 2
* Module: Module Load - 3
* Network Share: Network Share Access - 3
* Network Traffic: Network Connection Creation - 6
* Network Traffic: Network Traffic Content - 17
* Network Traffic: Network Traffic Flow - 12
* Operational Databases: Device Alarm - 1
* Operational Databases: Process History/Live Data - 3
* Operational Databases: Process/Event Alarm - 3
* Process: OS API Execution - 3
* Process: Process Creation - 13
* Process: Process Termination - 2
* Scheduled Job: Scheduled Job Metadata - 1
* Scheduled Job: Scheduled Job Modification - 1
* Script: Script Execution - 3
* Service: Service Creation - 1
* Service: Service Metadata - 1
* User Account: User Account Authentication - 5
* Windows Registry: Windows Registry Key Deletion - 1
* Windows Registry: Windows Registry Key Modification - 1

# Review the following attack references

* http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6142258 - Bonnie Zhu, Anthony Joseph, Shankar Sastry. (2011). A Taxonomy of Cyber Attacks on SCADA Systems. Retrieved January 12, 2018.
* http://www.sciencedirect.com/science/article/pii/S1874548213000231 - Basnight, Zachry, et al.. (n.d.).  Retrieved October 17, 2017.
* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK. (2019, October 25). Spearphishing Attachment. Retrieved October 25, 2019.
* https://attack.mitre.org/techniques/T1570/ - Enterprise ATT&CK. (n.d.). Lateral Tool Transfer. Retrieved October 27, 2019.
* https://attack.mitre.org/wiki/Technique/T1059 - Enterprise ATT&CK. (2018, January 11). Command-Line Interface. Retrieved May 17, 2018.
* https://attack.mitre.org/wiki/Technique/T1090 - Enterprise ATT&CK. (2018, January 11). Connection Proxy. Retrieved May 17, 2018.
* https://attack.mitre.org/wiki/Technique/T1133 - Daniel Oakley, Travis Smith, Tripwire. (n.d.).  Retrieved May 30, 2018.
* https://dragos.com/blog/industry-news/implications-of-it-ransomware-for-ics-environments/ - Joe Slowik. (2019, April 10). Implications of IT Ransomware for ICS Environments. Retrieved October 27, 2019.
* https://dragos.com/blog/trisis/TRISIS-01.pdf - Dragos. (2017, December 13). TRISIS Malware Analysis of Safety System Targeted Malware. Retrieved January 12, 2018.
* https://ics-cert.us-cert.gov/alerts/IR-ALERT-H-16-056-01 - ICS-CERT. (2016, February 25). Cyber-Attack Against Ukrainian Critical Infrastructure. Retrieved March 8, 2019.
* https://ics.sans.org/media/E-ISAC%20SANS%20Ukraine%20DUC%205.pdf - Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems. (2016, March 18). Analysis of the Cyber Attack on the Ukranian Power Grid: Defense Use Case. Retrieved March 27, 2018.
* https://statescoop.com/tornado-sirens-in-dallas-suburbs-deactivated-after-being-hacked-and-set-off/ - Benjamin Freed. (2019, March 13). Tornado sirens in Dallas suburbs deactivated after being hacked and set off. Retrieved November 6, 2020.
* https://time.com/4270728/iran-cyber-attack-dam-fbi/ - Mark Thompson. (2016, March 24). Iranian Cyber Attack on New York Dam Shows Future of War. Retrieved November 7, 2019.
* https://us-cert.cisa.gov/sites/default/files/publications/AA21-201A_Chinese_Gas_Pipeline_Intrusion_Campaign_2011_to_2013%20(1).pdf - ONG2011 - DHS Advisory - Department of Justice (DOJ), DHS Cybersecurity & Infrastructure Security Agency (CISA). (2021, July 20). Chinese Gas Pipeline Intrusion Campaign, 2011 to 2013. Retrieved October 8, 2021.
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton. (n.d.). When The Lights Went Out. Retrieved October 22, 2019.
* https://www.controlglobal.com/industrynews/2019/yokogawa-announcement-warns-of-counterfeit-transmitters/ - Control Global. (2019, May 29). Yokogawa announcement warns of counterfeit transmitters. Retrieved April 9, 2021.
* https://www.cpni.gov.uk/Documents/Publications/2014/2014-04-23-c2-report-birmingham.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://www.f-secure.com/weblog/archives/00002718.html - Daavid Hentunen, Antti Tikkanen. (2014, June 23). Havex Hunts For ICS/SCADA Systems. Retrieved April 1, 2019.
* https://www.fireeye.com/blog/threat-research/2016/01/ukraine-and-sandworm-team.html - John Hultquist. (2016, January 07). Sandworm Team and the Ukrainian Power Authority Attacks. Retrieved March 8, 2019.
* https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html - Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer. (2017, December 14). Attackers Deploy New ICS Attack Framework “TRITON” and Cause Operational Disruption to Critical Infrastructure. Retrieved January 12, 2018.
* https://www.mitre.org/sites/default/files/pdf/08%201145.pdf - Marshall Abrams. (2008, July 23). Malicious Control System Cyber Security Attack Case Study– Maroochy Water Services, Australia. Retrieved March 27, 2018.
* https://www.us-cert.gov/ics/alerts/ICS-ALERT-14-281-01B - ICS-CERT. (2014, December 10). ICS Alert (ICS-ALERT-14-281-01E) Ongoing Sophisticated Malware Campaign Compromising ICS (Update E). Retrieved October 11, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-293A - ICS-CERT. (2017, October 21). Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 23, 2017.
* https://www.us-cert.gov/ncas/alerts/TA18-074A - NCAS. (2018, March 15). Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 11, 2019.
* https://www.wired.com/2016/03/inside-cunning-unprecedented-hack-ukraines-power-grid/ - Zetter, Kim. (2016, March 03). INSIDE THE CUNNING, UNPRECEDENTED HACK OF UKRAINE'S POWER GRID. Retrieved March 8, 2019.
* https://www.wsj.com/articles/iranian-hackers-infiltrated-new-york-dam-in-2013-1450662559 - Danny Yadron. (2015, December 20). Iranian Hackers Infiltrated New York Dam in 2013. Retrieved November 7, 2019.
* https://www.youtube.com/watch?v=MkXDSOgLQ6M - Pinellas County Sheriff’s Office. (2021, February 8). Treatment Plant Intrusion Press Conference. Retrieved October 8, 2021.
* https://www.zdnet.com/article/experts-think-they-know-how-dallas-emergency-sirens-were-hacked/ - Zack Whittaker. (2017, April 12). Dallas' emergency sirens were hacked with a rogue radio signal. Retrieved November 6, 2020.

# Validate the following tools


# Review the following tool references


# Validate the following malware

* BlackEnergy - 1
* Industroyer - 1
* KillDisk - 1
* NotPetya - 1
* Triton - 1

# Review the following malware references

* http://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/ - Cherepanov, A.. (2016, January 3). BlackEnergy by the SSHBearDoor: attacks against Ukrainian news media and electric industry. Retrieved May 18, 2016.
* https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html - Chiu, A. (2016, June 27). New Ransomware Variant "Nyetya" Compromises Systems Worldwide. Retrieved March 26, 2019.
* https://cwe.mitre.org/data/definitions/119.html - Common Weakness Enumeration. (2019, January 03). CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer. Retrieved March 8, 2019.
* https://download.schneider-electric.com/files?p_enDocType=Technical+leaflet&p_File_Name=SEVD-2017-347-01+Triconex+V3.pdf&p_Doc_Ref=SEVD-2017-347-01 - Schneider Electric. (2018, December 14). Security Notification - EcoStruxure Triconex Tricon V3. Retrieved August 26, 2019.
* https://dragos.com/blog/crashoverride/CrashOverride-01.pdf - Dragos Inc.. (2017, June 13). CRASHOVERRIDE Analysis of the Threat to Electric Grid Operations. Retrieved December 18, 2020.
* https://dragos.com/blog/trisis/TRISIS-01.pdf - Dragos. (2017, December 13). TRISIS Malware Analysis of Safety System Targeted Malware. Retrieved January 12, 2018.
* https://github.com/MDudek-ICS/TRISIS-TRITON-HATMAN/tree/master/decompiled_code/library - MDudek-ICS. (n.d.). TRISIS-TRITON-HATMAN. Retrieved November 3, 2019.
* https://nvd.nist.gov/vuln/detail/CVE-2018-8872 - MITRE. (2018, May 04). CVE-2018-8872. Retrieved March 8, 2019.
* https://us-cert.cisa.gov/ics/advisories/ICSA-18-107-02 - ICS-CERT. (2018, December 18). Advisory (ICSA-18-107-02) - Schneider Electric Triconex Tricon (Update B). Retrieved March 8, 2019.
* https://us-cert.cisa.gov/sites/default/files/documents/MAR-17-352-01%20HatMan%20-%20Safety%20System%20Targeted%20Malware%20%28Update%20B%29.pdf - DHS CISA. (2019, February 27). MAR-17-352-01 HatMan—Safety System Targeted Malware (Update B). Retrieved March 8, 2019.
* https://www.bleepingcomputer.com/news/security/killdisk-disk-wiping-malware-adds-ransomware-component/ - Catalin Cimpanu. (2016, December 29). KillDisk Disk-Wiping Malware Adds Ransomware Component. Retrieved January 12, 2021.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Joe Slowik. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved December 18, 2020.
* https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html - Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer. (2017, December 14). Attackers Deploy New ICS Attack Framework “TRITON” and Cause Operational Disruption to Critical Infrastructure. Retrieved January 12, 2018.
* https://www.justice.gov/opa/press-release/file/1328521/download - Scott W. Brady. (2020, October 15). United States vs. Yuriy Sergeyevich Andrienko et al.. Retrieved November 25, 2020.
* https://www.midnightbluelabs.com/blog/2018/1/16/analyzing-the-triton-industrial-malware - Jos Wetzels. (2018, January 16). Analyzing the TRITON industrial malware. Retrieved October 22, 2019.
* https://www.nrc.gov/docs/ML1209/ML120900890.pdf - The Office of Nuclear Reactor Regulation. (n.d.). Triconex Topical Report 7286-545-1. Retrieved May 30, 2018.
* https://www.trendmicro.com/en_us/research/18/a/new-killdisk-variant-hits-financial-organizations-in-latin-america.html - Gilbert Sison, Rheniel Ramos, Jay Yaneza, Alfredo Oliveira. (2018, January 15). KillDisk Variant Hits Latin American Financial Groups. Retrieved January 12, 2021.
* https://www.trendmicro.com/en_us/research/18/f/new-killdisk-variant-hits-latin-american-financial-organizations-again.html - Fernando Merces, Byron Gelera, Martin Co. (2018, June 7). KillDisk Variant Hits Latin American Finance Industry. Retrieved January 12, 2021.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/ - Cherepanov, A.. (2017, June 30). TeleBots are back: Supply chain attacks against Ukraine. Retrieved June 11, 2020.
* https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf - Anton Cherepanov. (2017, June 12). Win32/Industroyer: A new threat for industrial controls systems. Retrieved December 18, 2020.
* https://www.youtube.com/watch?v=XwSJ8hloGvY - Julian Gutmanis. (2019, March 11). Triton - A Report From The Trenches. Retrieved March 11, 2019.
* https://www.youtube.com/watch?v=f09E75bWvkk&index=3&list=PL8OWO1qWXF4qYG19p7An4Vw3N2YZ86aRS&t=0s - Schneider Electric. (2018, January 23). TRITON - Schneider Electric Analysis and Disclosure. Retrieved March 14, 2019.
