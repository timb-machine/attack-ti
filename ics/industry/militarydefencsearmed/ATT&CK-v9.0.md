threat-crank.py 0.2.1
I: searching for industries that match .* military.*|.* defen[cs]e.*|.* armed.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v9.0/ics-attack/ics-attack.json
# Threat groups

* Dragonfly
* Sandworm Team

# Validate the following attacks

* Block Command Message - 1
* Block Reporting Message - 1
* Commonly Used Port - 1
* Device Restart/Shutdown - 1
* Drive-by Compromise - 1
* Exploit Public-Facing Application - 1
* External Remote Services - 1
* Graphical User Interface - 1
* Remote Services - 1
* Screen Capture - 1
* Spearphishing Attachment - 2
* System Firmware - 1
* Unauthorized Command Message - 1
* Valid Accounts - 2

# Validate the following phases

* collection-ics - 1
* command-and-control-ics - 1
* execution-ics - 1
* impair-process-control - 1
* inhibit-response-function - 4
* initial-access-ics - 6
* lateral-movement-ics - 3
* persistence-ics - 3

# Validate the following platforms

* Control Server - 7
* Data Historian - 4
* Engineering Workstation - 6
* Field Controller/RTU/PLC/IED - 8
* Human-Machine Interface - 8
* Input/Output Server - 5
* Safety Instrumented System/Protection Relay - 4
* Windows - 8

# Validate the following defences


# Validate the following data sources

* API monitoring - 1
* Alarm History - 2
* Alarm history - 3
* Application logs - 1
* Authentication logs - 4
* Binary file metadata - 1
* Data historian - 1
* Detonation chamber - 2
* Email gateway - 2
* File monitoring - 4
* Mail server - 2
* Netflow/Enclave netflow - 1
* Network device logs - 1
* Network intrusion detection system - 3
* Network protocol analysis - 5
* Packet capture - 9
* Process command-line parameters - 1
* Process monitoring - 4
* SSl/TLS inspection - 1
* Sequential event recorder - 3
* Web application firewall logs - 1
* Web logs - 1
* Web proxy - 1
* Windows event logs - 1
* process use of network - 1

# Review the following attack references

* http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6142258 - Bonnie Zhu, Anthony Joseph, Shankar Sastry. (2011). A Taxonomy of Cyber Attacks on SCADA Systems. Retrieved January 12, 2018.
* http://www.sciencedirect.com/science/article/pii/S1874548213000231 - Basnight, Zachry, et al.. (n.d.).  Retrieved October 17, 2017.
* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK. (2019, October 25). Spearphishing Attachment. Retrieved October 25, 2019.
* https://attack.mitre.org/wiki/Technique/T1133 - Daniel Oakley, Travis Smith, Tripwire. (n.d.).  Retrieved May 30, 2018.
* https://dragos.com/blog/industry-news/implications-of-it-ransomware-for-ics-environments/ - Joe Slowik. (2019, April 10). Implications of IT Ransomware for ICS Environments. Retrieved October 27, 2019.
* https://dragos.com/blog/trisis/TRISIS-01.pdf - Dragos. (2017, December 13). TRISIS Malware Analysis of Safety System Targeted Malware. Retrieved January 12, 2018.
* https://ics-cert.us-cert.gov/alerts/IR-ALERT-H-16-056-01 - ICS-CERT. (2016, February 25). Cyber-Attack Against Ukrainian Critical Infrastructure. Retrieved March 8, 2019.
* https://ics.sans.org/media/E-ISAC%20SANS%20Ukraine%20DUC%205.pdf - Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems. (2016, March 18). Analysis of the Cyber Attack on the Ukranian Power Grid: Defense Use Case. Retrieved March 27, 2018.
* https://statescoop.com/tornado-sirens-in-dallas-suburbs-deactivated-after-being-hacked-and-set-off/ - Benjamin Freed. (2019, March 13). Tornado sirens in Dallas suburbs deactivated after being hacked and set off. Retrieved November 6, 2020.
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton. (n.d.). When The Lights Went Out. Retrieved October 22, 2019.
* https://www.fireeye.com/blog/threat-research/2016/01/ukraine-and-sandworm-team.html - John Hultquist. (2016, January 07). Sandworm Team and the Ukrainian Power Authority Attacks. Retrieved March 8, 2019.
* https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html - Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer. (2017, December 14). Attackers Deploy New ICS Attack Framework “TRITON” and Cause Operational Disruption to Critical Infrastructure. Retrieved January 12, 2018.
* https://www.mitre.org/sites/default/files/pdf/08%201145.pdf - Marshall Abrams. (2008, July 23). Malicious Control System Cyber Security Attack Case Study– Maroochy Water Services, Australia. Retrieved March 27, 2018.
* https://www.us-cert.gov/ics/alerts/ICS-ALERT-14-281-01B - ICS-CERT. (2014, December 10). ICS Alert (ICS-ALERT-14-281-01E) Ongoing Sophisticated Malware Campaign Compromising ICS (Update E). Retrieved October 11, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-293A - ICS-CERT. (2017, October 21). Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 23, 2017.
* https://www.us-cert.gov/ncas/alerts/TA18-074A - NCAS. (2018, March 15). Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 11, 2019.
* https://www.wired.com/2016/03/inside-cunning-unprecedented-hack-ukraines-power-grid/ - Zetter, Kim. (2016, March 03). INSIDE THE CUNNING, UNPRECEDENTED HACK OF UKRAINE'S POWER GRID. Retrieved March 8, 2019.
* https://www.zdnet.com/article/experts-think-they-know-how-dallas-emergency-sirens-were-hacked/ - Zack Whittaker. (2017, April 12). Dallas' emergency sirens were hacked with a rogue radio signal. Retrieved November 6, 2020.

# Validate the following tools


# Review the following tool references


# Validate the following malware

* Backdoor.Oldrea - 1
* BlackEnergy - 1
* Industroyer - 1
* Killdisk - 1
* NotPetya - 1

# Review the following malware references

* http://www.symantec.com/content/en/us/enterprise/media/security_response/whitepapers/Dragonfly_Threat_Against_Western_Energy_Suppliers.pdf - Symantec Security Response. (2014, July 7). Dragonfly: Cyberespionage Attacks Against Energy Suppliers. Retrieved April 8, 2016.
* https://blog-assets.f-secure.com/wp-content/uploads/2019/10/15163408/BlackEnergy_Quedagh.pdf - F-Secure Labs. (2014). BlackEnergy & Quedagh: The convergence of crimeware and APT attacks. Retrieved March 24, 2016.
* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html - Chiu, A. (2016, June 27). New Ransomware Variant "Nyetya" Compromises Systems Worldwide. Retrieved March 26, 2019.
* https://dragos.com/wp-content/uploads/CRASHOVERRIDE.pdf - Joe Slowik. (2019, August 15). CRASHOVERRIDE: Reassessing the 2016 Ukraine Electric Power Event as a Protection-Focused Attack. Retrieved October 22, 2019.
* https://us-cert.cisa.gov/ncas/alerts/TA17-163A - CISA. (2017, June 12). Alert (TA17-163A). Retrieved October 22, 2019.
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton. (n.d.). When The Lights Went Out. Retrieved October 22, 2019.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Dragos. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved October 14, 2019.
* https://www.dragos.com/wp-content/uploads/CrashOverride-01.pdf - Dragos Inc.. (2017, June 13). Industroyer - Dragos - 201706: Analysis of the Threat to Electic Grid Operations. Retrieved September 18, 2017.
* https://www.justice.gov/opa/press-release/file/1328521/download - Scott W. Brady. (2020, October 15). United States vs. Yuriy Sergeyevich Andrienko et al.. Retrieved November 25, 2020.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.welivesecurity.com/2016/01/03/blackenergy-sshbeardoor-details-2015-attacks-ukrainian-news-media-electric-industry/ - Anton Cherepanov. (n.d.). BlackEnergy by the SSHBearDoor: attacks against Ukrainian news media and electric industry. Retrieved October 29, 2019.
* https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/ - Cherepanov, A.. (2017, June 30). TeleBots are back: Supply chain attacks against Ukraine. Retrieved June 11, 2020.
* https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf - Anton Cherepanov, ESET. (2017, June 12). Win32/Industroyer: A new threat for industrial control systems. Retrieved September 15, 2017.

