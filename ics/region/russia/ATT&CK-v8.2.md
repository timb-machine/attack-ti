threat-crank.py 0.2.1
I: searching for regions that match .* russia.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v8.2/ics-attack/ics-attack.json
# Threat groups

* ALLANITE
* Dragonfly 2.0
* Sandworm Team
* TEMP.Veles

# Validate the following attacks

* Drive-by Compromise - 3
* External Remote Services - 1
* Internet Accessible Device - 1
* Screen Capture - 1
* Spearphishing Attachment - 2
* Supply Chain Compromise - 2
* Valid Accounts - 4

# Validate the following phases

* collection-ics - 1
* initial-access-ics - 9
* lateral-movement-ics - 5
* persistence-ics - 4

# Validate the following platforms

* Control Server - 7
* Data Historian - 6
* Engineering Workstation - 6
* Field Controller/RTU/PLC/IED - 4
* Human-Machine Interface - 7
* Input/Output Server - 5
* Safety Instrumented System/Protection Relay - 4
* Windows - 17

# Validate the following defences


# Validate the following data sources

* API monitoring - 1
* Authentication logs - 6
* Detonation chamber - 4
* Digital signatures - 2
* Email gateway - 2
* File monitoring - 5
* Mail server - 2
* Network device logs - 3
* Network intrusion detection system - 5
* Packet capture - 5
* Process monitoring - 5
* SSl/TLS inspection - 3
* Web proxy - 5
* process use of network - 3

# Review the following attack references

* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK. (2019, October 25). Spearphishing Attachment. Retrieved October 25, 2019.
* https://attack.mitre.org/wiki/Technique/T1133 - Daniel Oakley, Travis Smith, Tripwire. (n.d.).  Retrieved May 30, 2018.
* https://ics-cert.us-cert.gov/alerts/IR-ALERT-H-16-056-01 - ICS-CERT. (2016, February 25). Cyber-Attack Against Ukrainian Critical Infrastructure. Retrieved March 8, 2019.
* https://ics.sans.org/media/E-ISAC%20SANS%20Ukraine%20DUC%205.pdf - Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems. (2016, March 18). Analysis of the Cyber Attack on the Ukranian Power Grid: Defense Use Case. Retrieved March 27, 2018.
* https://time.com/4270728/iran-cyber-attack-dam-fbi/ - Mark Thompson. (2016, March 24). Iranian Cyber Attack on New York Dam Shows Future of War. Retrieved November 7, 2019.
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton. (n.d.). When The Lights Went Out. Retrieved October 22, 2019.
* https://www.f-secure.com/weblog/archives/00002718.html - Daavid Hentunen, Antti Tikkanen. (2014, June 23). Havex Hunts For ICS/SCADA Systems. Retrieved April 1, 2019.
* https://www.fireeye.com/blog/threat-research/2016/01/ukraine-and-sandworm-team.html - John Hultquist. (2016, January 07). Sandworm Team and the Ukrainian Power Authority Attacks. Retrieved March 8, 2019.
* https://www.us-cert.gov/ncas/alerts/TA17-293A - ICS-CERT. (2017, October 21). Advanced Persistent Threat Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 23, 2017.
* https://www.us-cert.gov/ncas/alerts/TA18-074A - NCAS. (2018, March 15). Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 11, 2019.
* https://www.us-cert.gov/sites/default/files/Monitors/ICS-CERT%20Monitor%20Jan-April2014.pdf - NCCIC. (2014, January 1). Internet Accessible Control Systems At Risk. Retrieved November 7, 2019.
* https://www.wired.com/2016/03/inside-cunning-unprecedented-hack-ukraines-power-grid/ - Zetter, Kim. (2016, March 03). INSIDE THE CUNNING, UNPRECEDENTED HACK OF UKRAINE'S POWER GRID. Retrieved March 8, 2019.
* https://www.wsj.com/articles/iranian-hackers-infiltrated-new-york-dam-in-2013-1450662559 - Danny Yadron. (2015, December 20). Iranian Hackers Infiltrated New York Dam in 2013. Retrieved November 7, 2019.

# Validate the following tools


# Review the following tool references


# Validate the following malware

* Industroyer - 1
* NotPetya - 1
* Triton - 1

# Review the following malware references

* https://blog.talosintelligence.com/2017/06/worldwide-ransomware-variant.html - Chiu, A. (2016, June 27). New Ransomware Variant "Nyetya" Compromises Systems Worldwide. Retrieved March 26, 2019.
* https://cwe.mitre.org/data/definitions/119.html - Common Weakness Enumeration. (2019, January 03). CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer. Retrieved March 8, 2019.
* https://download.schneider-electric.com/files?p_enDocType=Technical+leaflet&p_File_Name=SEVD-2017-347-01+Triconex+V3.pdf&p_Doc_Ref=SEVD-2017-347-01 - Schneider Electric. (2018, December 14). Security Notification - EcoStruxure Triconex Tricon V3. Retrieved August 26, 2019.
* https://dragos.com/blog/trisis/TRISIS-01.pdf - Dragos. (2017, December 13). TRISIS Malware Analysis of Safety System Targeted Malware. Retrieved January 12, 2018.
* https://dragos.com/wp-content/uploads/CRASHOVERRIDE.pdf - Joe Slowik. (2019, August 15). CRASHOVERRIDE: Reassessing the 2016 Ukraine Electric Power Event as a Protection-Focused Attack. Retrieved October 22, 2019.
* https://github.com/MDudek-ICS/TRISIS-TRITON-HATMAN/tree/master/decompiled_code/library - MDudek-ICS. (n.d.). TRISIS-TRITON-HATMAN. Retrieved November 3, 2019.
* https://nvd.nist.gov/vuln/detail/CVE-2018-8872 - MITRE. (2018, May 04). CVE-2018-8872. Retrieved March 8, 2019.
* https://us-cert.cisa.gov/ics/advisories/ICSA-18-107-02 - ICS-CERT. (2018, December 18). Advisory (ICSA-18-107-02) - Schneider Electric Triconex Tricon (Update B). Retrieved March 8, 2019.
* https://us-cert.cisa.gov/ncas/alerts/TA17-163A - CISA. (2017, June 12). Alert (TA17-163A). Retrieved October 22, 2019.
* https://us-cert.cisa.gov/sites/default/files/documents/MAR-17-352-01%20HatMan%20-%20Safety%20System%20Targeted%20Malware%20%28Update%20B%29.pdf - DHS CISA. (2019, February 27). MAR-17-352-01 HatMan—Safety System Targeted Malware (Update B). Retrieved March 8, 2019.
* https://www.dragos.com/wp-content/uploads/CRASHOVERRIDE2018.pdf - Dragos. (2018, October 12). Anatomy of an Attack: Detecting and Defeating CRASHOVERRIDE. Retrieved October 14, 2019.
* https://www.dragos.com/wp-content/uploads/CrashOverride-01.pdf - Dragos Inc.. (2017, June 13). Industroyer - Dragos - 201706: Analysis of the Threat to Electic Grid Operations. Retrieved September 18, 2017.
* https://www.fireeye.com/blog/threat-research/2017/12/attackers-deploy-new-ics-attack-framework-triton.html - Blake Johnson, Dan Caban, Marina Krotofil, Dan Scali, Nathan Brubaker, Christopher Glyer. (2017, December 14). Attackers Deploy New ICS Attack Framework “TRITON” and Cause Operational Disruption to Critical Infrastructure. Retrieved January 12, 2018.
* https://www.midnightbluelabs.com/blog/2018/1/16/analyzing-the-triton-industrial-malware - Jos Wetzels. (2018, January 16). Analyzing the TRITON industrial malware. Retrieved October 22, 2019.
* https://www.nrc.gov/docs/ML1209/ML120900890.pdf - The Office of Nuclear Reactor Regulation. (n.d.). Triconex Topical Report 7286-545-1. Retrieved May 30, 2018.
* https://www.us-cert.gov/ncas/alerts/TA17-181A - US-CERT. (2017, July 1). Alert (TA17-181A): Petya Ransomware. Retrieved March 15, 2019.
* https://www.welivesecurity.com/2017/06/30/telebots-back-supply-chain-attacks-against-ukraine/ - Cherepanov, A.. (2017, June 30). TeleBots are back: Supply chain attacks against Ukraine. Retrieved June 11, 2020.
* https://www.welivesecurity.com/wp-content/uploads/2017/06/Win32_Industroyer.pdf - Anton Cherepanov, ESET. (2017, June 12). Win32/Industroyer: A new threat for industrial control systems. Retrieved September 15, 2017.
* https://www.youtube.com/watch?v=XwSJ8hloGvY - Julian Gutmanis. (2019, March 11). Triton - A Report From The Trenches. Retrieved March 11, 2019.
* https://www.youtube.com/watch?v=f09E75bWvkk&index=3&list=PL8OWO1qWXF4qYG19p7An4Vw3N2YZ86aRS&t=0s - Schneider Electric. (2018, January 23). TRITON - Schneider Electric Analysis and Disclosure. Retrieved March 14, 2019.

