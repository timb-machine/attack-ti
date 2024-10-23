threat-crank.py 0.2.1
I: searching for industries that match .* telco.*|.* telecom.*|.* carrier.*|.* phone.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v9.0/ics-attack/ics-attack.json
# Threat groups

* HEXANE
* OilRig

# Validate the following attacks

* Drive-by Compromise - 1
* Man in the Middle - 1
* Scripting - 2
* Spearphishing Attachment - 2
* Standard Application Layer Protocol - 2
* Valid Accounts - 2

# Validate the following phases

* collection-ics - 1
* command-and-control-ics - 2
* execution-ics - 2
* initial-access-ics - 3
* lateral-movement-ics - 2
* persistence-ics - 2

# Validate the following platforms

* Control Server - 7
* Data Historian - 6
* Engineering Workstation - 8
* Field Controller/RTU/PLC/IED - 3
* Human-Machine Interface - 7
* Input/Output Server - 2
* Safety Instrumented System/Protection Relay - 2
* Windows - 1

# Validate the following defences


# Validate the following data sources

* Authentication logs - 2
* Detonation chamber - 2
* Email gateway - 2
* File monitoring - 4
* Mail server - 2
* Malware reverse engineering - 2
* Netflow/Enclave netflow - 1
* Network device logs - 2
* Network intrusion detection system - 3
* Network protocol analysis - 2
* Packet capture - 6
* Process command-line parameters - 2
* Process monitoring - 6
* Process use of network - 2
* SSl/TLS inspection - 1
* Web proxy - 1
* process use of network - 1

# Review the following attack references

* http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=6142258 - Bonnie Zhu, Anthony Joseph, Shankar Sastry. (2011). A Taxonomy of Cyber Attacks on SCADA Systems. Retrieved January 12, 2018.
* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK. (2019, October 25). Spearphishing Attachment. Retrieved October 25, 2019.
* https://ics.sans.org/media/E-ISAC%20SANS%20Ukraine%20DUC%205.pdf - Electricity Information Sharing and Analysis Center; SANS Industrial Control Systems. (2016, March 18). Analysis of the Cyber Attack on the Ukranian Power Grid: Defense Use Case. Retrieved March 27, 2018.
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton. (n.d.). When The Lights Went Out. Retrieved October 22, 2019.
* https://www.sans.org/reading-room/whitepapers/ICS/man-in-the-middle-attack-modbus-tcp-illustrated-wireshark-38095 - Gabriel Sanchez. (2017, October). Man-In-The-Middle Attack Against Modbus TCP Illustrated with Wireshark. Retrieved January 5, 2020.
* https://www.us-cert.gov/ncas/alerts/TA18-074A - NCAS. (2018, March 15). Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors. Retrieved October 11, 2019.

# Validate the following tools


# Review the following tool references


# Validate the following malware


# Review the following malware references


