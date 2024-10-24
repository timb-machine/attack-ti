threat-crank.py 0.2.1
I: searching for industries that match .* telco.*|.* telecom.*|.* carrier.*|.* phone.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v11.1/ics-attack/ics-attack.json
# Threat groups

* HEXANE
* OilRig

# Validate the following attacks

* Drive-by Compromise - 1
* Scripting - 2
* Spearphishing Attachment - 2
* Standard Application Layer Protocol - 2
* Valid Accounts - 2

# Validate the following phases

* command-and-control-ics - 2
* execution-ics - 2
* initial-access-ics - 3
* lateral-movement-ics - 2
* persistence-ics - 2

# Validate the following platforms

* Control Server - 6
* Data Historian - 6
* Engineering Workstation - 8
* Field Controller/RTU/PLC/IED - 2
* Human-Machine Interface - 6
* Input/Output Server - 2
* None - 1
* Safety Instrumented System/Protection Relay - 2

# Validate the following defences


# Validate the following data sources

* Application Log: Application Log Content - 3
* Command: Command Execution - 2
* File: File Creation - 1
* Logon Session: Logon Session Creation - 2
* Module: Module Load - 2
* Network Traffic: Network Connection Creation - 1
* Network Traffic: Network Traffic Content - 5
* Network Traffic: Network Traffic Flow - 2
* Process: Process Creation - 3
* Script: Script Execution - 2
* User Account: User Account Authentication - 2

# Review the following attack references

* https://attack.mitre.org/techniques/T1193/ - Enterprise ATT&CK 2019, October 25 Spearphishing Attachment Retrieved. 2019/10/25 
* https://us-cert.cisa.gov/ncas/alerts/TA18-074A - Cybersecurity & Infrastructure Security Agency 2018, March 15 Alert (TA18-074A) Russian Government Cyber Activity Targeting Energy and Other Critical Infrastructure Sectors Retrieved. 2019/10/11 
* https://us-cert.cisa.gov/sites/default/files/publications/AA21-201A_Chinese_Gas_Pipeline_Intrusion_Campaign_2011_to_2013%20(1).pdf - Department of Justice (DOJ), DHS Cybersecurity & Infrastructure Security Agency (CISA) 2021, July 20 Chinese Gas Pipeline Intrusion Campaign, 2011 to 2013 Retrieved. 2021/10/08 
* https://www.boozallen.com/content/dam/boozallen/documents/2016/09/ukraine-report-when-the-lights-went-out.pdf - Booz Allen Hamilton   When The Lights Went Out Retrieved. 2019/10/22 

# Validate the following tools


# Review the following tool references


# Validate the following malware


# Review the following malware references


