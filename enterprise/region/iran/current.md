threat-crank.py 0.2.1
I: searching for regions that match .* iran.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v1.0/enterprise-attack/enterprise-attack.json
# Threat groups

* APT34
* Cleaver
* CopyKittens
* Group5
* OilRig
* Strider

# Validate the following attacks

* Account Discovery - 1
* Automated Collection - 1
* Brute Force - 1
* Code Signing - 1
* Command-Line Interface - 2
* Connection Proxy - 1
* Credential Dumping - 4
* Custom Command and Control Protocol - 1
* Data Compressed - 1
* Data Encrypted - 1
* Deobfuscate/Decode Files or Information - 2
* Exfiltration Over Alternative Protocol - 1
* External Remote Services - 1
* Fallback Channels - 1
* File Deletion - 3
* Indicator Removal from Tools - 1
* Input Capture - 2
* Network Service Scanning - 1
* Obfuscated Files or Information - 3
* Permission Groups Discovery - 1
* PowerShell - 3
* Process Discovery - 1
* Query Registry - 1
* Redundant Access - 1
* Remote Desktop Protocol - 2
* Remote File Copy - 1
* Remote Services - 1
* Rundll32 - 1
* Screen Capture - 2
* Scripting - 2
* Software Packing - 1
* Standard Application Layer Protocol - 2
* Standard Cryptographic Protocol - 1
* System Information Discovery - 1
* System Network Configuration Discovery - 1
* System Network Connections Discovery - 1
* System Owner/User Discovery - 1
* System Service Discovery - 1
* Uncommonly Used Port - 1
* Valid Accounts - 2
* Web Shell - 2
* Windows Management Instrumentation - 1

# Validate the following phases

* collection - 5
* command-and-control - 8
* credential-access - 7
* defense-evasion - 17
* discovery - 10
* execution - 9
* exfiltration - 3
* lateral-movement - 4
* persistence - 6
* privilege-escalation - 4

# Validate the following platforms

* Linux - 42
* Windows - 60
* macOS - 43

# Validate the following defences

* Anti-virus - 8
* Application whitelisting - 1
* Firewall - 2
* Host forensic analysis - 6
* Host intrusion prevention systems - 8
* Log analysis - 1
* Network intrusion detection system - 5
* Process whitelisting - 4
* Signature-based detection - 6
* System access controls - 2
* Windows User Account Control - 1
* heuristic detection - 1

# Validate the following data sources

* API monitoring - 10
* Anti-virus - 3
* Authentication logs - 11
* Binary file metadata - 13
* Data loss prevention - 1
* File monitoring - 24
* Kernel drivers - 2
* Malware reverse engineering - 7
* Netflow/Enclave netflow - 15
* Network protocol analysis - 7
* Packet capture - 10
* PowerShell logs - 4
* Process Monitoring - 2
* Process command-line parameters - 32
* Process monitoring - 45
* Process use of network - 15
* SSL/TLS inspection - 1
* User interface - 1
* Windows Registry - 6

# Review the following attack references

* http://blog.crowdstrike.com/adversary-tricks-crowdstrike-treats/ - Alperovitch, D. (2014, October 31). Malware-Free Intrusions. Retrieved November 4, 2014.
* http://blog.leetsys.com/2012/01/02/capturing-windows-7-credentials-at-logon-using-custom-credential-provider/ - Wrightson, T. (2012, January 2). CAPTURING WINDOWS 7 CREDENTIALS AT LOGON USING CUSTOM CREDENTIAL PROVIDER. Retrieved November 12, 2014.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://en.wikipedia.org/wiki/Executable%20compression - Executable compression. (n.d.).  Retrieved December 4, 2014.
* http://www.blackhillsinfosec.com/?p=4645 - Thyer, J. (2015, October 30). Password Spraying & Other Fun with RPCCLIENT. Retrieved April 25, 2017.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html - Korznikov, A. (2017, March 17). Passwordless RDP Session Hijacking Feature All Windows versions. Retrieved December 11, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.metasploit.com - Metasploit. (n.d.).  Retrieved December 4, 2014.
* http://www.netsec.colostate.edu/~zhang/DetectingEncryptedBotnetTraffic.pdf - Zhang, H., Papadopoulos, C., & Massey, D. (2013, April). Detecting encrypted botnet traffic. Retrieved August 19, 2015.
* http://www.sans.org/reading-room/whitepapers/analyst/finding-hidden-threats-decrypting-ssl-34840 - Butler, M. (2013, November). Finding Hidden Threats by Decrypting SSL. Retrieved April 5, 2016.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.thesafemac.com/new-signed-malware-called-janicab/ - Thomas. (2013, July 15). New signed malware called Janicab. Retrieved July 17, 2017.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://blog.crowdstrike.com/deep-thought-chinese-targeting-national-security-think-tanks/ - Alperovitch, D. (2014, July 7). Deep in Thought: Chinese Targeting of National Security Think Tanks. Retrieved November 12, 2014.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://en.wikipedia.org/wiki/Code%20signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Command-line%20interface - Wikipedia. (2016, June 26). Command-line interface. Retrieved June 27, 2016.
* https://en.wikipedia.org/wiki/List%20of%20file%20signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Password%20cracking - Wikipedia. (n.d.). Password cracking. Retrieved December 23, 2015.
* https://en.wikipedia.org/wiki/Server%20Message%20Block - Wikipedia. (2016, June 12). Server Message Block. Retrieved June 12, 2016.
* https://en.wikipedia.org/wiki/Windows%20Registry - Wikipedia. (n.d.). Windows Registry. Retrieved February 2, 2015.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa - Delpy, B. (2014, September 14). Mimikatz module ~ sekurlsa. Retrieved January 10, 2016.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.).  Retrieved December 4, 2014.
* https://github.com/nccgroup/redsnarf - NCC Group PLC. (2016, November 1). Kali Redsnarf. Retrieved December 11, 2017.
* https://insights.sei.cmu.edu/cert/2015/03/the-risks-of-ssl-inspection.html - Dormann, W. (2015, March 13). The Risks of SSL Inspection. Retrieved April 5, 2016.
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6 - Beaumont, K. (2017, March 19). RDP hijacking — how to hijack RDS and RemoteApp sessions transparently to move through an organisation. Retrieved December 11, 2017.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://technet.microsoft.com/en-us/library/cc787851.aspx - Microsoft. (2003, March 28). What Is RPC?. Retrieved June 12, 2016.
* https://technet.microsoft.com/en-us/library/dn487457.aspx - Microsoft. (2016, April 15). Audit Policy Recommendations. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/dn535501.aspx - Microsoft. (2016, April 15). Attractive Accounts for Credential Theft. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/windowsserver/ee236407.aspx - Microsoft. (n.d.). Remote Desktop Services. Retrieved June 1, 2016.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.cylance.com/content/dam/cylance/pages/operation-cleaver/Cylance%20Operation%20Cleaver%20Report.pdf - Cylance. (2014, December). Operation Cleaver. Retrieved September 14, 2017.
* https://www.fidelissecurity.com/sites/default/files/FTA%201018%20looking%20at%20the%20sky%20for%20a%20dark%20comet.pdf - Fidelis Cybersecurity. (2015, August 4). Looking at the Sky for a DarkComet. Retrieved April 5, 2016.
* https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html - Lee, T., Hanzlik, D., Ahl, I. (2013, August 7). Breaking Down the China Chopper Web Shell - Part I. Retrieved March 27, 2015.
* https://www.fireeye.com/blog/threat-research/2016/02/greater%20visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.us-cert.gov/ncas/alerts/TA15-314A - US-CERT. (2015, November 13). Compromised Web Servers and Web Shells - Threat Awareness and Guidance. Retrieved June 8, 2016.
* https://www.veil-framework.com/framework/ - Veil Framework. (n.d.).  Retrieved December 4, 2014.
* https://www.volexity.com/blog/2015/10/07/virtual-private-keylogging-cisco-web-vpns-leveraged-for-access-and-persistence/ - Adair, S. (2015, October 7). Virtual Private Keylogging: Cisco Web VPNs Leveraged for Access and Persistence. Retrieved March 20, 2017.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.

# Validate the following tools


# Review the following tool references


# Validate the following malware


# Review the following malware references


