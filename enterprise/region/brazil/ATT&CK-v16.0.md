threat-crank.py 0.2.1
I: searching for regions that match .* brazil.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v16.0/enterprise-attack/enterprise-attack.json
# Threat groups

* Malteiro

# Validate the following attacks

* Credentials from Password Stores - 1
* Credentials from Web Browsers - 1
* Deobfuscate/Decode Files or Information - 1
* Dynamic-link Library Injection - 1
* Encrypted/Encoded File - 1
* Financial Theft - 1
* Malicious File - 1
* Security Software Discovery - 1
* Spearphishing Attachment - 1
* System Information Discovery - 1
* System Language Discovery - 1
* Visual Basic - 1

# Validate the following phases

* credential-access - 2
* defense-evasion - 3
* discovery - 3
* execution - 2
* impact - 1
* initial-access - 1
* privilege-escalation - 1

# Validate the following platforms

* IaaS - 3
* Linux - 11
* Network - 1
* Office Suite - 1
* SaaS - 1
* Windows - 13
* macOS - 11

# Validate the following defences

* Anti-virus - 2
* Application control - 1
* Host Intrusion Prevention Systems - 1
* Network Intrusion Detection System - 1
* Signature-based Detection - 1

# Validate the following data sources

* Application Log: Application Log Content - 2
* Cloud Service: Cloud Service Enumeration - 1
* Command: Command Execution - 6
* File: File Access - 2
* File: File Creation - 3
* File: File Metadata - 1
* File: File Modification - 1
* Firewall: Firewall Enumeration - 1
* Firewall: Firewall Metadata - 1
* Module: Module Load - 2
* Network Traffic: Network Traffic Content - 1
* Network Traffic: Network Traffic Flow - 1
* Process: OS API Execution - 6
* Process: Process Access - 3
* Process: Process Creation - 7
* Process: Process Metadata - 1
* Process: Process Modification - 1
* Script: Script Execution - 2
* Windows Registry: Windows Registry Key Access - 1

# Review the following attack references

* https://apnews.com/article/russia-ukraine-technology-business-europe-hacking-ce7a8aca506742ab8e8873e7f9f229c2 - FRANK BAJAK AND RAPHAEL SATTER. (2017, June 30). Companies still hobbled from fearsome cyberattack. Retrieved August 18, 2023.
* https://blog.f-secure.com/hiding-malicious-code-with-module-stomping/ - Aliz Hammond. (2019, August 15). Hiding Malicious Code with "Module Stomping": Part 1. Retrieved July 14, 2022.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.talosintelligence.com/2018/02/olympic-destroyer.html - Mercer, W. and Rascagneres, P. (2018, February 12). Olympic Destroyer Takes Aim At Winter Olympics. Retrieved March 14, 2019.
* https://cloud.google.com/compute/docs/reference/rest/v1/instances - Google. (n.d.). Rest Resource: instance. Retrieved March 3, 2020.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://docs.aws.amazon.com/cli/latest/reference/ssm/describe-instance-information.html - Amazon. (n.d.). describe-instance-information. Retrieved March 3, 2020.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/rest/api/compute/virtualmachines/get - Microsoft. (2019, March 1). Virtual Machines - Get. Retrieved October 8, 2019.
* https://docs.microsoft.com/en-us/windows/desktop/api/dpapi/nf-dpapi-cryptunprotectdata - Microsoft. (2018, April 12). CryptUnprotectData function. Retrieved June 18, 2019.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://github.com/putterpanda/mimikittenz - Jamieson O'Reilly (putterpanda). (2016, July 4). mimikittenz. Retrieved June 20, 2019.
* https://labs.sentinelone.com/20-common-tools-techniques-used-by-macos-threat-actors-malware/ - Phil Stokes. (2021, February 16). 20 Common Tools & Techniques Used by macOS Threat Actors & Malware. Retrieved August 23, 2021.
* https://researchcenter.paloaltonetworks.com/2018/07/unit42-new-threat-actor-group-darkhydrus-targets-middle-east-government/ - Falcone, R., et al. (2018, July 27). New Threat Actor Group DarkHydrus Targets Middle East Government. Retrieved August 2, 2018.
* https://securelist.com/evolution-of-jsworm-ransomware/102428/ - Fedor Sinitsyn. (2021, May 25). Evolution of JSWorm Ransomware. Retrieved August 18, 2021.
* https://securelist.com/synack-targeted-ransomware-uses-the-doppelganging-technique/85431/ - Ivanov, A. et al. (2018, May 7). SynAck targeted ransomware uses the Doppelgänging technique. Retrieved May 22, 2018.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://web.archive.org/web/20210708014107/https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.
* https://www.bbc.com/news/technology-60933174 - Joe Tidy. (2022, March 30). Ronin Network: What a $600m hack says about the state of crypto. Retrieved August 18, 2023.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.cisa.gov/sites/default/files/Ransomware_Trifold_e-version.pdf - FBI. (n.d.). Ransomware. Retrieved August 18, 2023.
* https://www.cloudflare.com/learning/email-security/what-is-vendor-email-compromise/#:~:text=Vendor%20email%20compromise%2C%20also%20referred,steal%20from%20that%20vendor%27s%20customers. - CloudFlare. (n.d.). What is vendor email compromise (VEC)?. Retrieved September 12, 2023.
* https://www.crowdstrike.com/blog/big-game-hunting-with-ryuk-another-lucrative-targeted-ransomware/ - Hanel, A. (2019, January 10). Big Game Hunting with Ryuk: Another Lucrative Targeted Ransomware. Retrieved May 12, 2020.
* https://www.crowdstrike.com/blog/double-trouble-ransomware-data-leak-extortion-part-1/ - Crowdstrike. (2020, September 24). Double Trouble: Ransomware with Data Leak Extortion, Part 1. Retrieved December 6, 2023.
* https://www.crowdstrike.com/blog/self-extracting-archives-decoy-files-and-their-hidden-payloads/ - Jai Minton. (2023, March 31). How Falcon OverWatch Investigates Malicious Self-Extracting Archives, Decoy Files and Their Hidden Payloads. Retrieved March 29, 2024.
* https://www.crowdstrike.com/blog/shlayer-malvertising-campaigns-still-using-flash-update-disguise/ - Aspen Lindblom, Joseph Goodwin, and Chris Sheldon. (2021, July 19). Shlayer Malvertising Campaigns Still Using Flash Update Disguise. Retrieved March 29, 2024.
* https://www.cybereason.com/blog/cybereason-vs-darkside-ransomware - Cybereason Nocturnus. (2021, April 1). Cybereason vs. Darkside Ransomware. Retrieved August 18, 2021.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.endgame.com/blog/technical-blog/hunting-memory - Desimone, J. (2017, June 13). Hunting in Memory. Retrieved December 7, 2017.
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process - Hosseini, A. (2017, July 18). Ten Process Injection Techniques: A Technical Survey Of Common And Trending Process Injection Techniques. Retrieved December 7, 2017.
* https://www.f-secure.com/documents/996508/1030745/dukes_whitepaper.pdf - F-Secure Labs. (2015, September 17). The Dukes: 7 years of Russian cyberespionage. Retrieved December 10, 2015.
* https://www.fbi.gov/file-repository/fy-2022-fbi-congressional-report-business-email-compromise-and-real-estate-wire-fraud-111422.pdf/view - FBI. (2022). FBI 2022 Congressional Report on BEC and Real Estate Wire Fraud. Retrieved August 18, 2023.
* https://www.fireeye.com/blog/threat-research/2017/07/hawkeye-malware-distributed-in-phishing-campaign.html - Swapnil Patil, Yogesh Londhe. (2017, July 25). HawkEye Credential Theft Malware Distributed in Recent Phishing Campaign. Retrieved June 18, 2019.
* https://www.ic3.gov/Media/PDF/AnnualReport/2022_IC3Report.pdf - IC3. (2022). 2022 Internet Crime Report. Retrieved August 18, 2023.
* https://www.ired.team/offensive-security/code-injection-process-injection/modulestomping-dll-hollowing-shellcode-injection - Red Teaming Experiments. (n.d.). Module Stomping for Shellcode Injection. Retrieved July 14, 2022.
* https://www.justice.gov/usao-cdca/pr/3-north-korean-military-hackers-indicted-wide-ranging-scheme-commit-cyber-attacks-and - Department of Justice. (2021). 3 North Korean Military Hackers Indicted in Wide-Ranging Scheme to Commit Cyber-attacks and Financial Crimes Across the Globe. Retrieved August 18, 2023.
* https://www.mandiant.com/resources/blog/ransomware-extortion-ot-docs - DANIEL KAPELLMANN ZAFRA, COREY HIDELBRANDT, NATHAN BRUBAKER, KEITH LUNDEN. (2022, January 31). 1 in 7 OT Ransomware Extortion Attacks Leak Critical Operational Technology Information. Retrieved August 18, 2023.
* https://www.nytimes.com/2021/05/13/technology/colonial-pipeline-ransom.html - Nicole Perlroth. (2021, May 13). Colonial Pipeline paid 75 Bitcoin, or roughly $5 million, to hackers.. Retrieved August 18, 2023.
* https://www.proofpoint.com/us/threat-insight/post/new-vega-stealer-shines-brightly-targeted-campaign - Proofpoint. (2018, May 10). New Vega Stealer shines brightly in targeted campaign . Retrieved June 18, 2019.
* https://www.sentinelone.com/blog/trail-osx-fairytale-adware-playing-malware/ - Phile Stokes. (2018, September 20). On the Trail of OSX.FairyTale | Adware Playing at Malware. Retrieved August 24, 2021.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.welivesecurity.com/2009/01/15/malware-trying-to-avoid-some-countries/ - Pierre-Marc Bureau. (2009, January 15). Malware Trying to Avoid Some Countries. Retrieved August 18, 2021.
* https://www.wired.com/story/pig-butchering-fbi-ic3-2022-report/ - Lily Hay Newman. (n.d.). ‘Pig Butchering’ Scams Are Now a $3 Billion Threat. Retrieved August 18, 2023.

# Validate the following tools


# Review the following tool references


# Validate the following malware

* Mispadu - 1

# Review the following malware references

* https://blog.scilabs.mx/en/cyber-threat-profile-malteiro/ - SCILabs. (2021, December 23). Cyber Threat Profile Malteiro. Retrieved March 13, 2024.
* https://blog.scilabs.mx/en/evolution-of-banking-trojan-ursa-mispadu/ - SCILabs. (2023, May 23). Evolution of banking trojan URSA/Mispadu. Retrieved March 13, 2024.
* https://seguranca-informatica.pt/threat-analysis-the-emergent-ursa-trojan-impacts-many-countries-using-a-sophisticated-loader/ - Pedro Tavares (Segurança Informática). (2020, September 15). Threat analysis: The emergent URSA trojan impacts many countries using a sophisticated loader. Retrieved March 13, 2024.
* https://www.welivesecurity.com/2019/11/19/mispadu-advertisement-discounted-unhappy-meal/ - ESET Security. (2019, November 19). Mispadu: Advertisement for a discounted Unhappy Meal. Retrieved March 13, 2024.

