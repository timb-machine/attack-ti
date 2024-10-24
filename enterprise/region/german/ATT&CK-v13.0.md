threat-crank.py 0.2.1
I: searching for regions that match .* german.*
I: using https://raw.githubusercontent.com/mitre/cti/ATT&CK-v13.0/enterprise-attack/enterprise-attack.json
# Threat groups

* CopyKittens
* Earth Lusca
* TA551

# Validate the following attacks

* Archive via Custom Method - 1
* Archive via Utility - 2
* Bypass User Account Control - 1
* Code Signing - 1
* Command Obfuscation - 1
* DCSync - 1
* DLL Side-Loading - 1
* Deobfuscate/Decode Files or Information - 1
* Domain Generation Algorithms - 1
* Domain Trust Discovery - 1
* Domains - 1
* Drive-by Compromise - 1
* Email Addresses - 1
* Exfiltration to Cloud Storage - 1
* Exploit Public-Facing Application - 1
* Exploitation of Remote Services - 1
* Hidden Window - 1
* Ingress Tool Transfer - 1
* JavaScript - 1
* LSASS Memory - 1
* Malicious File - 2
* Malicious Link - 1
* Malware - 1
* Masquerading - 1
* Match Legitimate Name or Location - 1
* Modify Registry - 1
* Mshta - 2
* Obfuscated Files or Information - 1
* PowerShell - 2
* Print Processors - 1
* Process Discovery - 1
* Proxy - 2
* Python - 1
* Regsvr32 - 1
* Remote System Discovery - 1
* Rundll32 - 2
* SSH Authorized Keys - 1
* Scheduled Task/Job - 1
* Server - 2
* Spearphishing Attachment - 1
* Spearphishing Link - 1
* Standard Encoding - 1
* Steganography - 2
* System Network Configuration Discovery - 1
* System Network Connections Discovery - 1
* System Owner/User Discovery - 1
* System Service Discovery - 1
* Tool - 2
* Upload Malware - 1
* Visual Basic - 1
* Vulnerability Scanning - 1
* Web Protocols - 1
* Web Services - 2
* Windows Command Shell - 1
* Windows Management Instrumentation - 1
* Windows Service - 1

# Validate the following phases

* collection - 3
* command-and-control - 6
* credential-access - 2
* defense-evasion - 17
* discovery - 7
* execution - 11
* exfiltration - 1
* initial-access - 4
* lateral-movement - 1
* persistence - 5
* privilege-escalation - 5
* reconnaissance - 2
* resource-development - 9

# Validate the following platforms

* Containers - 4
* Google Workspace - 1
* IaaS - 3
* Linux - 42
* Network - 9
* Office 365 - 1
* PRE - 11
* SaaS - 2
* Windows - 69
* macOS - 42

# Validate the following defences

* Anti-virus - 5
* Application Control - 4
* Application control - 5
* Digital Certificate Validation - 5
* Host Forensic Analysis - 1
* Host Intrusion Prevention Systems - 2
* Host forensic analysis - 1
* Log Analysis - 1
* Network Intrusion Detection System - 1
* Signature-based Detection - 2
* Windows User Account Control - 2

# Validate the following data sources

* Active Directory: Active Directory Object Access - 2
* Application Log: Application Log Content - 5
* Command: Command Execution - 32
* Container: Container Creation - 1
* Domain Name: Active DNS - 1
* Domain Name: Domain Registration - 1
* Domain Name: Passive DNS - 1
* Driver: Driver Load - 2
* File: File Access - 3
* File: File Creation - 15
* File: File Metadata - 9
* File: File Modification - 6
* Image: Image Metadata - 2
* Internet Scan: Response Content - 5
* Internet Scan: Response Metadata - 2
* Malware Repository: Malware Content - 1
* Malware Repository: Malware Metadata - 3
* Module: Module Load - 10
* Network Traffic: Network Connection Creation - 11
* Network Traffic: Network Traffic Content - 17
* Network Traffic: Network Traffic Flow - 11
* Process: OS API Execution - 11
* Process: Process Access - 2
* Process: Process Creation - 34
* Process: Process Metadata - 5
* Scheduled Job: Scheduled Job Creation - 1
* Scheduled Job: Scheduled Job Metadata - 1
* Scheduled Job: Scheduled Job Modification - 1
* Script: Script Execution - 11
* Service: Service Creation - 2
* Service: Service Metadata - 1
* Service: Service Modification - 1
* WMI: WMI Creation - 1
* Windows Registry: Windows Registry Key Access - 1
* Windows Registry: Windows Registry Key Creation - 3
* Windows Registry: Windows Registry Key Deletion - 1
* Windows Registry: Windows Registry Key Modification - 4

# Review the following attack references

* http://blog.shadowserver.org/2012/05/15/cyber-espionage-strategic-web-compromises-trusted-websites-serving-dangerous-results/ - Adair, S., Moran, N. (2012, May 15). Cyber Espionage & Strategic Web Compromises – Trusted Websites Serving Dangerous Results. Retrieved March 13, 2018.
* http://blog.talosintelligence.com/2017/09/avast-distributes-malware.html - Brumaghin, E. et al. (2017, September 18). CCleanup: A Vast Number of Machines at Risk. Retrieved March 9, 2018.
* http://blog.trendmicro.com/trendlabs-security-intelligence/in-depth-look-apt-attack-tools-of-the-trade/ - Wilhoit, K. (2013, March 4). In-Depth Look: APT Attack Tools of the Trade. Retrieved December 2, 2015.
* http://cdn0.vox-cdn.com/assets/4589853/crowdstrike-intelligence-report-putter-panda.original.pdf - Crowdstrike Global Intelligence Team. (2014, June 9). CrowdStrike Intelligence Report: Putter Panda. Retrieved January 22, 2016.
* http://csis.pace.edu/~ctappert/srd2017/2017PDF/d4.pdf - Chen, L., Wang, T.. (2017, May 5). Detecting Algorithmically Generated Domains Using Data Visualization and N-Grams Methods . Retrieved April 26, 2019.
* http://docplayer.net/20839173-Analysis-of-malicious-security-support-provider-dlls.html - Graeber, M. (2014, October). Analysis of Malicious Security Support Provider DLLs. Retrieved March 1, 2017.
* http://go.cybereason.com/rs/996-YZT-709/images/Cybereason-Lab-Analysis-Dissecting-DGAs-Eight-Real-World-DGA-Variants.pdf - Sternfeld, U. (2016). Dissecting Domain Generation Algorithms: Eight Real World DGA Variants. Retrieved February 18, 2019.
* http://pages.endgame.com/rs/627-YBU-612/images/EndgameJournal_The%20Masquerade%20Ball_Pages_R2.pdf - Ewing, P. (2016, October 31). How to Hunt: The Masquerade Ball. Retrieved October 31, 2016.
* http://pen-testing.sans.org/blog/pen-testing/2013/08/08/psexec-uac-bypass - Medin, T. (2013, August 8). PsExec UAC Bypass. Retrieved June 3, 2016.
* http://www.harmj0y.net/blog/redteaming/mimikatz-and-dcsync-and-extrasids-oh-my/ - Schroeder, W. (2015, September 22). Mimikatz and DCSync and ExtraSids, Oh My. Retrieved December 4, 2017.
* http://www.malwarearchaeology.com/s/Windows-PowerShell-Logging-Cheat-Sheet-ver-June-2016-v2.pdf - Malware Archaeology. (2016, June). WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later. Retrieved June 24, 2016.
* http://www.pretentiousname.com/misc/win7_uac_whitelist2.html - Davidson, L. (n.d.). Windows 7 UAC whitelist. Retrieved November 12, 2014.
* http://www.symantec.com/connect/blogs/how-attackers-steal-private-keys-digital-certificates - Shinotsuka, H. (2013, February 22). How Attackers Steal Private Keys from Digital Certificates. Retrieved March 31, 2016.
* http://www.welivesecurity.com/wp-content/uploads/2016/10/eset-sednit-part-2.pdf - ESET. (2016, October). En Route with Sednit - Part 2: Observing the Comings and Goings. Retrieved November 21, 2016.
* https://about.gitlab.com/blog/2020/02/12/plundering-gcp-escalating-privileges-in-google-cloud-platform/ - Chris Moberly. (2020, February 12). Tutorial on privilege escalation and post exploitation tactics in Google Cloud Platform environments. Retrieved April 1, 2022.
* https://adsecurity.org/?p=1588 - Metcalf, S. (2015, July 15). It’s All About Trust – Forging Kerberos Trust Tickets to Spoof Access across Active Directory Trusts. Retrieved February 14, 2019.
* https://adsecurity.org/?p=1729 - Metcalf, S. (2015, September 25). Mimikatz DCSync Usage, Exploitation, and Detection. Retrieved December 4, 2017.
* https://airbus-cyber-security.com/fileless-malware-behavioural-analysis-kovter-persistence/ - Dove, A. (2016, March 23). Fileless Malware – A Behavioural Analysis Of Kovter Persistence. Retrieved December 5, 2017.
* https://arxiv.org/ftp/arxiv/papers/1408/1408.1136.pdf - Gardiner, J.,  Cova, M., Nagaraja, S. (2014, February). Command & Control Understanding, Denying and Detecting. Retrieved April 20, 2016.
* https://arxiv.org/pdf/1611.00791.pdf - Ahuja, A., Anderson, H., Grant, D., Woodbridge, J.. (2016, November 2). Predicting Domain Generation Algorithms with Long Short-Term Memory Networks. Retrieved April 26, 2019.
* https://bashfuscator.readthedocs.io/en/latest/Mutators/command_obfuscators/index.html - LeFevre, A. (n.d.). Bashfuscator Command Obfuscators. Retrieved March 17, 2023.
* https://blog.fortinet.com/2016/12/16/malicious-macro-bypasses-uac-to-elevate-privilege-for-fareit-malware - Salvio, J., Joven, R. (2016, December 16). Malicious Macro Bypasses UAC to Elevate Privilege for Fareit Malware. Retrieved December 27, 2016.
* https://blog.malwarebytes.com/cybercrime/social-engineering-cybercrime/2017/03/new-targeted-attack-saudi-arabia-government/ - Malwarebytes Labs. (2017, March 27). New targeted attack against Saudi Arabia Government. Retrieved July 3, 2017.
* https://blog.malwarebytes.com/threat-analysis/2017/01/new-mac-backdoor-using-antiquated-code/ - Thomas Reed. (2017, January 18). New Mac backdoor using antiquated code. Retrieved July 5, 2017.
* https://blog.stealthbits.com/manipulating-user-passwords-with-mimikatz-SetNTLM-ChangeNTLM - Warren, J. (2017, July 11). Manipulating User Passwords with Mimikatz. Retrieved December 4, 2017.
* https://blog.talosintelligence.com/2021/05/transparent-tribe-infra-and-targeting.html - Malhotra, A., McKay, K. et al. (2021, May 13). Transparent Tribe APT expands its Windows malware arsenal . Retrieved July 29, 2022.
* https://blog.talosintelligence.com/2022/03/transparent-tribe-new-campaign.html - Malhotra, A., Thattil, J. et al. (2022, March 29). Transparent Tribe campaign uses new bespoke malware to target Indian government officials . Retrieved September 6, 2022.
* https://blog.talosintelligence.com/ipfs-abuse/ - Edmund Brumaghin. (2022, November 9). Threat Spotlight: Cyber Criminal Adoption of IPFS for Phishing, Malware Campaigns. Retrieved March 8, 2023.
* https://blog.trendmicro.com/trendlabs-security-intelligence/pawn-storm-abuses-open-authentication-advanced-social-engineering-attacks - Hacquebord, F.. (2017, April 25). Pawn Storm Abuses Open Authentication in Advanced Social Engineering Attacks. Retrieved October 4, 2019.
* https://blog.trendmicro.com/trendlabs-security-intelligence/poweliks-malware-hides-in-windows-registry/ - Santos, R. (2014, August 1). POWELIKS: Malware Hides In Windows Registry. Retrieved August 9, 2018.
* https://blogs.akamai.com/2018/01/a-death-match-of-domain-generation-algorithms.html - Liu, H. and Yuzifovich, Y. (2018, January 9). A Death Match of Domain Generation Algorithms. Retrieved February 18, 2019.
* https://blogs.msdn.microsoft.com/kebab/2014/04/28/executing-powershell-scripts-from-c/ - Babinec, K. (2014, April 28). Executing PowerShell scripts from C#. Retrieved April 22, 2019.
* https://blogs.technet.microsoft.com/askpfeplat/2016/04/18/the-importance-of-kb2871997-and-kb2928120-for-credential-protection/ - Wilson, B. (2016, April 18). The Importance of KB2871997 and KB2928120 for Credential Protection. Retrieved April 11, 2018.
* https://bromiley.medium.com/malware-monday-vbscript-and-vbe-files-292252c1a16 - Bromiley, M. (2016, December 27). Malware Monday: VBScript and VBE Files. Retrieved March 17, 2023.
* https://cloud.google.com/sdk/gcloud/reference/compute/instances/add-metadata - Google Cloud. (2022, March 31). gcloud compute instances add-metadata. Retrieved April 1, 2022.
* https://cloud.google.com/vpc/docs/vpc - Google. (2019, September 23). Virtual Private Cloud (VPC) network overview. Retrieved October 6, 2019.
* https://community.cisco.com/t5/security-blogs/attackers-continue-to-target-legacy-devices/ba-p/4169954 - Omar Santos. (2020, October 19). Attackers Continue to Target Legacy Devices. Retrieved October 20, 2020.
* https://cwe.mitre.org/top25/index.html - Christey, S., Brown, M., Kirby, D., Martin, B., Paller, A.. (2011, September 13). 2011 CWE/SANS Top 25 Most Dangerous Software Errors. Retrieved April 10, 2019.
* https://datadrivensecurity.info/blog/posts/2014/Oct/dga-part2/ - Jacobs, J. (2014, October 2). Building a DGA Classifier: Part 2, Feature Engineering. Retrieved February 18, 2019.
* https://devblogs.microsoft.com/vbteam/visual-basic-support-planned-for-net-5-0/ - .NET Team. (2020, March 11). Visual Basic support planned for .NET 5.0. Retrieved June 23, 2020.
* https://developer.apple.com/library/archive/documentation/LanguagesUtilities/Conceptual/MacAutomationScriptingGuide/index.html - Apple. (2016, June 13). About Mac Scripting. Retrieved April 14, 2021.
* https://docs.aws.amazon.com/vpc/latest/userguide/what-is-amazon-vpc.html - Amazon. (n.d.). What Is Amazon VPC?. Retrieved October 6, 2019.
* https://docs.docker.com/engine/reference/commandline/images/ - Docker. (n.d.). Docker Images. Retrieved April 6, 2021.
* https://docs.microsoft.com/archive/blogs/gauravseth/the-world-of-jscript-javascript-ecmascript - Microsoft. (2007, August 15). The World of JScript, JavaScript, ECMAScript …. Retrieved June 23, 2020.
* https://docs.microsoft.com/dotnet/visual-basic/ - Microsoft. (n.d.). Visual Basic documentation. Retrieved June 23, 2020.
* https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-overview - Annamalai, N., Casey, C., Almeida, M., et. al.. (2019, June 18). What is Azure Virtual Network?. Retrieved October 6, 2019.
* https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.domain.getalltrustrelationships?redirectedfrom=MSDN&view=netframework-4.7.2#System_DirectoryServices_ActiveDirectory_Domain_GetAllTrustRelationships - Microsoft. (n.d.). Domain.GetAllTrustRelationships Method. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/anti-spoofing-protection?view=o365-worldwide - Microsoft. (2020, October 13). Anti-spoofing protection in EOP. Retrieved October 19, 2020.
* https://docs.microsoft.com/en-us/powershell/module/Microsoft.PowerShell.Core/About/about_PowerShell_exe?view=powershell-5.1 - Wheeler, S. et al.. (2019, May 1). About PowerShell.exe. Retrieved October 11, 2019.
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc759554(v=ws.10) - Microsoft. (2009, October 7). Trust Technologies. Retrieved February 14, 2019.
* https://docs.microsoft.com/en-us/rest/api/compute/virtual-machines/update - Microsoft. (n.d.). Virtual Machines - Update. Retrieved April 1, 2022.
* https://docs.microsoft.com/en-us/sysinternals/downloads/regdelnull - Russinovich, M. & Sharkey, K. (2016, July 4). RegDelNull v1.11. Retrieved August 10, 2018.
* https://docs.microsoft.com/en-us/windows/terminal/tutorials/ssh - Microsoft. (2020, May 19). Tutorial: SSH in Windows Terminal. Retrieved July 26, 2021.
* https://docs.microsoft.com/en-us/windows/win32/printdocs/addprintprocessor - Microsoft. (2018, May 31). AddPrintProcessor function. Retrieved October 5, 2020.
* https://docs.microsoft.com/office/vba/api/overview/ - Microsoft. (2019, June 11). Office VBA Reference. Retrieved June 23, 2020.
* https://docs.microsoft.com/previous-versions//1kw29xwf(v=vs.85) - Microsoft. (2011, April 19). What Is VBScript?. Retrieved March 28, 2020.
* https://docs.microsoft.com/scripting/winscript/windows-script-interfaces - Microsoft. (2017, January 18). Windows Script Interfaces. Retrieved June 23, 2020.
* https://docs.microsoft.com/sysinternals/downloads/reghide - Russinovich, M. & Sharkey, K. (2006, January 10). Reghide. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4657 - Miroshnikov, A. & Hall, J. (2017, April 18). 4657(S): A registry value was modified. Retrieved August 9, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/auditing/event-4697 - Miroshnikov, A. & Hall, J. (2017, April 18). 4697(S): A service was installed in the system. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/security/threat-protection/use-windows-event-forwarding-to-assist-in-intrusion-detection - Hardy, T. & Hall, J. (2018, February 15). Use Windows Event Forwarding to help with intrusion detection. Retrieved August 7, 2018.
* https://docs.microsoft.com/windows/win32/com/translating-to-jscript - Microsoft. (2018, May 31). Translating to JScript. Retrieved June 23, 2020.
* https://eclecticlight.co/2020/11/16/checks-on-executable-code-in-catalina-and-big-sur-a-first-draft/ - Howard Oakley. (2020, November 16). Checks on executable code in Catalina and Big Sur: a first draft. Retrieved September 21, 2022.
* https://en.wikipedia.org/wiki/Binary-to-text_encoding - Wikipedia. (2016, December 26). Binary-to-text encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Character_encoding - Wikipedia. (2017, February 19). Character Encoding. Retrieved March 1, 2017.
* https://en.wikipedia.org/wiki/Code_signing - Wikipedia. (2015, November 10). Code Signing. Retrieved March 31, 2016.
* https://en.wikipedia.org/wiki/Duqu - Wikipedia. (2017, December 29). Duqu. Retrieved April 10, 2018.
* https://en.wikipedia.org/wiki/HTML_Application - Wikipedia. (2017, October 14). HTML Application. Retrieved October 27, 2017.
* https://en.wikipedia.org/wiki/List_of_file_signatures - Wikipedia. (2016, March 31). List of file signatures. Retrieved April 22, 2016.
* https://en.wikipedia.org/wiki/Visual_Basic_for_Applications - Wikipedia. (n.d.). Visual Basic for Applications. Retrieved August 13, 2020.
* https://enigma0x3.net/2016/08/15/fileless-uac-bypass-using-eventvwr-exe-and-registry-hijacking/ - Nelson, M. (2016, August 15). "Fileless" UAC Bypass using eventvwr.exe and Registry Hijacking. Retrieved December 27, 2016.
* https://enigma0x3.net/2017/03/14/bypassing-uac-using-app-paths/ - Nelson, M. (2017, March 14). Bypassing UAC using App Paths. Retrieved May 25, 2017.
* https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/ - Nelson, M. (2017, March 17). "Fileless" UAC Bypass Using sdclt.exe. Retrieved May 25, 2017.
* https://github.com/danielbohannon/Invoke-DOSfuscation - Bohannon, D. (2018, March 19). Invoke-DOSfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Invoke-Obfuscation - Bohannon, D. (2016, September 24). Invoke-Obfuscation. Retrieved March 17, 2023.
* https://github.com/danielbohannon/Revoke-Obfuscation - Bohannon, D. (2017, July 27). Revoke-Obfuscation. Retrieved February 12, 2018.
* https://github.com/gentilkiwi/mimikatz/wiki/module-~-lsadump - Deply, B., Le Toux, V. (2016, June 5). module ~ lsadump. Retrieved August 7, 2017.
* https://github.com/gremwell/o365enum - gremwell. (2020, March 24). Office 365 User Enumeration. Retrieved May 27, 2022.
* https://github.com/gtworek/PSBits/tree/master/NoRunDll - gtworek. (2019, December 17). NoRunDll. Retrieved August 23, 2021.
* https://github.com/hfiref0x/UACME - UACME Project. (2016, June 16). UACMe. Retrieved July 26, 2016.
* https://github.com/itsreallynick/office-crackros - Carr, N. (2016, August 14). OfficeCrackros. Retrieved February 12, 2018.
* https://github.com/jaredhaight/PSAttack - Haight, J. (2016, April 21). PS>Attack. Retrieved June 1, 2016.
* https://github.com/mattifestation/PowerSploit - PowerSploit. (n.d.). Retrieved December 4, 2014.
* https://grimhacker.com/2017/07/24/office365-activesync-username-enumeration/ - GrimHacker. (2017, July 24). Office365 ActiveSync Username Enumeration. Retrieved December 9, 2021.
* https://krebsonsecurity.com/2018/11/that-domain-you-forgot-to-renew-yeah-its-now-stealing-credit-cards/ - Krebs, B. (2018, November 13). That Domain You Forgot to Renew? Yeah, it’s Now Stealing Credit Cards. Retrieved September 20, 2019.
* https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedcommand-base64encodedcommand - Microsoft. (2023, February 8). about_PowerShell_exe: EncodedCommand. Retrieved March 17, 2023.
* https://lolbas-project.github.io/ - LOLBAS. (n.d.). Living Off The Land Binaries and Scripts (and also Libraries). Retrieved February 10, 2020.
* https://lolbas-project.github.io/#t1105 - LOLBAS. (n.d.). LOLBAS Mapped to T1105. Retrieved March 11, 2022.
* https://lolbas-project.github.io/lolbas/Binaries/Diantz/ - Living Off The Land Binaries, Scripts and Libraries (LOLBAS). (n.d.). Diantz.exe. Retrieved October 25, 2021.
* https://lolbas-project.github.io/lolbas/Binaries/Mshta/ - LOLBAS. (n.d.). Mshta.exe. Retrieved July 31, 2019.
* https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/ - LOLBAS. (n.d.). Regsvr32.exe. Retrieved July 31, 2019.
* https://medium.com/threatpunter/detecting-attempts-to-steal-passwords-from-memory-558f16dce4ea - French, D. (2018, October 2). Detecting Attempts to Steal Passwords from Memory. Retrieved October 11, 2019.
* https://michaelkoczwara.medium.com/cobalt-strike-c2-hunting-with-shodan-c448d501a6e2 - Koczwara, M. (2021, September 7). Hunting Cobalt Strike C2 with Shodan. Retrieved October 12, 2021.
* https://msdn.microsoft.com/en-us/library/aa394582.aspx - Microsoft. (n.d.). Windows Management Instrumentation. Retrieved April 27, 2016.
* https://msdn.microsoft.com/en-us/library/ms679687.aspx - Microsoft. (n.d.). The COM Elevation Moniker. Retrieved July 26, 2016.
* https://msdn.microsoft.com/library/cc228086.aspx - Microsoft. (2017, December 1). MS-DRSR Directory Replication Service (DRS) Remote Protocol. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/cc237008.aspx - Microsoft. (2017, December 1). MS-NRPC - Netlogon Remote Protocol. Retrieved December 6, 2017.
* https://msdn.microsoft.com/library/cc245496.aspx - Microsoft. (n.d.). MS-SAMR Security Account Manager (SAM) Remote Protocol (Client-to-Server) - Transport. Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/dd207691.aspx - Microsoft. (n.d.). IDL_DRSGetNCChanges (Opnum 3). Retrieved December 4, 2017.
* https://msdn.microsoft.com/library/ms536471.aspx - Microsoft. (n.d.). HTML Applications. Retrieved October 27, 2017.
* https://nodejs.org/ - OpenJS Foundation. (n.d.). Node.js. Retrieved June 23, 2020.
* https://nvd.nist.gov/vuln/detail/CVE-2014-7169 - National Vulnerability Database. (2017, September 24). CVE-2014-7169 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2016-6662 - National Vulnerability Database. (2017, February 2). CVE-2016-6662 Detail. Retrieved April 3, 2018.
* https://nvd.nist.gov/vuln/detail/CVE-2017-0176 - National Vulnerability Database. (2017, June 22). CVE-2017-0176 Detail. Retrieved April 3, 2018.
* https://o365blog.com/post/just-looking/ - Dr. Nestori Syynimaa. (2020, June 13). Just looking: Azure Active Directory reconnaissance as an outsider. Retrieved May 27, 2022.
* https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-014_Vulnerability_Scanning - OWASP. (n.d.). OAT-014 Vulnerability Scanning. Retrieved October 20, 2020.
* https://posts.specterops.io/a-guide-to-attacking-domain-trusts-971e52cb2944 - Schroeder, W. (2017, October 30). A Guide to Attacking Domain Trusts. Retrieved February 14, 2019.
* https://posts.specterops.io/hiding-registry-keys-with-psreflect-b18ec5ac8353 - Reitz, B. (2017, July 14). Hiding Registry keys with PSReflect. Retrieved August 9, 2018.
* https://posts.specterops.io/persistent-jxa-66e1c3cd1cf5 - Pitt, L. (2020, August 6). Persistent JXA. Retrieved April 14, 2021.
* https://powershellmagazine.com/2014/07/16/investigating-powershell-attacks/ - Hastings, M. (2014, July 16). Investigating PowerShell Attacks. Retrieved December 1, 2021.
* https://redcanary.com/blog/clipping-silver-sparrows-wings/ - Tony Lambert. (2021, February 18). Clipping Silver Sparrow’s wings: Outing macOS malware before it takes flight. Retrieved April 20, 2021.
* https://redcanary.com/threat-detection-report/techniques/powershell/ - Red Canary. (n.d.). 2022 Threat Detection Report: PowerShell. Retrieved March 17, 2023.
* https://researchcenter.paloaltonetworks.com/2017/03/unit42-pulling-back-the-curtains-on-encodedcommand-powershell-attacks/ - White, J. (2017, March 10). Pulling Back the Curtains on EncodedCommand PowerShell Attacks. Retrieved February 12, 2018.
* https://s7d2.scene7.com/is/content/cylance/prod/cylance-web/en-us/resources/knowledge-center/resource-library/reports/Op_Dust_Storm_Report.pdf - Gross, J. (2016, February 23). Operation Dust Storm. Retrieved December 22, 2021.
* https://securelist.com/why-you-shouldnt-completely-trust-files-signed-with-digital-certificates/68593/ - Ladikov, A. (2015, January 29). Why You Shouldn’t Completely Trust Files Signed with Digital Certificates. Retrieved March 31, 2016.
* https://securingtomorrow.mcafee.com/mcafee-labs/malicious-document-targets-pyeongchang-olympics/ - Saavedra-Morales, J., Sherstobitoff, R. (2018, January 6). Malicious Document Targets Pyeongchang Olympics. Retrieved April 10, 2018.
* https://securityintelligence.com/posts/brazking-android-malware-upgraded-targeting-brazilian-banks/ - Shahar Tavor. (n.d.). BrazKing Android Malware Upgraded and Targeting Brazilian Banks. Retrieved March 24, 2023.
* https://source.winehq.org/WineAPI/samlib.html - Wine API. (n.d.). samlib.dll. Retrieved December 4, 2017.
* https://support.microsoft.com/en-us/kb/249873 - Microsoft. (2015, August 14). How to use the Regsvr32 tool and troubleshoot Regsvr32 error messages. Retrieved June 22, 2016.
* https://symantec.broadcom.com/hubfs/Attacks-Against-Government-Sector.pdf - Symantec. (2021, June 10). Attacks Against the Government Sector. Retrieved September 28, 2021.
* https://techcommunity.microsoft.com/t5/microsoft-365-blog/helping-users-stay-safe-blocking-internet-macros-by-default-in/ba-p/3071805 - Kellie Eickmeyer. (2022, February 7). Helping users stay safe: Blocking internet macros by default in Office. Retrieved February 7, 2022.
* https://technet.microsoft.com/en-US/magazine/2009.07.uac.aspx - Russinovich, M. (2009, July). User Account Control: Inside Windows 7 User Account Control. Retrieved July 26, 2016.
* https://technet.microsoft.com/en-us/itpro/windows/keep-secure/how-user-account-control-works - Lich, B. (2016, May 31). How User Account Control Works. Retrieved June 3, 2016.
* https://technet.microsoft.com/en-us/library/cc732643.aspx - Microsoft. (2012, April 17). Reg. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc754820.aspx - Microsoft. (n.d.). Enable the Remote Registry Service. Retrieved May 1, 2015.
* https://technet.microsoft.com/en-us/library/cc772408.aspx - Microsoft. (n.d.). Services. Retrieved June 7, 2016.
* https://technet.microsoft.com/en-us/library/cc785125.aspx - Microsoft. (2005, January 21). Task Scheduler and security. Retrieved June 8, 2016.
* https://technet.microsoft.com/en-us/scriptcenter/dd742419.aspx - Microsoft. (n.d.). Windows PowerShell Scripting. Retrieved April 28, 2016.
* https://technet.microsoft.com/en-us/sysinternals/bb963902 - Russinovich, M. (2016, January 4). Autoruns for Windows v13.51. Retrieved June 6, 2016.
* https://thisissecurity.stormshield.com/2014/08/20/poweliks-command-line-confusion/ - B. Ancel. (2014, August 20). Poweliks – Command Line Confusion. Retrieved March 5, 2018.
* https://threatconnect.com/blog/infrastructure-research-hunting/ - ThreatConnect. (2020, December 15). Infrastructure Research and Hunting: Boiling the Domain Ocean. Retrieved October 12, 2021.
* https://twitter.com/ItsReallyNick/status/1055321652777619457 - Carr, N.. (2018, October 25). Nick Carr Status Update Masquerading. Retrieved April 22, 2019.
* https://twitter.com/rfackroyd/status/1639136000755765254 - Ackroyd, R. (2023, March 24). Twitter. Retrieved March 24, 2023.
* https://umbrella.cisco.com/blog/2016/10/10/domain-generation-algorithms-effective/ - Scarfo, A. (2016, October 10). Domain Generation Algorithms – Why so effective?. Retrieved February 18, 2019.
* https://unit42.paloaltonetworks.com/acidbox-rare-malware/ - Reichel, D. and Idrizovic, E. (2020, June 17). AcidBox: Rare Malware Repurposing Turla Group Exploit Targeted Russian Organizations. Retrieved March 16, 2021.
* https://unit42.paloaltonetworks.com/threat-brief-understanding-domain-generation-algorithms-dga/ - Unit 42. (2019, February 7). Threat Brief: Understanding Domain Generation Algorithms (DGA). Retrieved February 19, 2019.
* https://us-cert.cisa.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://us-cert.cisa.gov/ncas/alerts/aa20-258a - CISA. (2020, September 14). Alert (AA20-258A): Chinese Ministry of State Security-Affiliated Cyber Threat Actor Activity. Retrieved October 1, 2020.
* https://us-cert.cisa.gov/ncas/analysis-reports/ar21-126a - CISA. (2021, May 6). Analysis Report (AR21-126A) FiveHands Ransomware. Retrieved June 7, 2021.
* https://us-cert.cisa.gov/ncas/tips/ST05-016 - CISA. (2019, September 27). Security Tip (ST05-016): Understanding Internationalized Domain Names. Retrieved October 20, 2020.
* https://web.archive.org/web/20151022204649/https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-apt28.pdf - FireEye. (2015). APT28: A WINDOW INTO RUSSIA’S CYBER ESPIONAGE OPERATIONS?. Retrieved August 19, 2015.
* https://web.archive.org/web/20160327101330/http://www.sixdub.net/?p=367 - Warner, J.. (2015, January 6). Inexorable PowerShell – A Red Teamer’s Tale of Overcoming Simple AppLocker Policies. Retrieved December 8, 2018.
* https://web.archive.org/web/20170923102302/https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html - Bohannon, D. & Carr N. (2017, June 30). Obfuscation in the Wild: Targeted Attackers Lead the Way in Evasion Techniques. Retrieved February 12, 2018.
* https://web.archive.org/web/20171223000420/https://www.riskiq.com/blog/labs/lazarus-group-cryptocurrency/ - RISKIQ. (2017, December 20). Mining Insights: Infrastructure Analysis of Lazarus Group Cyber Attacks on the Cryptocurrency Industry. Retrieved July 29, 2022.
* https://web.archive.org/web/20190508170150/https://silentbreaksecurity.com/powershell-jobs-without-powershell-exe/ - Christensen, L.. (2015, December 28). The Evolution of Offensive PowerShell Invocation. Retrieved December 8, 2018.
* https://web.archive.org/web/20220527112908/https://www.riskiq.com/blog/labs/ukraine-malware-infrastructure/ - RISKIQ. (2022, March 15). RiskIQ Threat Intelligence Roundup: Campaigns Targeting Ukraine and Global Malware Infrastructure. Retrieved July 29, 2022.
* https://wiki.samba.org/index.php/DRSUAPI - SambaWiki. (n.d.). DRSUAPI. Retrieved December 4, 2017.
* https://www.7-zip.org/ - I. Pavlov. (2019). 7-Zip. Retrieved February 20, 2020.
* https://www.akamai.com/blog/security/catch-me-if-you-can-javascript-obfuscation - Katz, O. (2020, October 26). Catch Me if You Can—JavaScript Obfuscation. Retrieved March 17, 2023.
* https://www.attackify.com/blog/rundll32_execution_order/ - Attackify. (n.d.). Rundll32.exe Obscurity. Retrieved August 23, 2021.
* https://www.blackhillsinfosec.com/bypass-web-proxy-filtering/ - Fehrman, B. (2017, April 13). How to Bypass Web-Proxy Filtering. Retrieved September 20, 2019.
* https://www.bleepingcomputer.com/news/security/psa-dont-open-spam-containing-password-protected-word-docs/ - Lawrence Abrams. (2017, July 12). PSA: Don't Open SPAM Containing Password Protected Word Docs. Retrieved January 5, 2022.
* https://www.carbonblack.com/2016/04/28/threat-advisory-squiblydoo-continues-trend-of-attackers-using-native-os-tools-to-live-off-the-land/ - Nolen, R. et al.. (2016, April 28). Threat Advisory: “Squiblydoo” Continues Trend of Attackers Using Native OS Tools to “Live off the Land”. Retrieved April 9, 2018.
* https://www.carbonblack.com/2016/09/23/security-advisory-variants-well-known-adware-families-discovered-include-sophisticated-obfuscation-techniques-previously-associated-nation-state-attacks/ - Tedesco, B. (2016, September 23). Security Alert Summary. Retrieved February 12, 2018.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/fundamentals/command/cf_command_ref/show_monitor_permit_list_through_show_process_memory.html#wp3599497760 - Cisco. (2022, August 16). show processes - . Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d1/sec-d1-cr-book/sec-cr-i3.html#wp1254331478 - Cisco. (2021, August 23). ip ssh pubkey-chain. Retrieved July 13, 2022.
* https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s1/sec-s1-cr-book/sec-cr-s5.html - Cisco. (2023, March 7). Cisco IOS Security Command Reference: Commands S to Z . Retrieved July 13, 2022.
* https://www.cisecurity.org/advisory/multiple-vulnerabilities-in-microsoft-windows-smb-server-could-allow-for-remote-code-execution/ - CIS. (2017, May 15). Multiple Vulnerabilities in Microsoft Windows SMB Server Could Allow for Remote Code Execution. Retrieved April 3, 2018.
* https://www.cnet.com/news/massive-breach-leaks-773-million-emails-21-million-passwords/ - Ng, A. (2019, January 17). Massive breach leaks 773 million email addresses, 21 million passwords. Retrieved October 20, 2020.
* https://www.cobaltstrike.com/blog/high-reputation-redirectors-and-domain-fronting/ - Mudge, R. (2017, February 6). High-reputation Redirectors and Domain Fronting. Retrieved July 11, 2022.
* https://www.crowdstrike.com/blog/how-crowdstrike-falcon-protects-against-wiper-malware-used-in-ukraine-attacks/ - Thomas, W. et al. (2022, February 25). CrowdStrike Falcon Protects from New Wiper Malware Used in Ukraine Cyberattacks. Retrieved March 25, 2022.
* https://www.cyber.gov.au/sites/default/files/2019-03/spoof_email_sender_policy_framework.pdf - Australian Cyber Security Centre. (2012, December). Mitigating Spoofed Emails Using Sender Policy Framework. Retrieved October 19, 2020.
* https://www.cybereason.com/blog/new-pervasive-worm-exploiting-linux-exim-server-vulnerability - Cybereason Nocturnus. (2019, June 13). New Pervasive Worm Exploiting Linux Exim Server Vulnerability. Retrieved June 24, 2020.
* https://www.cynet.com/attack-techniques-hands-on/defense-evasion-techniques/ - Ariel silver. (2022, February 1). Defense Evasion Techniques. Retrieved April 8, 2022.
* https://www.elastic.co/blog/embracing-offensive-tooling-building-detections-against-koadic-using-eql - Stepanic, D.. (2020, January 13). Embracing offensive tooling: Building detections against Koadic using EQL. Retrieved November 30, 2020.
* https://www.fireeye.com/blog/threat-research/2016/02/greater_visibilityt.html - Dunwoody, M. (2016, February 11). GREATER VISIBILITY THROUGH POWERSHELL LOGGING. Retrieved February 16, 2016.
* https://www.fireeye.com/blog/threat-research/2017/02/spear_phishing_techn.html - Anubhav, A., Kizhakkinan, D. (2017, February 22). Spear Phishing Techniques Used in Attacks Targeting the Mongolian Government. Retrieved February 24, 2017.
* https://www.fireeye.com/blog/threat-research/2017/03/dissecting_one_ofap.html - Dunwoody, M.. (2017, April 3). Dissecting One of APT29’s Fileless WMI and PowerShell Backdoors (POSHSPY). Retrieved April 5, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/cve-2017-0199-hta-handler.html - Berry, A., Galang, L., Jiang, G., Leathery, J., Mohandas, R. (2017, April 11). CVE-2017-0199: In the Wild Attacks Leveraging HTA Handler. Retrieved October 27, 2017.
* https://www.fireeye.com/blog/threat-research/2017/04/fin7-phishing-lnk.html - Carr, N., et al. (2017, April 24). FIN7 Evolution and the Phishing LNK. Retrieved April 24, 2017.
* https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/revoke-obfuscation-report.pdf - Bohannon, D. & Holmes, L. (2017, July 27). Revoke-Obfuscation: PowerShell Obfuscation Detection Using Science. Retrieved February 12, 2018.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/rpt-dll-sideloading.pdf - Amanda Steward. (2014). FireEye DLL Side-Loading: A Thorn in the Side of the Anti-Virus Industry. Retrieved March 13, 2020.
* https://www.fireeye.com/content/dam/fireeye-www/global/en/current-threats/pdfs/wp-windows-management-instrumentation.pdf - Ballenthin, W., et al. (2015). Windows Management Instrumentation (WMI) Offense, Defense, and Forensics. Retrieved March 30, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/mandiant-apt1-report.pdf - Mandiant. (n.d.). APT1 Exposing One of China’s Cyber Espionage Units. Retrieved July 18, 2016.
* https://www.fireeye.com/content/dam/fireeye-www/services/pdfs/sans-dfir-2015.pdf - Devon Kerr. (2015). There's Something About WMI. Retrieved May 4, 2020.
* https://www.hackers-arise.com/email-scraping-and-maltego - Hackers Arise. (n.d.). Email Scraping and Maltego. Retrieved October 20, 2020.
* https://www.mandiant.com/resources/apt41-initiates-global-intrusion-campaign-using-multiple-exploits - Gyler, C.,Perez D.,Jones, S.,Miller, S.. (2021, February 25). This is Not a Test: APT41 Initiates Global Intrusion Campaign Using Multiple Exploits. Retrieved February 17, 2022.
* https://www.mandiant.com/resources/blog/fortinet-malware-ecosystem - Marvi, A. et al.. (2023, March 16). Fortinet Zero-Day and Custom Malware Used by Suspected Chinese Actor in Espionage Operation. Retrieved March 22, 2023.
* https://www.mandiant.com/resources/scandalous-external-detection-using-network-scan-data-and-automation - Stephens, A. (2020, July 13). SCANdalous! (External Detection Using Network Scan Data and Automation). Retrieved October 12, 2021.
* https://www.mandiant.com/resources/supply-chain-analysis-from-quartermaster-to-sunshop - FireEye. (2014). SUPPLY CHAIN ANALYSIS: From Quartermaster to SunshopFireEye. Retrieved March 6, 2017.
* https://www.mdsec.co.uk/2017/07/categorisation-is-not-a-security-boundary/ - MDSec Research. (2017, July). Categorisation is not a Security Boundary. Retrieved September 20, 2019.
* https://www.mdsec.co.uk/2021/01/macos-post-exploitation-shenanigans-with-vscode-extensions/ - Dominic Chell. (2021, January 1). macOS Post-Exploitation Shenanigans with VSCode Extensions. Retrieved April 20, 2021.
* https://www.microsoft.com/security/blog/2017/05/04/windows-defender-atp-thwarts-operation-wilysupply-software-supply-chain-cyberattack/ - Florio, E.. (2017, May 4). Windows Defender ATP thwarts Operation WilySupply software supply chain cyberattack. Retrieved February 14, 2019.
* https://www.microsoft.com/security/blog/2021/07/14/microsoft-delivers-comprehensive-solution-to-battle-rise-in-consent-phishing-emails/ - Microsoft 365 Defender Threat Intelligence Team. (2021, June 14). Microsoft delivers comprehensive solution to battle rise in consent phishing emails. Retrieved December 13, 2021.
* https://www.nytimes.com/2011/01/16/world/middleeast/16stuxnet.html - William J. Broad, John Markoff, and David E. Sanger. (2011, January 15). Israeli Test on Worm Called Crucial in Iran Nuclear Delay. Retrieved March 1, 2017.
* https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project - OWASP. (2018, February 23). OWASP Top Ten Project. Retrieved April 3, 2018.
* https://www.proofpoint.com/us/blog/threat-insight/serpent-no-swiping-new-backdoor-targets-french-entities-unique-attack-chain - Campbell, B. et al. (2022, March 21). Serpent, No Swiping! New Backdoor Targets French Entities with Unique Attack Chain. Retrieved April 11, 2022.
* https://www.ptsecurity.com/upload/corporate/ww-en/analytics/Cobalt-Snatch-eng.pdf - Positive Technologies. (2016, December 16). Cobalt Snatch. Retrieved October 9, 2018.
* https://www.randhome.io/blog/2020/12/20/analyzing-cobalt-strike-for-fun-and-profit/ - Maynier, E. (2020, December 20). Analyzing Cobalt Strike for Fun and Profit. Retrieved October 12, 2021.
* https://www.rarlab.com/ - A. Roshal. (2020). RARLAB. Retrieved February 20, 2020.
* https://www.recordedfuture.com/identifying-cobalt-strike-servers/ - Recorded Future. (2019, June 20). Out of the Blue: How Recorded Future Identified Rogue Cobalt Strike Servers. Retrieved October 16, 2020.
* https://www.recordedfuture.com/turla-apt-infrastructure/ - Insikt Group. (2020, March 12). Swallowing the Snake’s Tail: Tracking Turla Infrastructure. Retrieved October 20, 2020.
* https://www.redcanary.com/blog/microsoft-html-application-hta-abuse-part-deux/ - McCammon, K. (2015, August 14). Microsoft HTML Application (HTA) Abuse, Part Deux. Retrieved October 27, 2017.
* https://www.sentinelone.com/blog/macos-red-team-calling-apple-apis-without-building-binaries/ - Phil Stokes. (2019, December 5). macOS Red Team: Calling Apple APIs Without Building Binaries. Retrieved July 17, 2020.
* https://www.ssh.com/ssh/authorized_keys/ - ssh.com. (n.d.). Authorized_keys File in SSH. Retrieved June 24, 2020.
* https://www.trendmicro.de/cloud-content/us/pdfs/security-intelligence/white-papers/wp-cpl-malware.pdf - Merces, F. (2014). CPL Malware Malicious Control Panel Items. Retrieved November 1, 2017.
* https://www.us-cert.gov/ncas/alerts/TA18-106A - US-CERT. (2018, April 20). Alert (TA18-106A) Russian State-Sponsored Cyber Actors Targeting Network Infrastructure Devices. Retrieved October 19, 2020.
* https://www.venafi.com/blog/growing-abuse-ssh-keys-commodity-malware-campaigns-now-equipped-ssh-capabilities - Blachman, Y. (2020, April 22). Growing Abuse of SSH Keys: Commodity Malware Campaigns Now Equipped with SSH Capabilities. Retrieved June 24, 2020.
* https://www.volexity.com/blog/2016/11/09/powerduke-post-election-spear-phishing-campaigns-targeting-think-tanks-and-ngos/ - Adair, S.. (2016, November 9). PowerDuke: Widespread Post-Election Spear Phishing Campaigns Targeting Think Tanks and NGOs. Retrieved January 11, 2017.
* https://www.volexity.com/blog/2017/11/06/oceanlotus-blossoms-mass-digital-surveillance-and-exploitation-of-asean-nations-the-media-human-rights-and-civil-society/ - Lassalle, D., et al. (2017, November 6). OceanLotus Blossoms: Mass Digital Surveillance and Attacks Targeting ASEAN, Asian Nations, the Media, Human Rights Groups, and Civil Society. Retrieved November 6, 2017.
* https://www.volexity.com/blog/2020/11/06/oceanlotus-extending-cyber-espionage-operations-through-fake-websites/ - Adair, S. and Lancaster, T. (2020, November 6). OceanLotus: Extending Cyber Espionage Operations Through Fake Websites. Retrieved November 20, 2020.
* https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/ - Gruzweig, J. et al. (2021, March 2). Operation Exchange Marauder: Active Exploitation of Multiple Zero-Day Microsoft Exchange Vulnerabilities. Retrieved March 3, 2021.
* https://www.welivesecurity.com/2013/04/26/linuxcdorked-new-apache-backdoor-in-the-wild-serves-blackhole/ - Pierre-Marc Bureau. (2013, April 26). Linux/Cdorked.A: New Apache backdoor being used in the wild to serve Blackhole. Retrieved September 10, 2017.
* https://www.welivesecurity.com/2017/12/21/sednit-update-fancy-bear-spent-year/ - ESET. (2017, December 21). Sednit update: How Fancy Bear Spent the Year. Retrieved February 18, 2019.
* https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/ - Tartare, M. et al. (2020, May 21). No “Game over” for the Winnti Group. Retrieved August 24, 2020.
* https://www.welivesecurity.com/wp-content/uploads/2020/06/ESET_InvisiMole.pdf - Hromcova, Z. and Cherpanov, A. (2020, June). INVISIMOLE: THE HIDDEN PART OF THE STORY. Retrieved July 16, 2020.
* https://www.winzip.com/win/en/ - Corel Corporation. (2020). WinZip. Retrieved February 20, 2020.
* https://www.wired.com/images_blogs/threatlevel/2010/11/w32_stuxnet_dossier.pdf - Nicolas Falliere, Liam O. Murchu, Eric Chien. (2011, February). W32.Stuxnet Dossier. Retrieved December 7, 2020.
* https://www.wired.com/story/russia-ukraine-cyberattacks-mandiant/ - Greenberg, A. (2022, November 10). Russia’s New Cyberwarfare in Ukraine Is Fast, Dirty, and Relentless. Retrieved March 22, 2023.
* https://www.zdnet.com/article/paypal-alert-beware-the-paypai-scam-5000109103/ - Bob Sullivan. (2000, July 24). PayPal alert! Beware the 'PaypaI' scam. Retrieved March 2, 2017.

# Validate the following tools

* Empire - 1
* Mimikatz - 1
* NBTscan - 1
* Nltest - 1
* PowerSploit - 1
* certutil - 1

# Review the following tool references

* http://powersploit.readthedocs.io - PowerSploit. (n.d.). PowerSploit. Retrieved February 6, 2018.
* http://www.powershellmagazine.com/2014/07/08/powersploit/ - Graeber, M. (2014, July 8). PowerSploit. Retrieved February 6, 2018.
* https://adsecurity.org/?page_id=1821 - Metcalf, S. (2015, November 13). Unofficial Guide to Mimikatz & Command Reference. Retrieved December 23, 2015.
* https://github.com/PowerShellEmpire/Empire - Schroeder, W., Warner, J., Nelson, M. (n.d.). Github PowerShellEmpire. Retrieved April 28, 2016.
* https://github.com/PowerShellMafia/PowerSploit - PowerShellMafia. (2012, May 26). PowerSploit - A PowerShell Post-Exploitation Framework. Retrieved February 6, 2018.
* https://github.com/dstepanic/attck_empire - Stepanic, D. (2018, September 2). attck_empire: Generate ATT&CK Navigator layer file from PowerShell Empire agent logs. Retrieved March 11, 2019.
* https://github.com/gentilkiwi/mimikatz - Deply, B. (n.d.). Mimikatz. Retrieved September 29, 2015.
* https://manpages.debian.org/testing/nbtscan/nbtscan.1.en.html - Bezroutchko, A. (2019, November 19). NBTscan man page. Retrieved March 17, 2021.
* https://sectools.org/tool/nbtscan/ - SecTools. (2003, June 11). NBTscan. Retrieved March 17, 2021.
* https://ss64.com/nt/nltest.html - ss64. (n.d.). NLTEST.exe - Network Location Test. Retrieved February 14, 2019.
* https://technet.microsoft.com/library/cc732443.aspx - Microsoft. (2012, November 14). Certutil. Retrieved July 3, 2017.
* https://www.fireeye.com/blog/threat-research/2019/01/apt39-iranian-cyber-espionage-group-focused-on-personal-information.html - Hawley et al. (2019, January 29). APT39: An Iranian Cyber Espionage Group Focused on Personal Information. Retrieved February 19, 2019.
* https://www.ncsc.gov.uk/report/joint-report-on-publicly-available-hacking-tools - The Australian Cyber Security Centre (ACSC), the Canadian Centre for Cyber Security (CCCS), the New Zealand National Cyber Security Centre (NZ NCSC), CERT New Zealand, the UK National Cyber Security Centre (UK NCSC) and the US National Cybersecurity and Communications Integration Center (NCCIC). (2018, October 11). Joint report on publicly available hacking tools. Retrieved March 11, 2019.
* https://www.symantec.com/blogs/threat-intelligence/waterbug-espionage-governments - Symantec DeepSight Adversary Intelligence Team. (2019, June 20). Waterbug: Espionage Group Rolls Out Brand-New Toolset in Attacks Against Governments. Retrieved July 8, 2019.

# Validate the following malware

* Cobalt Strike - 2
* IcedID - 1
* Matryoshka - 1
* QakBot - 1
* ShadowPad - 1
* TDTESS - 1
* Ursnif - 1
* Valak - 1
* Winnti for Linux - 1

# Review the following malware references

* http://www.clearskysec.com/wp-content/uploads/2017/07/Operation_Wilted_Tulip.pdf - ClearSky Cyber Security and Trend Micro. (2017, July). Operation Wilted Tulip: Exposing a cyber espionage apparatus. Retrieved August 21, 2017.
* https://blog.trendmicro.com/trendlabs-security-intelligence/ursnif-the-multifaceted-malware/?_ga=2.165628854.808042651.1508120821-744063452.1505819992 - Caragay, R. (2015, March 26). URSNIF: The Multifaceted Malware. Retrieved June 5, 2019.
* https://blogs.juniper.net/en-us/threat-research/covid-19-and-fmla-campaigns-used-to-install-new-icedid-banking-malware - Kimayong, P. (2020, June 18). COVID-19 and FMLA Campaigns used to install new IcedID banking malware. Retrieved July 14, 2020.
* https://cybersecurity.att.com/blogs/labs-research/the-rise-of-qakbot - Morrow, D. (2021, April 15). The rise of QakBot. Retrieved September 27, 2021.
* https://go.recordedfuture.com/hubfs/reports/cta-2021-0228.pdf - Insikt Group. (2021, February 28). China-Linked Group RedEcho Targets the Indian Power Sector Amid Heightened Border Tensions. Retrieved March 22, 2021.
* https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2017/08/07172148/ShadowPad_technical_description_PDF.pdf - Kaspersky Lab. (2017, August). ShadowPad: popular server management software hit in supply chain attack. Retrieved March 22, 2021.
* https://medium.com/chronicle-blog/winnti-more-than-just-windows-and-gates-e4f03436031a - Chronicle Blog. (2019, May 15). Winnti: More than just Windows and Gates. Retrieved April 29, 2020.
* https://redcanary.com/threat-detection-report/threats/qbot/ - Rainey, K. (n.d.). Qbot. Retrieved September 27, 2021.
* https://s3-eu-west-1.amazonaws.com/minervaresearchpublic/CopyKittens/CopyKittens.pdf - Minerva Labs LTD and ClearSky Cyber Security. (2015, November 23). CopyKittens Attack Group. Retrieved September 11, 2017.
* https://securelist.com/qakbot-technical-analysis/103931/ - Kuzmenko, A. et al. (2021, September 2). QakBot technical analysis. Retrieved September 27, 2021.
* https://securelist.com/shadowpad-in-corporate-networks/81432/ - GReAT. (2017, August 15). ShadowPad in corporate networks. Retrieved March 22, 2021.
* https://securityintelligence.com/new-banking-trojan-icedid-discovered-by-ibm-x-force-research/ - Kessem, L., et al. (2017, November 13). New Banking Trojan IcedID Discovered by IBM X-Force Research. Retrieved July 14, 2020.
* https://success.trendmicro.com/solution/000283381 - Trend Micro. (2020, December 17). QAKBOT: A decade-old malware still with new tricks. Retrieved September 27, 2021.
* https://unit42.paloaltonetworks.com/valak-evolution/ - Duncan, B. (2020, July 24). Evolution of Valak, from Its Beginnings to Mass Distribution. Retrieved August 31, 2020.
* https://web.archive.org/web/20210825130434/https://cobaltstrike.com/downloads/csmanual38.pdf - Strategic Cyber LLC. (2017, March 14). Cobalt Strike Manual. Retrieved May 24, 2017.
* https://www.cyber.nj.gov/threat-profiles/trojan-variants/ursnif - NJCCIC. (2016, September 27). Ursnif. Retrieved June 4, 2019.
* https://www.cybereason.com/blog/valak-more-than-meets-the-eye - Salem, E. et al. (2020, May 28). VALAK: MORE THAN MEETS THE EYE . Retrieved June 19, 2020.
* https://www.fireeye.com/blog/threat-research/2017/11/ursnif-variant-malicious-tls-callback-technique.html - Vaish, A. & Nemes, S. (2017, November 28). Newly Observed Ursnif Variant Employs Malicious TLS Callback Technique to Achieve Process Injection. Retrieved June 5, 2019.
* https://www.mandiant.com/sites/default/files/2022-02/rt-apt41-dual-operation.pdf - Fraser, N., et al. (2019, August 7). Double DragonAPT41, a dual espionage and cyber crime operation APT41. Retrieved September 23, 2019.
* https://www.proofpoint.com/us/threat-insight/post/ursnif-variant-dreambot-adds-tor-functionality - Proofpoint Staff. (2016, August 25). Nightmare on Tor Street: Ursnif variant Dreambot adds Tor functionality. Retrieved June 5, 2019.

