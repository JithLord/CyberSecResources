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
    ``` ffuf -w /path/to/wordlist -u https://target/FUZZ ```
    ``` ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.134.222/customers/signup -mr "username already exists" ```

### Spiders & Path Traversal
- OWASP ZAP
- Burpsuite

## Privilege Escalation
### Linux
- LinPeas https://github.com/peass-ng/PEASS-ng
- DirtyCow https://github.com/firefart/dirtycow // https://github.com/firefart/dirtycow/blob/master/dirty.c
- linux-exploit-suggester
  
### Windows
- BeRoot.exe
- WinPeas https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS
- PowerUp.ps1


## Enumerate OS
- nmap
- enum4linux

## Find Exploit-db Exploits commands line
- searchsploit

## Malware Analysis
### Offline Malware Analysis

#### Static

##### File Fingerprinting
- MD5/SHA2 Message Digest 

##### String Search
- PE Studio
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
https://toolbar.netcraft.com/site_report?url
- https://www.robtex.com
knockpy To discover subdomains

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
