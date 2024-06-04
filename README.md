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

