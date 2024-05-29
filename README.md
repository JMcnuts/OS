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





