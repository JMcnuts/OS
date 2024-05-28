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

 





