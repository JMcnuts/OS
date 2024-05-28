# OS (Focuss on persistence).

### 10.50.26.35 (IP for number 71) 
### 10.50.22.197:8000 (Website for challenges)
### xfreerdp /u:student /v:10.50.26.35 -dynamic-resolution +glyph-cache +clipboard
### for ssh from xfreerdp use your stack number to ssh into the machine 10.XX.0.(0-7) (1.Domain Controller, 3.File Server, 4.Workstation 2, 5.Workstation 1, 6.Terra, 7.Minas Tirith)
### credentials 1,3,4 andy.dwyer-BurtMacklinFBI (SSH-Connection)
### credentials 5 student-password
### credentials 6 garviel-luna
### credentials 7 bombadil-jolly 
```
## Pwershell profiles are good to set persistence. Profiles are just scripts that have configurations set.

PowerShell supports several profile files and host programs, like Windows, support their own specific profiles. The profiles below are listed in order of precedence with the first profile having the highest precedence.


Description	                              Path
All Users, All Hosts                      $PsHome\Profile.ps1
All Users, Current Host                   $PsHome\Microsoft.PowerShell_profile.ps1
Current User, All Hosts                   Home\[My]Documents\Profile.ps1
Current User, Current Host                $Home\[My ]Documents\WindowsPowerShell\Profile.ps1


In addition, other programs that host PowerShell can support their own profiles. For example, PowerShell Integrated Scripting Environment (ISE) supports the following host-specific profiles.



All users, Current Host                   $PsHome\Microsoft.PowerShellISE_profile.ps1
Current user, Current Host                $Home\[My]Documents\WindowsPowerShell\Microsoft.PowerShellISE_profile.ps1
```
