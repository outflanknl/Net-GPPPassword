# Net-GPPPassword
.NET/C# implementation of Get-GPPPassword. Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

If you have no idea what this is about, then please read: https://adsecurity.org/?p=2288. The technique is old, but can still be valuable in environments where a domain was created long ago.

## Usage
Net-GPPPassword.exe [ADdomain (optional)]

Also works with Cobalt Strike's execute-assembly.

## Compiled versions
Check out Releases: https://github.com/outflanknl/Net-GPPPassword/releases.

## Credits
Author: Stan Hegt (@StanHacked) / Outflank

Original PowerShell implementation by Chris Campbell (@obscuresec): https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Get-GPPPassword.ps1
