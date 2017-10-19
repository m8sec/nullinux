# nullinux
### nullinux v4.0 just released!
### About
nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB null sessions. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation._This program assumes Python 2.7, and the Samba package are installed on the machine._

####  Featured on [toolswatch.org](http://www.toolswatch.org/2016/11/nullinux-v3-5-null-session-tool/)!<br>

### Usage
python nullinux.py -users -quick DC1.Domain.net<br>
python nullinux.py -all 192.168.0.0-5<br>
python nullinux.py -shares -U 'Domain\User' -P 'Password1' 10.0.0.1,10.0.0.5<br>
python nullinux.py 10.0.0.0/24




