# nullinux
### Featured on [toolswatch.org](http://www.toolswatch.org/2016/11/nullinux-v3-5-null-session-tool/)!<br>
### For more usage information or to get started visit the [nullinux wiki page](https://github.com/m8r0wn/nullinux/wiki)!
### About
nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB null sessions. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation.

_This program assumes Python 2.7, the Scapy module, and the Samba package are installed on the machine._

### Usage
./nullinux.py 10.0.0.1-255<br>
./nullinux.py -sT -v --enumusers 10.0.0.1-10<br>
./nullinux.py -sN -U Administrator -P password --all 10.0.0.10<br>
./nullinux.py 10.0.0.1-255




