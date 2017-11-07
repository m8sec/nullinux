# nullinux

####  Featured on [toolswatch.org](http://www.toolswatch.org/2016/11/nullinux-v3-5-null-session-tool/)!
#### For more information and example output visit [https://m8r0wn-cyber.blogspot.com/p/nullinux.html](https://m8r0wn-cyber.blogspot.com/p/nullinux.html)

### About
nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB null sessions. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation._This program assumes Python 2.7, and the smbclient package is installed on the machine. Run the setup.sh script to check if these packages are installed._

### Getting Started
* git clone https://github.com/m8r0wn/nullinux
* sudo chmod +x nullinux/setup.sh
* sudo ./nullinux/setup.sh

### Usage
python nullinux.py -users -quick DC1.Domain.net<br>
python nullinux.py -all 192.168.0.0-5<br>
python nullinux.py -shares -U 'Domain\User' -P 'Password1' 10.0.0.1,10.0.0.5<br>
python nullinux.py 10.0.0.0/24




