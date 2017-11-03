# nullinux

####  Featured on [toolswatch.org](http://www.toolswatch.org/2016/11/nullinux-v3-5-null-session-tool/)!
#### For more information or to get started visit [https://m8r0wn-cyber.blogspot.com/p/nullinux.html](https://m8r0wn-cyber.blogspot.com/p/nullinux.html)

### About
nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB null sessions. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation._This program assumes Python 2.7, and the Samba package are installed on the machine._

### Usage
```bash
Scanning:
    -shares             Dynamically Enumerate all possible
                        shares. (formally: --enumshares)

    -users              Enumerate users through a variety of
                        techniques. (formally: --enumusers)

    -quick              Quickly enumerate users, leaving out brute
                        force options. (used with: -users, or -all)

    -all                Enumerate both users and shares
                        (formally: --all)

Host:
    -U                  Set username (optional)
    -P                  Set password (optional)

More Options:
    -v                  Verbose Output
    -h                  Help menu

Example Usage:
    python nullinux.py -users -quick DC1.Domain.net
    python nullinux.py -all 192.168.0.0-5
    python nullinux.py -shares -U 'Domain\User' -P 'Password1' 10.0.0.1,10.0.0.5
    python nullinux.py 10.0.0.0/24
```
