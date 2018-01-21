# nullinux

nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided, nullinux will attempt to connect to the target using an SMB null session. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation._This program assumes Python 2.7, and the smbclient package is installed on the machine. Run the setup.sh script to check if these packages are installed._

For more information visit the [wiki page](https://github.com/m8r0wn/nullinux/wiki)

### Getting Started
In the Linux terminal run:
1. git clone https://github.com/m8r0wn/nullinux
2. sudo chmod +x nullinux/setup.sh
3. sudo ./nullinux/setup.sh

### Usage
    Scanning:
        -shares             Dynamically Enumerate all possible
                            shares.
    
        -users              Enumerate users through a variety of
                            techniques.
    
        -quick              Quickly enumerate users, leaving out brute
                            force options. (used with: -users, or -all)
    
        -all                Enumerate both users and shares
    
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
