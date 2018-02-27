# nullinux

**Now available for python 3 in separate branch**

nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided, nullinux will attempt to connect to the target using an SMB null session. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and when finished, creates a users.txt file of all users found on the host(s). This file is formatted for direct implementation and further exploitation._This script uses Python 2.7 and the smbclient package, run the setup.sh script to get started._

For more information visit the [wiki page](https://github.com/m8r0wn/nullinux/wiki)

### Getting Started
In the Linux terminal run:
1. git clone https://github.com/m8r0wn/nullinux
2. sudo chmod +x nullinux/setup.sh
3. sudo ./nullinux/setup.sh

### Usage

    usage:
        python nullinux.py -users -quick DC1.Domain.net
        python nullinux.py -all 192.168.0.0-5
        python nullinux.py -shares -U 'Domain\User' -P 'Password1' 10.0.0.1,10.0.0.5

    positional arguments:
      targets      Target server

    optional arguments:
      -h, --help   show this help message and exit
      -U USERNAME  Username
      -P PASSWORD  Password
      -v           Verbose output
      -shares      Enumerate shares
      -users       Enumerate users
      -all         Enumerate shares & users
      -quick       Fast user enumeration (use with -users or -all)
