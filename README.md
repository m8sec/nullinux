# nullinux

nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided in the command line arguments, nullinux will attempt to connect to the target using an SMB null session. Unlike many of the enumeration tools out there already, nullinux can enumerate multiple targets at once and, when finished, creates a nullinux_users.txt file of all accounts found on the host(s). This user file is free of duplicates and formatted for direct implementation and further exploitation. _nullinux is Python 2/3 compatible. However, the setup.sh script is designed for Python3 usage._

For more information visit the [wiki page](https://github.com/m8r0wn/nullinux/wiki)

### Getting Started
In the Linux terminal run:
1. git clone https://github.com/m8r0wn/nullinux
2. sudo chmod +x nullinux/setup.sh
3. sudo ./nullinux/setup.sh

### Usage

    usage:
        python3 nullinux.py -users -quick DC1.Domain.net
        python3 nullinux.py -all 192.168.0.0-5
        python3 nullinux.py -shares -U 'Domain\User' -P 'Password1' 10.0.0.1,10.0.0.5

    positional arguments:
      targets                   Target server

    optional arguments:
      -h, --help                show this help message and exit
      -u USERNAME, -U USERNAME  Username
      -p PASSWORD, -P PASSWORD  Password
      -v                        Verbose output
      -shares                   Enumerate shares
      -users                    Enumerate users
      -a, -all                  Enumerate shares & users
      -q, -quick                Fast user enumeration (use with -users or -all)
      -r RID_RANGE              Set Custom RID cycling range
