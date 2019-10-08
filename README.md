# nullinux
![](https://img.shields.io/badge/Python-2.7%20&%203+-blue.svg)&nbsp;&nbsp;
![](https://img.shields.io/badge/License-MIT-green.svg)&nbsp;&nbsp;
[![](https://img.shields.io/badge/Demo-Youtube-red.svg)](https://www.youtube.com/watch?v=akvWRGxxDp0)&nbsp;&nbsp;

Nullinux is an internal penetration testing tool for Linux that can be used to enumerate OS information, domain information, shares, directories, and users through SMB. If no username and password are provided in the command line arguments, an anonymous login, or null session, is attempted. Nullinux acts as a wrapper around the Samba tools smbclient & rpcclient to enumerate hosts using a variety of techniques.

Key Features:
* Single or multi-host enumeration
* Enumerate shares and list files in root directory
* Enumerate users & groups
* Multi-threaded RID Cycling
* Creates a formatted nullinux_users.txt output file free of duplicates for further exploitation
* Python 2.7 & 3 compatible

For more information, and example output, visit the [wiki page](https://github.com/m8r0wn/nullinux/wiki).

### Getting Started
In the Linux terminal run:
```
git clone https://github.com/m8r0wn/nullinux
cd nullinux
sudo bash setup.sh
```

### Usage
```
positional arguments:
  target                Target server
optional arguments:
  -h, --help            show this help message and exit
  -v                    Verbose output
Authentication:
  -u USERNAME, -U USERNAME Username
  -p PASSWORD, -P PASSWORD Password
Enumeration:
  -shares               Enumerate shares only
  -users                Enumerate users only
  -q, -quick            Fast user enumeration
  -r, -rid              Perform RID cycling only
  -range RID_RANGE      Set Custom RID cycling range (Default: '500-550')
  -T MAX_THREADS        Max threads for RID cycling (Default: 15)
  ```
