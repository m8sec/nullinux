#!/usr/bin/env bash

# Author: m8r0wn
# Description: nullinux setup script to verify all required packages
# are installed on the system.

#Check if Script run as root
if [[ $(id -u) != 0 ]]; then
	echo -e "\n[!] Setup script needs to run as root\n\n"
	exit 0
fi

echo -e "\n[*] Starting nullinux setup script"
echo -e "[*] Checking for Python 3"
if [[ $(python3 -V 2>&1) == *"not found"* ]]
then
    echo -e "[*] Installing Python 3"
    apt-get install python3 -y
else
    echo "[+] Python 3 installed"
fi

echo -e "[*] Checking for smbclient"
if [[ $(smbclient -V 2>&1) == *"not found"* ]]
then
    echo -e "[*] Installing smbclient"
    apt-get install smbclient -y
else
    echo "[+] smbclient installed"
fi

# Copy the file
cp ./nullinux.py /usr/local/bin/nullinux
# Make the file executable
chmod +x /usr/local/bin/nullinux

echo -e "\n[*] nullinux setup complete\n\n"