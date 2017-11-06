#!/usr/bin/env bash

#Check if Script run as root
if ! [ $(id -u) = 0 ]; then
	echo -e "\n[!] Setup script needs to run as root.\n\n"
	exit 0
fi

echo -e "\n[*] Starting nullinux setup script"

echo -e "[*] Checking for Python 2.7..."
if [[ $(python2.7 -V 2>&1) == *"not found"* ]]
then
    echo -e "[*] Installing Python 2.7"
    apt-get install python2.7 -y
else
    echo "[+] Python 2.7 installed"
fi

echo -e "[*] Checking for Samba tools..."
if [[ $(samba -V 2>&1) == *"not found"* ]]
then
    echo -e "[*] Installing Samba"
    apt-get install samba -y
else
    echo "[+] Samba installed"
fi

echo -e "\n[*] nullinux setup complete\n\n"