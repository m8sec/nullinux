#!/usr/bin/env bash
# nullinux install script

if [[ $(id -u) != 0 ]]; then
	echo -e "\n[!] Setup script needs to run as root\n\n"
	exit 0
fi

echo -e "\n[*] Starting nullinux setup script"

pip3 install -r requirements.txt

echo -e "[*] Checking for smbclient"
if [[ $(smbclient -V 2>&1) == *"not found"* ]]
then
    echo -e "[*] Installing smbclient"
    apt-get install smbclient -y
else
    echo "[+] smbclient installed"
fi

cp ./nullinux.py /usr/local/bin/nullinux

chmod +x /usr/local/bin/nullinux

echo -e "\n[*] nullinux setup complete\n\n"