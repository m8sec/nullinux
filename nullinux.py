#!/user/bin/python2.7

# Author: m8r0wn
# Script: nullinux.py
# Category: recon

# Description:
# SMB null session enumeration tool

# Disclaimer:
# This tool was designed to be used only with proper
# consent. Use at your own risk.

import sys
import re
import os
import datetime
from commands import getoutput

class nullinux():
    version         = "v4.0"
    verbose         = False
    shares          = False
    users           = False
    quick           = False
    username        = "\'\'"
    password        = "\'\'"
    known_users     = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
    domain_sid      = ""
    acquired_users  = []
    group_count     = 0

    def __init__(self):
        #Get Class Variables from sys args
        self.parse_args()
        #Start Enumeration
        print"\n    Starting nullinux %s | %s\n\n" % (self.version, datetime.datetime.now().strftime('%m-%d-%Y %H:%M'))
        for t in self.list_targets():
            self.enum_os(t)
            if self.shares:
                print "\n\033[1;34m[*]\033[1;m Enumerating Shares for: %s" % (t)
                self.enum_shares(t)
            if self.users:
                if not self.domain_sid:
                    print "\n\033[1;34m[*]\033[1;m Enumerating Domain Information for: %s" % (t)
                    self.get_dom_sid(t)
                print "\n\033[1;34m[*]\033[1;m Enumerating querydispinfo for: %s" % (t)
                self.enum_querydispinfo(t)
                print "\n\033[1;34m[*]\033[1;m Enumerating enumdomusers for: %s" % (t)
                self.enum_enumdomusers(t)
                if not self.quick:
                    print "\n\033[1;34m[*]\033[1;m Enumerating LSA for: %s" % (t)
                    self.enum_lsa(t)
                    print "\n\033[1;34m[*]\033[1;m Performing RID Cycling for: %s" % (t)
                    self.enum_RIDcycle(t)
                    print "\n\033[1;34m[*]\033[1;m Testing %s for Known Users" % (t)
                    self.enum_known_users(t)
                print "\n\033[1;34m[*]\033[1;m Enumerating Group Memberships for: %s" % (t)
                self.enum_dom_groups(t)
        #Create nullinux_users.txt file
        if self.users:
            if self.acquired_users:
                print "\n\033[1;32m[+]\033[1;m %s USER(s) identified in %s GROUP(s)" % (len(self.acquired_users), self.group_count)
                print "\033[1;34m[*]\033[1;m Writing users to file: ./nullinux_sers.txt"
                self.create_userfile()
            else:
                print "\n\033[1;31m[-]\033[1;m No valid users or groups detected"

        print "\n",
        self.print_status("Scan Complete\n\n")

    def parse_args(self):
        try:
            if "-v" in sys.argv or "-V" in sys.argv:
                self.verbose = True
            if "-P" in sys.argv:
                self.password = "\'%s\'" % (sys.argv[sys.argv.index("-P") + 1])
            if "-U" in sys.argv:
                self.username = "\'%s\'" % (sys.argv[sys.argv.index("-U") + 1])

            if "--enumshares" in sys.argv:
                print "\033[1;31m[-]\033[1;m Depreciating option, please use \"-shares\""
                self.shares = True
            elif "-shares" in sys.argv:
                self.shares = True

            if "--enumusers" in sys.argv:
                print "\033[1;31m[-]\033[1;m Depreciating option, please use \"-users\""
                self.users = True
            elif "-users" in sys.argv:
                self.users = True

            if "--all" in sys.argv:
                print "\033[1;31m[-]\033[1;m Depreciating option, please use \"-users\""
                self.shares = True
                self.users = True
            elif "-all" in sys.argv:
                self.shares = True
                self.users = True

            if "-quick" in sys.argv:
                self.quick = True
        except:
            print "\n[!] Error parsing command line arguments"
            print "[*] Please close and try again...\n\n"
            sys.exit(0)

    def list_targets(self):
        targets = []
        single_ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
        ip_range = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$")
        cidr = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$")
        t = sys.argv[-1]
        try:
            #Cidr Range /24 only
            if cidr.match(t):
                temp = t.split("/")
                if int(temp[1]) != 24:
                    print "invalid target range cider"
                    sys.exit(0)
                A1, A2, A3, A4 = temp[0].split(".")
                for x in range(0, 256):
                    target = A1 + "." + A2 + "." + A3 + "." + `x`
                    targets.append(target)
            #IP Ranges 0-255
            elif ip_range.match(t):
                t.split("-")
                if int(t[1]) > 255:
                    print "[-] Invalid target range\n"
                    sys.exit()
                A, B = t.split("-")
                A1, A2, A3, A4 = A.split(".")
                for x in range(int(A4), int(B) + 1):
                    t = A1 + "." + A2 + "." + A3 + "."
                    t += `x`
                    targets.append(t)
            #Multip IP's 192.168.1.1,192.168.1.3
            elif "," in sys.argv[-1]:
                for t in sys.argv[-1].split(","):
                    targets.append(t)
            #List of single IP addresses, one-per-line
            elif ".txt" in t:
                if not os.path.exists(t):
                    print "[-] File not found, please try again"
                    sys.exit(0)
                targets = [line.strip() for line in open(t)]
                #check file for valid targets
                for x in targets:
                    if not single_ip.match(x):
                        print "valid target not identified in file"
                        sys.exit(0)
            else:
                targets.append(t)
        except:
            print "[-] Error parsing target\n[*] use -h for more information\n\n"
            sys.exit(0)

        # check for targets after parsing sys args
        if not targets:
            print "\n[-] Error: No valid target detected\n\n"
            sys.exit(0)
        # return targets
        self.print_status("Targets Acquired, starting enumeration...\n")
        return targets

    def print_success(self,msg):
        print '\033[1;32m[+]\033[1;m', msg

    def print_status(self,msg):
        print '\033[1;34m[*]\033[1;m', msg

    def print_failure(self, msg):
        print '\033[1;31m[-]\033[1;m', msg

    def enum_os(self, target):
        #Uses null session as opposed to username and password
        cmd = "smbclient //%s/IPC$ -U %s%%%s -t 1 -c exit" % (target, '', '')
        for line in getoutput(cmd).splitlines():
            if "Domain=" in line:
                self.print_success("%s: %s" % (target, line))
            elif "NT_STATUS_LOGON_FAILURE" in line:
                self.print_failure("%s: Authentication Failed" % (target))

    def get_dom_sid(self, target):
        cmd = "rpcclient -c lsaquery -U %s%%%s %s" % (self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            if "Domain Name:" in line:
                self.print_success(line)
            elif "Domain Sid:" in line:
                self.domain_sid = line.split(":")[1].strip()
                self.print_success("Domain SID: %s" % (self.domain_sid))
        if not self.domain_sid:
            self.print_failure("Could not attain Domain SID")

    def create_userfile(self):
        openfile = open('nullinux_users.txt', 'w')
        for user in self.acquired_users:
            if user == self.acquired_users[0]:
                openfile.write(user)
            else:
                openfile.write('\n%s' % user)
        openfile.close()

    def enum_shares(self, target):
        count = 0
        acquired_shares = []
        smbclient_types = ['Disk', 'IPC', 'Printer']
        cmd = "smbclient -L %s -U %s%%%s -t 2" % (target, self.username, self.password)
        for line in getoutput(cmd).splitlines():
            for t in smbclient_types:
                if t in line:
                    try:
                        if count == 0:
                            print "         %-26s %s" % ("Shares", "Comments")
                            print "   ", "-"*43
                        if "IPC" == t:
                            print "    \\\%s\%-15s %s" % (target, "IPC$", comment)
                            acquired_shares.append(share)
                        else:
                            share = line.split(t)[0].strip()
                            comment = line.split(t)[1].strip()
                            print "    \\\%s\%-15s %s" % (target, share, comment)
                            acquired_shares.append(share)
                        count += 1
                    except KeyboardInterrupt:
                        print "\n[!] Key Event Detected...\n\n"
                        sys.exit(0)
                    except:
                        print "    ", line


        #Enumerate dir of each new share
        if acquired_shares:
            for s in acquired_shares:
                self.enum_dir(target, s)
        else:
            self.print_failure("No Shares Detected")

    def enum_dir(self, target, share):
        print "\n   ",
        self.print_status("Enumerating: \\\%s\%s" % (target, share))
        cmd = "smbclient //%s/%s -t 3 -U %s%%%s -c dir" % (target, share, self.username, self.password)
        for line in getoutput(cmd).splitlines():
            if "NT_STATUS_LOGON_FAILURE" in line or "NT_STATUS_ACCESS_DENIED" in line:
                print "   ",
                self.print_failure("Access Denied")
            elif "NT_STATUS_UNSUCCESSFUL" in line:
                print "   ",
                self.print_status("Connection Unsuccessful")
            elif "NT_STATUS_IO_TIMEOUT" in line:
                print "   ",
                self.print_status("Connection Timed Out")
            elif "Domain=" in line or "blocks available" in line or "WARNING" in line or "failed:" in line or not line:
                pass
            else:
                print "    ", line


    def enum_querydispinfo(self, target):
        cmd = "rpcclient -c querydispinfo -U %s%%%s %s" % (self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            try:
                user_account = line.split("Name:")[0].split("Account:")[1].strip()
                print "   ", user_account
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
            except KeyboardInterrupt:
                print "\n[!] Key Event Detected...\n\n"
                sys.exit(0)
            except:
                pass


    def enum_enumdomusers(self, target):
        cmd = "rpcclient -c enumdomusers -U %s%%%s %s" % (self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            try:
                user_account = line.split("[")[1].split("]")[0].strip()
                print "   ", user_account
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
            except KeyboardInterrupt:
                print "\n[!] Key Event Detected...\n\n"
                sys.exit(0)
            except:
                pass


    def enum_lsa(self, target):
        cmd = "rpcclient -c lsaenumsid -U %s%%%s %s" % (self.username, self.password, target)
        output = getoutput(cmd)
        for line in output.splitlines():
            try:
                if "S-1-5-21" in line:
                    user_sid = "rpcclient -c 'lookupsids %s' -U %s%%%s %s" % (line, self.username, self.password, target)
                    for x in getoutput(user_sid).splitlines():
                        user_account = x.split("\\")[1].split("(")[0].strip()
                        count = int(x.split("(")[1].split(")")[0].strip())
                        if count == 1:
                            if self.verbose:
                                print "   ", x
                            else:
                                print "   ", user_account
                            if user_account not in self.acquired_users:
                                self.acquired_users.append(user_account)
                        elif count > 1 and "*unknown*\*unknown*" not in line:
                            if self.verbose:
                                print "    %-35s (Network/LocalGroup)" % (x)
                            else:
                                print "    %-35s (Network/Local Group)" % (user_account)
            except KeyboardInterrupt:
                print "\n[!] Key Event Detected...\n\n"
                sys.exit(0)
            except:
                pass

    def enum_RIDcycle(self, target):
        if not self.domain_sid:
            self.print_failure("RID Failed: Could not attain Domain SID")
            return False
        rid_range = list(range(500, 530))
        for rid in rid_range:
            try:
                cmd = "rpcclient -c \"lookupsids %s-%s\" -U %s%%%s %s" % (self.domain_sid, rid, self.username, self.password, target)
                for line in getoutput(cmd).splitlines():
                    if "S-1-5-21" in line:
                        user_account = line.split("\\")[1].split("(")[0].strip()
                        count = int(line.split("(")[1].split(")")[0].strip())
                        if count == 1:
                            if self.verbose:
                                print "   ",line
                            else:
                                print "   ", user_account
                            if user_account not in self.acquired_users:
                                self.acquired_users.append(user_account)
                        elif count > 1 and "*unknown*\*unknown*" not in line:
                            if self.verbose:
                                print "    %-35s (Network/LocalGroup)" % (line)
                            else:
                                print "    %-35s (Network/Local Group)" % (user_account)
            except KeyboardInterrupt:
                print "\n[!] Key Event Detected...\n\n"
                sys.exit(0)
            except:
                pass

    def enum_known_users(self, target):
        for user in self.known_users:
            cmd = "rpcclient -c \"lookupnames %s\" -U %s%%%s %s" % (user, self.username, self.password, target)
            for line in getoutput(cmd).splitlines():
                if "S-1-5" in line:
                    try:
                        user_account = line.split(" ")[0].strip()
                        if self.verbose:
                            print "   ", line
                        else:
                            print "   ", user_account
                        if user_account not in self.acquired_users and int(line.split("User:")[1]) == 1:
                            self.acquired_users.append(user_account)
                    except KeyboardInterrupt:
                        print "\n[!] Key Event Detected...\n\n"
                        sys.exit(0)
                    except:
                        pass

    def enum_dom_groups(self, target):
        cmd = "rpcclient -c enumdomgroups -U %s%%%s %s" % (self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            if "rid:" in line:
                try:
                    group = line.split("[")[1].split("]")[0].strip()
                    self.print_success("Group: %s" % (group))
                    self.group_count += 1
                    self.enum_group_mem(target, group)
                except KeyboardInterrupt:
                    print "\n[!] Key Event Detected...\n\n"
                    sys.exit(0)
                except:
                    pass

    def enum_group_mem(self, target, group):
        cmd = "net rpc group members \'%s\' -U %s%%%s -I %s" % (group, self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            try:
                user_account = line.split("\\")[1].strip()
                print "   ", user_account
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
            except KeyboardInterrupt:
                print "\n[!] Key Event Detected...\n\n"
                sys.exit(0)
            except:
                pass

def main():
    #Print Help Banner
    if "-h" in sys.argv or len(sys.argv) == 1: banner()
    try:
        #New class object
        scan = nullinux()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected, exiting...\n\n"
        sys.exit(0)
    except Exception as e:
        print "\n[*] Main Error: %s\n\n" % (e)

def banner():
    print """
                 nullinux | %s
         SMB Null Session Enumeration Tool

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
    python nullinux.py --all 192.168.0.0-5
    python nullinux.py --shares 10.0.0.1,10.0.0.5
    python nullinux.py 10.0.0.0/24

    """ % (nullinux.version)
    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print "\n[!] Key Event Detected...\n\n"
        sys.exit(0)