#! /usr/bin/env python2.7
# Copyright (c) 2018 m8r0wn

import sys
import re
from os import path
import datetime
from commands import getoutput
import argparse

class nullinux():
    shares          = False
    users           = False
    quick           = False
    known_users     = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
    domain_sid      = ""
    acquired_users  = []
    group_count     = 0

    def __init__(self, username, password, verbose):
        self.username = username
        self.password = password
        self.verbose = verbose

    def enum_os(self, target):
        cmd = "smbclient //{}/IPC$ -U {}%{} -t 1 -c exit".format(target,self.username, self.password)
        for line in getoutput(cmd).splitlines():
            if "Domain=" in line:
                print_success("{}: {}".format(target, line))
            elif "NT_STATUS_LOGON_FAILURE" in line:
                print_failure("{}: Authentication Failed".format(target))

    def get_dom_sid(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating Domain Information for: {}".format(target))
        cmd = "rpcclient -c lsaquery -U {}%{} {}".format(self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            if "Domain Name:" in line:
                print_success(line)
            elif "Domain Sid:" in line:
                self.domain_sid = line.split(":")[1].strip()
                print_success("Domain SID: {}".format(self.domain_sid))
        if not self.domain_sid:
            print_failure("Could not attain Domain SID")

    def create_userfile(self):
        openfile = open('nullinux_users.txt', 'w')
        for user in self.acquired_users:
            if user == self.acquired_users[0]:
                openfile.write(user)
            else:
                openfile.write('\n{}'.format(user))
        openfile.close()

    def enum_shares(self, target):
        count = 0
        acquired_shares = []
        smbclient_types = ['Disk', 'IPC', 'Printer']
        print("\n\033[1;34m[*]\033[1;m Enumerating Shares for: {}".format(target))
        cmd = "smbclient -L {} -U {}%{} -t 2".format(target, self.username, self.password)
        for line in getoutput(cmd).splitlines():
            if count == 0:              #Print Enum Share Heading
                print("        {:26} {}".format("Shares", "Comments"))
                print("   " + "-" * 43)
            count += 1
            for t in smbclient_types:   #Check if output in known share types
                if t in line:
                    try:
                        if 'IPC$' in line:
                            print("    \\\{}\{}".format(target, "IPC$"))
                            acquired_shares.append("IPC$")
                        else:
                            share = line.split(t)[0].strip()
                            comment = line.split(t)[1].strip()
                            print("    \\\{}\{:15} {}".format(target, share, comment))
                            acquired_shares.append(share)
                    except KeyboardInterrupt:
                        print("\n[!] Key Event Detected...\n\n")
                        sys.exit(0)
                    except:
                        pass
        if acquired_shares:             #Enumerate dir of each new share
            for s in acquired_shares:
                self.enum_dir(target, s)
        else:
            print("   ")
            print_failure("No Shares Detected")

    def share_header(self, target, share):
        print "\n   ",
        print_status("Enumerating: \\\%s\%s" % (target, share))

    def enum_dir(self, target, share):
        header_count = 0
        cmd = "smbclient //{}/\'{}\' -t 3 -U {}%{} -c dir".format(target, share, self.username, self.password)
        for line in getoutput(cmd).splitlines():
            if "NT_STATUS" in line or "_ACCESS_DENIED" in line:
                if self.verbose:
                    if header_count == 0:
                        header_count += 1
                        self.share_header(target, share)
                    print"   ",
                    print_failure(line)
            elif "Domain=" in line or "blocks available" in line or "WARNING" in line or "failed:" in line or not line:
                pass
            else:
                if header_count == 0:
                    header_count += 1
                    self.share_header(target, share)
                print("     "+line)

    def enum_querydispinfo(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating querydispinfo for: {}".format(target))
        cmd = "rpcclient -c querydispinfo -U {}%{} {}".format(self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            try:
                user_account = line.split("Name:")[0].split("Account:")[1].strip()
                print("    " + user_account)
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                sys.exit(0)
            except:
                pass

    def enum_enumdomusers(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating enumdomusers for: {}".format(target))
        cmd = "rpcclient -c enumdomusers -U {}%{} {}".format(self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            try:
                user_account = line.split("[")[1].split("]")[0].strip()
                print("    "+user_account)
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                sys.exit(0)
            except:
                pass

    def enum_lsa(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating LSA for: {}".format(target))
        cmd = "rpcclient -c lsaenumsid -U {}%{} {}".format(self.username, self.password, target)
        output = getoutput(cmd)
        for line in output.splitlines():
            try:
                if "S-1-5-21" in line:
                    user_sid = "rpcclient -c 'lookupsids {}' -U {}%{} {}".format(line, self.username, self.password, target)
                    for x in getoutput(user_sid).splitlines():
                        user_account = x.split("\\")[1].split("(")[0].strip()
                        count = int(x.split("(")[1].split(")")[0].strip())
                        if count == 1:
                            if self.verbose:
                                print("   "+x)
                            else:
                                print("   "+user_account)
                            if user_account not in self.acquired_users:
                                self.acquired_users.append(user_account)
                        elif count > 1 and "*unknown*\*unknown*" not in line:
                            if self.verbose:
                                print("    {:35} (Network/LocalGroup)".format(x))
                            else:
                                print("    {:35} (Network/Local Group)".format(user_account))
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                sys.exit(0)
            except:
                pass

    def enum_RIDcycle(self, target):
        print("\n\033[1;34m[*]\033[1;m Performing RID Cycling for: {}".format(target))
        if not self.domain_sid:
            print_failure("RID Failed: Could not attain Domain SID")
            return False
        rid_range = list(range(500, 530))
        for rid in rid_range:
            try:
                cmd = "rpcclient -c \"lookupsids {}-{}\" -U {}%{} {}".format(self.domain_sid, rid, self.username, self.password, target)
                for line in getoutput(cmd).splitlines():
                    if "S-1-5-21" in line:
                        user_account = line.split("\\")[1].split("(")[0].strip()
                        count = int(line.split("(")[1].split(")")[0].strip())
                        if count == 1:
                            if self.verbose:
                                print("    " + line)
                            else:
                                print("    " + user_account)
                            if user_account not in self.acquired_users:
                                self.acquired_users.append(user_account)
                        elif count > 1 and "*unknown*\*unknown*" not in line:
                            if self.verbose:
                                print("    {:35} (Network/LocalGroup)".format(line))
                            else:
                                print("    {:35} (Network/LocalGroup)".format(user_account))
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                sys.exit(0)
            except:
                pass

    def enum_known_users(self, target):
        print("\n\033[1;34m[*]\033[1;m Testing {} for Known Users".format(target))
        for user in self.known_users:
            cmd = "rpcclient -c \"lookupnames {}\" -U {}%{} {}".format(user, self.username, self.password, target)
            for line in getoutput(cmd).splitlines():
                if "S-1-5" in line:
                    try:
                        user_account = line.split(" ")[0].strip()
                        if self.verbose:
                            print("    " + line)
                        else:
                            print("    " + user_account)
                        if user_account not in self.acquired_users and int(line.split("User:")[1]) == 1:
                            self.acquired_users.append(user_account)
                    except KeyboardInterrupt:
                        print("\n[!] Key Event Detected...\n\n")
                        sys.exit(0)
                    except:
                        pass

    def enum_dom_groups(self, target):
        print("\n\033[1;34m[*]\033[1;m Enumerating Group Memberships for: {}".format(target))
        cmd = "rpcclient -c enumdomgroups -U {}%{} {}".format(self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            if "rid:" in line:
                try:
                    group = line.split("[")[1].split("]")[0].strip()
                    print_success("Group: %s" % (group))
                    self.group_count += 1
                    self.enum_group_mem(target, group)
                except KeyboardInterrupt:
                    print("\n[!] Key Event Detected...\n\n")
                    sys.exit(0)
                except:
                    pass

    def enum_group_mem(self, target, group):
        cmd = "net rpc group members \'{}\' -U {}%{} -I {}".format(group, self.username, self.password, target)
        for line in getoutput(cmd).splitlines():
            try:
                user_account = line.split("\\")[1].strip()
                print("    " + user_account)
                if user_account not in self.acquired_users:
                    self.acquired_users.append(user_account)
            except KeyboardInterrupt:
                print("\n[!] Key Event Detected...\n\n")
                sys.exit(0)
            except:
                pass

def list_targets(t):
    hosts = []
    ip = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
    iprange = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}$")
    dns = re.compile("^.+\.[a-z|A-Z]{2,}$")
    try:
        #txt File
        if t.endswith(".txt"):
            if path.exists(t):
                return [ip.strip() for ip in open(t)]
            else:
                raise Exception("001: host file not found")
        #multiple 127.0.0.1,yahoo.com
        elif "," in t:
            for x in t.split(","):
                hosts.append(x)
        #Range 127.0.0.1-50
        elif iprange.match(t):
            a,b = t.split("-")
            c = a.split(".")
            for x in range(int(c[2]), int(b)+1):
                hosts.append(c[0]+"."+c[1]+"."+c[2]+"."+str(x))
        # dns name
        elif dns.match(t):
            hosts.append(t)
        #Single IP match
        elif ip.match(t):
            hosts.append(t)
        #no match
        else:
            raise Exception("002: invalid target provided")
        return hosts
    except Exception as e:
        print("[!] List_Target Error " + str(e))
        exit(1)

def print_success(msg):
    print('\033[1;32m[+] \033[1;m'+msg)

def print_status(msg):
    print('\033[1;34m[*] \033[1;m'+msg)

def print_failure(msg):
    print('\033[1;31m[-] \033[1;m'+msg)

def time_stamp():
    return datetime.datetime.now().strftime('%m-%d-%Y %H:%M')

def main():
    version = 5.0
    args = argparse.ArgumentParser(description=("""
               nullinux | {0}
    -----------------------------------
     SMB Null Session Enumeration Tool

usage:
    python nullinux.py -users -quick DC1.Domain.net
    python nullinux.py -all 192.168.0.0-5
    python nullinux.py -shares -U 'Domain\\User' -P 'Password1' 10.0.0.1,10.0.0.5""").format(version), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)

    args.add_argument('-U', dest='username', type=str,default="", help='Username')
    args.add_argument('-P', dest='password', type=str, default="", help='Password')
    args.add_argument('-v', dest="verbose", action='store_true', help="Verbose output")
    args.add_argument('-shares', dest="shares", action='store_true', help="Enumerate shares")
    args.add_argument('-users', dest="users", action='store_true', help="Enumerate users")
    args.add_argument('-all', dest="all", action='store_true', help="Enumerate shares & users")
    args.add_argument('-quick', dest="quick", action='store_true', help="Fast user enumeration (use with -users or -all)")
    args.add_argument(dest='targets', nargs='+', help='Target server')
    args = args.parse_args()
    try:
        print("\n    Starting nullinux {} | {}\n\n".format(version, time_stamp()))
        for t in list_targets(args.targets[0]):
            #enum os
            scan = nullinux('\"{}\"'.format(args.username), '\"{}\"'.format(args.password), args.verbose)
            scan.enum_os(t)
            #enum shares
            if args.shares or args.all:
                scan.enum_shares(t)
            #enum users
            if args.users or args.all:
                if not scan.domain_sid:
                    scan.get_dom_sid(t)
                scan.enum_querydispinfo(t)
                scan.enum_enumdomusers(t)
                #bypass on quick option
                if not args.quick:
                    scan.enum_lsa(t)
                    scan.enum_RIDcycle(t)
                    scan.enum_known_users(t)
                scan.enum_dom_groups(t)
                #if users, write to file, close
                if scan.acquired_users:
                    print("\n\033[1;32m[+]\033[1;m {} USER(s) identified in {} GROUP(s)".format(len(scan.acquired_users), scan.group_count))
                    print("\033[1;34m[*]\033[1;m Writing users to file: ./nullinux_users.txt\n")
                    scan.create_userfile()
                else:
                    print("\n\033[1;31m[-]\033[1;m No valid users or groups detected\n")

    except KeyboardInterrupt:
        print("\n[!] Key Event Detected...\n\n")
        sys.exit(0)
    except Exception as e:
        print("\n[*] Main Error: {}\n\n".format(e))

if __name__ == '__main__':
    main()