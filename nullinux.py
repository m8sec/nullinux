#!/usr/bin/env python3
from __future__ import print_function

import sys
import re
import argparse
import datetime
from time import sleep
from ipaddress import IPv4Network
from threading import Thread, activeCount

if sys.version_info[0] < 3:
    from commands import getoutput
else:
    from subprocess import getoutput

class TargetParser():
    # Condensed version of IPParser using only standard libraries
    regex = {
        'single': re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
        'range': re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}$"),
        'cidr': re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$"),
        'dns': re.compile("^.+\.[a-z|A-Z]{2,}$")
    }

    def __init__(self):
        self.hosts = []

    def parse(self, target):
        try:
            self.controller(target)
            return self.hosts
        except Exception as e:
            print_failure('Target Error: {}\n'.format(str(e)))
            sys.exit(1)

    def controller(self, target):
        if target.endswith('.txt'):
            self.fileParser(target)
        elif re.match(self.regex['range'], target):
            self.rangeParser(target)
        elif re.match(self.regex['dns'], target):
            self.hosts.append(target)
        elif ',' in target:
            self.multiParser(target)
        else:
            for ip in IPv4Network(target):
                self.hosts.append(ip)

    def fileParser(self, filename):
        with open(filename, 'r') as f:
            for line in f:
                self.controller(line.strip())

    def multiParser(self, target):
        for t in target.strip().split(','):
            self.controller(t)

    def rangeParser(self, target):
        a = target.split("-")
        b = a[0].split(".")
        for x in range(int(b[3]), int(a[1]) + 1):
            tmp = b[0] + "." + b[1] + "." + b[2] + "." + str(x)
            self.hosts.append(tmp)


class nullinux():
    known_users     = ['Administrator', 'Guest', 'krbtgt', 'root', 'bin']
    domain_sid      = ""
    acquired_users  = []

    def __init__(self, username, password, verbose, output_file):
        self.username       = username
        self.password       = password
        self.verbose        = verbose
        self.output_file   = output_file

    def enum_os(self, target):
        cmd = "smbclient //{}/IPC$ -U {}%{} -t 1 -c exit".format(target,self.username, self.password)
        for line in getoutput(cmd).splitlines():
            if "Domain=" in line:
                # OS info is no longer enumerated in newer Windows servers
                print_success("{}: {}".format(target, line))
            elif "NT_STATUS_LOGON_FAILURE" in line:
                print_failure("{}: Authentication Failed".format(target))
                return False
            return True

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
        openfile = open(self.output_file, 'a')
        for user in self.acquired_users:
             openfile.write('{}\n'.format(user))
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
        if acquired_shares:
            #Enumerate dir of each new share
            for s in acquired_shares:
                self.enum_dir(target, s)
        else:
            print("   ")
            print_failure("No Shares Detected")

    def share_header(self, target, share):
        print("\n   ", end='')
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
                    print("   ", end='')
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

    def rid_cycling(self, target, ridrange, max_threads):
        print("\n\033[1;34m[*]\033[1;m Performing RID Cycling for: {}".format(target))
        if not self.domain_sid:
            print_failure("RID Failed: Could not attain Domain SID")
            return False
        # Handle custom RID range input
        try:
            r = ridrange.split("-")
            rid_range = list(range(int(r[0]), int(r[1])+1))
        except:
            print_failure("Error parsing custom RID range, reverting to default")
            rid_range = list(range(500, 551))
        for rid in rid_range:
            try:
                Thread(target=self.rid_thread, args=(rid,target,), daemon=True).start()
            except:
                pass
            while activeCount() > max_threads:
                sleep(0.001)
        while activeCount() > 1:
            sleep(0.001)

    def rid_thread(self, rid, target):
        cmd = "rpcclient -c \"lookupsids {}-{}\" -U {}%{} {}".format(self.domain_sid, rid, self.username, self.password,target)
        for line in getoutput(cmd).splitlines():
            if "S-1-5-21" in line:
                # Split output to get username/group name
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

def print_success(msg):
    print('\033[1;32m[+]\033[0m {}'.format(msg))

def print_status(msg):
    print('\033[1;34m[*]\033[0m {}'.format(msg))

def print_failure(msg):
    print('\033[1;31m[-]\033[0m {}'.format(msg))

def time_stamp():
    return datetime.datetime.now().strftime('%m-%d-%Y %H:%M')

def nullinux_enum(args, scan, target):
    scan.enum_os(target)
    if args.users:
        scan.enum_shares(target)
    if args.shares:
        if not scan.domain_sid:
            scan.get_dom_sid(target)
        scan.enum_querydispinfo(target)
        scan.enum_enumdomusers(target)
        if not args.quick:
            scan.enum_lsa(target)
            scan.rid_cycling(target, args.rid_range, args.max_threads)
            scan.enum_known_users(target)
        scan.enum_dom_groups(target)

def main(args):
    print("\n    Starting nullinux v{} | {}\n\n".format(version, time_stamp()))
    scan = nullinux('\"{}\"'.format(args.username), '\"{}\"'.format(args.password), args.verbose, args.output_file)
    for t in args.target:
        try:
            if args.rid_only:
                scan.get_dom_sid(t)
                scan.rid_cycling(t, args.rid_range, args.max_threads)
            else:
                nullinux_enum(args, scan, t)
        except Exception as e:
            print("\n[*] Main Error: {}\n\n".format(e))

    if args.users:
        print("\n\033[1;34m[*]\033[1;m {} unique user(s) identified".format(len(scan.acquired_users)))
        if scan.acquired_users:
            print("\033[1;32m[+]\033[1;m Writing users to file: {}\n".format(args.output_file))
            scan.create_userfile()

if __name__ == '__main__':
    try:
        version = '5.5.0dev'
        args = argparse.ArgumentParser(description=("""
               nullinux | v{0}
    -----------------------------------
SMB null-session enumeration tool to gather OS,
user, share, and domain information.

usage:
    nullinux -users -quick DC1.demo.local,10.0.1.1
    nullinux -rid -range 500-600 10.0.0.1
    nullinux -shares -U 'Domain\\User' -P 'Password1' 10.0.0.1""").format(version), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
        args.add_argument('-v', dest="verbose", action='store_true', help="Verbose output")
        args.add_argument('-o', dest="output_file", type=str, default="./nullinux_users.txt", help="Output users to the specified file")
        auth = args.add_argument_group("Authentication")
        auth.add_argument('-u', '-U', dest='username', type=str, default="", help='Username')
        auth.add_argument('-p', '-P', dest='password', type=str, default="", help='Password')
        enum = args.add_argument_group("Enumeration")
        enum.add_argument('-shares', dest="shares", action='store_false', help="Enumerate shares only")
        enum.add_argument('-users', dest="users", action='store_false', help="Enumerate users only")
        enum.add_argument('-q', '-quick', dest="quick", action='store_true', help="Fast user enumeration")
        enum.add_argument('-r', '-rid', dest="rid_only", action='store_true', help="Perform RID cycling only")
        enum.add_argument('-range', dest='rid_range', type=str, default="500-550", help='Set Custom RID cycling range (Default: \'500-550\')')
        enum.add_argument('-T', dest='max_threads', type=int, default=15, help='Max threads for RID cycling (Default: 15)')
        args.add_argument(dest='target', nargs='+', help='Target server')
        args = args.parse_args()
        args.target = TargetParser().parse(args.target[0])
        main(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected...\n\n")
        sys.exit(0)
