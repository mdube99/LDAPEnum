#!/usr/bin/env python3

import subprocess
import ipaddress
from ldap3 import Server, Connection, ALL, NTLM
import ldap3
from datetime import datetime
import os
import sys
import os.path
import socket
import argparse
import re

# colors without dependencies
class colors:

    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def check_error(msg: str) -> str:
    minus = colors.FAIL + '[-]' + colors.ENDC + ' '
    return minus + msg + '\n'

def check_success(msg: str) -> str:
    plus = colors.OKGREEN + '[+]' + colors.ENDC + ' '
    return plus + msg + '\n'

def error(msg: str) -> str:
    max_length = 70
    padding = max(0, (max_length - len(msg)) // 2)
    this = '-' * padding + msg + '-' * (max_length - len(msg) - padding)
    return colors.FAIL + this + colors.ENDC + '\n'

def success(msg: str) -> str:
    max_length = 70
    padding = max(0, (max_length - len(msg)) // 2)
    this = '-' * padding + msg + '-' * (max_length - len(msg) - padding)
    return colors.OKGREEN + this + colors.ENDC + '\n'

class LDAPEnum():
    def __init__(self) -> None:
        pass

    def banner(self) -> None:
        print(colors.BOLD + colors.OKGREEN + '''
 /$$       /$$$$$$$   /$$$$$$  /$$$$$$$  /$$$$$$$$                                  
| $$      | $$__  $$ /$$__  $$| $$__  $$| $$_____/                                  
| $$      | $$  \ $$| $$  \ $$| $$  \ $$| $$       /$$$$$$$  /$$   /$$ /$$$$$$/$$$$ 
| $$      | $$  | $$| $$$$$$$$| $$$$$$$/| $$$$$   | $$__  $$| $$  | $$| $$_  $$_  $$
| $$      | $$  | $$| $$__  $$| $$____/ | $$__/   | $$  \ $$| $$  | $$| $$ \ $$ \ $$
| $$      | $$  | $$| $$  | $$| $$      | $$      | $$  | $$| $$  | $$| $$ | $$ | $$
| $$$$$$$$| $$$$$$$/| $$  | $$| $$      | $$$$$$$$| $$  | $$|  $$$$$$/| $$ | $$ | $$
|________/|_______/ |__/  |__/|__/      |________/|__/  |__/ \______/ |__/ |__/ |__/

        ''' + colors.ENDC)

    def args(self) -> None:
        parser = argparse.ArgumentParser('''python3 LDAPEnum.py -D 10.10.0.44 -u test -p test -A
        ''')
        parser.add_argument('-D', '--domaincontroller', type=str, help="Domain Controller")
        parser.add_argument('-H', '--hash', help="hash")
        parser.add_argument('-u', '--username', help="Username")
        parser.add_argument('-p', '--password', help="Password")
        parser.add_argument('-A', '--all', action='store_true', help="Print all available options")
        parser.add_argument('-P', '--passpol', action='store_true', help="Print out users.fault: will only output to file.")
        parser.add_argument('-U', '--users', action='store_true', help="Print out domain users.")
        parser.add_argument('-G', '--groups', action='store_true', help="Print out domain groups.")
        parser.add_argument('-C', '--computers', action='store_true', help="Print out domain computers.")
        parser.add_argument('-O', '--obfuscate', action='store_true', help="(Experimental) Obfuscate LDAP Queries")
        parser.add_argument('--gpo', action='store_true', help="Print out Group Policy Objects")
        parser.add_argument('--sid', action='store_true', help="Print out Domain SID")
        parser.add_argument('-L', '--laps', action='store_true', help="Print out LAPS information.")

        if len(sys.argv) <= 5:
            parser.print_help(sys.stderr)
            sys.exit(1)
        self.args = parser.parse_args()

        self.hostname = self.args.domaincontroller
        self.username = self.args.username
        self.password = self.args.password

    def __search_ldap_server(self, OBJ_TO_SEARCH: str, ATTRI_TO_SEARCH: str | list) -> None:
        "ldap server searching"

        # obfuscation is highly experimental. May not always work.
        # LDAP can read some queries via hex, which will be harder for EDR to alert on.
        # Obfuscations are also case sensitive.
        # Obfuscation searching for 'objectCategory' will not work against 'objectcategory'

        if self.args.obfuscate:

            # list of queries that are obfuscatable
            obfuscatable = ['memberof', 'objectCategory', 'servicePrincipalName']

            # will loop over each obfuscatable item and check for it in OBJ_TO_SEARCH
            for query in obfuscatable:
                if query in OBJ_TO_SEARCH:
                    obfuscatable_value = re.findall(f'{query}=([^)]*)', OBJ_TO_SEARCH)
                    # Turn first value from query into hex
                    # without [0] it will return it as a list. probably a cleaner way to do this
                    obfuscated_query = obfuscatable_value[0].encode('utf-8').hex(sep='\\')
                    orig_query = f'{query}={obfuscatable_value[0]}'

                    # e.g. objectCategory=person
                    # objectCategory=\70\65\72\73\6f\6e
                    new_query = f'{query}=\\{obfuscated_query}'
                    OBJ_TO_SEARCH = OBJ_TO_SEARCH.replace(orig_query, new_query)

        self.ldapconn.search(self.ldap_domain_name, OBJ_TO_SEARCH, attributes=ATTRI_TO_SEARCH)

    # inspired by themayor
    def ldap_connect_cred(self, hostname: str, username: str, password: str) -> None:
        self.begintime = datetime.now()

        # 5 second timeout
        socket.setdefaulttimeout(5)
        # tries LDAPS
        try:
            host_with_port = f'ldaps://{hostname}:636'
            self.server = Server(str(host_with_port), port=636, use_ssl=True, get_info=ALL)
            self.ldapconn = Connection(self.server, auto_bind=True)
        except:
            try:
                print(check_error("LDAPS connection failed, attempting LDAP..."))
                host_with_port = f'ldap://{hostname}:389'
                self.server = Server(str(host_with_port), port=389, use_ssl=True, get_info=ALL)
                self.ldapconn = Connection(self.server, auto_bind=True)
                print(check_success("LDAP connection successful"))
            except Exception as e:
                print(check_error(f"LDAP connection failed: {e}"))
                quit()

        with open(f"{hostname}.txt", 'w') as f:
            f.write(str(self.server.info))
        print(check_success("Attempting to identify a domain naming convention\n"))
        get_dom_info = str(self.server.info).split("\n")
        for item in get_dom_info:
            if "DC=" in item:
                self.name_context = item.strip()
                if "ForestDnsZones" in item:
                    continue
                else:
                    break
        self.long_dc = self.name_context
        self.dn_val_count = self.name_context.count('DC=')
        self.name_context = self.name_context.replace("DC=", "")
        self.name_context = self.name_context.replace(",", ".")

        # with open(f"{hostname}.txt", 'r') as f:
        # # From msLDAPDump
        #     for line in f:
        #         if line.startswith("    DC="):
        #             self.name_context = line.strip()
        #             print("orig name_context", self.name_context)
        #             self.long_dc = self.name_context
        #             print("long_dc", self.long_dc)
        #             self.dc_val = (self.name_context.count('DC='))
        #             self.name_context = self.name_context.replace(
        #                 "DC=", "")
        #             self.name_context = self.name_context.replace(",", ".")
        #             if "ForestDnsZones" in self.name_context:
        #                 continue
        #             else:
        #                 break

        self.domain = self.name_context
        domain_contents = self.domain.split(".")
        print(check_success(f"Possible domain name found - {self.name_context}"))
        # print(success(f"Possible domain name found - {self.name_context}"))
        print(self.long_dc)
        print("")
        self.ldap_domain_name = f"{self.long_dc}"
        try:
            self.ldapconn = Connection(
                self.server, user=f"{domain_contents[self.dn_val_count - 2]}\\{username}", password=password, auto_bind=True)
            self.ldapconn.bind()
        except ldap3.core.exceptions.LDAPBindError:
            print("Invalid credentials. Please try again.")
            quit()
        print(check_success(f"Connected to {hostname}\n"))


    # inspired by themayor
    def ldap_connect_ntlm(self, hostname: str, username: str, password: str) -> None:
        try:
            self.begintime = datetime.now()
            socket.setdefaulttimeout(5)
            # tries LDAPS
            try:
                host_with_port = f'ldaps://{hostname}:636'
                self.server = Server(str(host_with_port), port=636, use_ssl=True, get_info=ALL)
                self.ldapconn = Connection(self.server, auto_bind=True)
            except:
                try:
                    print(check_error("LDAPS connection failed, attempting LDAP..."))
                    host_with_port = f'ldap://{hostname}:389'
                    self.server = Server(str(host_with_port), port=389, use_ssl=True, get_info=ALL)
                    self.ldapconn = Connection(self.server, auto_bind=True)
                    print(check_success("LDAP connection successful"))
                except Exception as e:
                    print(f"Connection failed: {e}")
                    quit()
            self.ldapconn = Connection(self.server, auto_bind=True)
            with open(f"{hostname}.txt", 'w') as f:
                f.write(str(self.server.info))
            print(check_success("Attempting to identify a domain naming convention\n"))
            get_dom_info = str(self.server.info).split("\n")
            for item in get_dom_info:
                if "DC=" in item:
                    self.name_context = item.strip()
                    if "ForestDnsZones" in item:
                        continue
                    else:
                        break
            self.long_dc = self.name_context
            self.dn_val_count = self.name_context.count('DC=')
            self.name_context = self.name_context.replace("DC=", "")
            self.name_context = self.name_context.replace(",", ".")

            # with open(f"{hostname}.txt", 'w') as f:
            #     f.write(str(self.server.info))
            # print(success("Attempting to identify a domain naming convention for the domain.\n"))
            # # From msLDAPDump
            # with open(f"{hostname}.txt", 'r') as f:
            #     for line in f:
            #         if line.startswith("    DC="):
            #             self.name_context = line.strip()
            #             self.long_dc = self.name_context
            #             self.dc_val = (self.name_context.count('DC='))
            #             self.name_context = self.name_context.replace(
            #                 "DC=", "")
            #             self.name_context = self.name_context.replace(",", ".")
            #             if "ForestDnsZones" in self.name_context:
            #                 continue
            #             else:
            #                 break
            
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(check_success(f"Possible domain name found - {self.name_context}"))
            # print(success(f"Possible domain name found - {self.name_context}"))
            self.ldap_domain_name = f"{self.long_dc}"
            print(self.long_dc)
            print("")
            try:
                self.ldapconn = Connection(
                    self.server, user=f"{domain_contents[self.dn_val_count - 2]}\\{username}", password=password, auto_bind=True, authentication=NTLM)

                self.ldapconn.bind()
            except:
                print("Invalid credentials. Please try again.")
                quit()

        except (ipaddress.AddressValueError, socket.herror):
            print(check_error("Invalid IP Address or unable to contact host. Please try again."))
            quit()
        except socket.timeout:
            print(check_error("Timeout while trying to contact the host. Please try again."))
            quit()

    def kerberoast_accounts(self) -> None:
        # Query LDAP for Kerberoastable users - searching for SPNs where user is a normal user and account is not disabled
        OBJ_TO_SEARCH = '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No Kerberoastable Users"))
        else:
            print(success("Kerberoastable Users"))
            for kerb_users in self.ldapconn.entries:
                print(kerb_users.sAMAccountName)
        print("")

    def asreproast_accounts(self) -> None:
        # Query LDAP for ASREPRoastable Users
        OBJ_TO_SEARCH = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
        ATTRI_TO_SEARCH = 'sAMAccountName'
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No ASREPRoastable Users"))
        else:
            print(success("ASREPRoastable Users"))
            for asrep_users in self.ldapconn.entries:
                print(asrep_users.sAMAccountName)
        print("")

    def server_search(self) -> None:
        # Query LDAP for computer accounts
        OBJ_TO_SEARCH = '(&(objectClass=computer)(!(objectClass=msDS-ManagedServiceAccount)))'
        ATTRI_TO_SEARCH = ['name', 'operatingsystem']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        print(success("Domain Joined Servers"))
        for comp_account in self.ldapconn.entries:
            comp_account1 = str(comp_account).lower()
            if "server" in comp_account1:
                print(f"{comp_account.name} - {comp_account.operatingsystem}")
        print("")

    def dc_search(self) -> None:
        # Query LDAP for domain controllers
        OBJ_TO_SEARCH = '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        print(success('Domain Controllers'))
        for dc_accounts in self.ldapconn.entries:
            try:
                print(dc_accounts.dNSHostName)
            except ldap3.core.exceptions.LDAPCursorAttributeError:
                print(dc_accounts.name)
        print("")

    def mssql_search(self) -> None:
        # Query LDAP for MSSQL Servers
        OBJ_TO_SEARCH = '(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error('No MSSQL Servers Found'))
        else:
            try:
                print(success('MSSQL Servers'))
                # if os.path.exists(f"mssqlservers.txt"):
                #     os.remove(f"mssqlservers.txt")
                # with open(f"mssqlservers.txt", 'r+') as f:
                #     comp_val = 0
                #     for line in f:
                #         if line.startswith('    dNSHostName: '):
                #             comp_name = line.strip()
                #             comp_name = comp_name.replace('dNSHostName: ', '')
                #             comp_name = comp_name.replace('$', '')
                #             print(comp_name)
                #             comp_val += 1
                #             if comp_val >= 25:
                #                 print(success(f'Truncating results at 25. Check {self.domain}.computers.txt for full details.'))
                #                 break
                #     f.close()
                if os.path.exists(f"mssqlservers.txt"):
                    os.remove(f"mssqlservers.txt")
                with open(f"mssqlservers.txt", 'a') as f:
                    print(check_success('Output mssqlservers to file'))
                    for entry in self.ldapconn.entries:
                        dNSHostName = str(entry.dNSHostName)

                        f.write(dNSHostName + '\n')
                        print(dNSHostName)
                    f.close()
            except Exception as e:
                print(check_error(f"Could not find MSSQL servers: {e}"))
        print("")

    def admin_count_search(self) -> None:
        # Query LDAP for users with adminCount=1
        OBJ_TO_SEARCH = '(&(!(memberof=Builtin))(adminCount=1)(objectClass=person)(objectCategory=Person))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        ldap_entries = self.ldapconn.entries
        print(success('Users with adminCount=1 (DA, EA)'))
        ldap_entries = str(ldap_entries)
        for admin_count_val in self.ldapconn.entries:
            print(admin_count_val.name)
        print("")

    def find_fields(self) -> None:
        print(success('Checking user descriptions for interesting information'))
        OBJ_TO_SEARCH = '(&(objectClass=person)(objectCategory=Person))'
        ATTRI_TO_SEARCH = ['sAMAccountname', 'description']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        for entry in self.ldapconn.entries:
            if entry.description == 'Built-in account for administering the computer/domain':
                pass
            if entry.description == 'Built-in account for guest access to the computer/domain':
                pass
            desc = str(entry.description)
            account_name = str(entry.sAMAccountname)
            # pass_val = 'pass'
            desc_lower = desc.lower()
            if "pass" in desc_lower or "pwd" in desc_lower or "cred" in desc_lower:
                print(f'User: {account_name}\t- Description:\t{desc}')
        print("")

    def find_ad_printers(self) -> None:
        "not tested on an environment yet"
        OBJ_TO_SEARCH = '(&(uncName=*lon-prnt*)(objectCategory=printQueue)(printColor=TRUE))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No Domain joined Printers found"))
        else:
            print(success('Printers connected to Active Directory environment'))
            try:
                for entry in self.ldapconn.entries:
                    print(entry)
            except Exception as e:
                print(error(f"Error getting AD Printers {e}"))
            print("")

    def find_password_policy(self) -> None:
        print(success('Domain Password Policy'))
        OBJ_TO_SEARCH = '(objectClass=*)'
        ATTRI_TO_SEARCH =  ['forceLogoff', 'lockoutDuration', 'lockOutObservationWindow', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        ldap_entries = str(self.ldapconn.entries)
        if os.path.exists(f"passpol.txt"):
            os.remove(f"passpol.txt")
        lines = ldap_entries.split('\n')

        found_target = False
        # enumerate through all lines in file
        for i, line in enumerate(lines):
            # If it finds 'forceLogoff', print the line
            if "    forceLogoff: " in line:
                with open(f"passpol.txt", 'a') as f:
                    found_target = True

                    # print the 8 lines following forceLogoff, then break
                    for j in range(i + 1, min(i + 9, len(lines))):
                        f.write(lines[j].strip() + '\n')
                        print(lines[j].strip())
                    f.close()

                    break
        if not found_target:
            print("Unable to find Password Policy")
        print("")

    def get_all_users(self) -> None:
        print(success('All Domain Users'))
        OBJ_TO_SEARCH = '(&(objectClass=user)(objectCategory=person)(objectCategory=user))'
        ATTRI_TO_SEARCH = ['name', 'sAMAccountName', 'whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        if os.path.exists(f"users.txt"):
            os.remove(f"users.txt")
        with open(f"users.txt", 'a') as f:
            print(check_success('Output users to file'))
            for entry in self.ldapconn.entries:
                samaccount = str(entry.sAMAccountname)

                f.write(samaccount + '\n')
                print(samaccount)
            f.close()
        print("")

    def get_all_computers(self) -> None:
        print(success('All Domain Computers'))
        OBJ_TO_SEARCH = '(&(objectClass=computer))'
        ATTRI_TO_SEARCH = ['sAMAccountName', 'name','operatingSystem','operatingSystemServicePack','whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        if os.path.exists(f"computers.txt"):
            os.remove(f"computers.txt")
        with open(f"computers.txt", 'a') as f:
            print(check_success('Output computers to file'))
            for entry in self.ldapconn.entries:
                samaccount = str(entry.sAMAccountname)

                # Print one samaccount per line
                f.write(samaccount + '\n')
                print(samaccount)
            f.close()
        print("")


    def get_all_groups(self) -> None:
        print(success('All Domain Groups'))
        OBJ_TO_SEARCH = '(&(objectClass=group))'
        ATTRI_TO_SEARCH = ['sAMAccountName', 'name','whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if os.path.exists(f"groups.txt"):
            os.remove(f"groups.txt")
        with open(f"groups.txt", 'a') as f:
            print(check_success('Output groups to file'))
            for entry in self.ldapconn.entries:
                group = str(entry.sAMAccountname)
                whencreated = str(entry.whencreated)

                # Print one samaccount per line
                f.write(group + '\n')
                # splitting on space will only show the date, rather than date and time
                print(f'Group: {group}.\tCreated: {whencreated.split(" ")[0]}')
            f.close()
        print("")
    def searchResEntry_to_dict(self, results):
        data = {}
        for attr in results['attributes']:
            key = str(attr['type'])
            value = str(attr['vals'][0])
            data[key] = value
        return data

    def get_gpo(self) -> None:
        "untested"
        print(success('GPOs Found'))
        OBJ_TO_SEARCH = '(&(objectClass=groupPolicyContainer))'
        ATTRI_TO_SEARCH = ['displayname', 'gPCFileSysPath', 'versionNumber', 'Name', 'gPLink', 'whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        try:
            if os.path.exists(f"group_policy.txt"):
                os.remove(f"group_policy.txt")
            with open(f"group_policy.txt", 'a') as f:
                print(check_success('Output GPOs to file'))
                for entry in self.ldapconn.entries:
                    displayname = str(entry.displayName)
                    name = str(entry.name)

                    # Print one samaccount per line
                    f.write(str(entry) + '\n')
                    # splitting on space will only show the date, rather than date and time
                    print("----")
                    print(displayname)
                    print(name)
                f.close()
                print("----")
        except Exception as e:
            print(error(f"Error getting Group Policy: {e}"))
        print("")

    def get_laps(self) -> None:
        "untested"
        OBJ_TO_SEARCH = '(&(objectCategory=person)(objectClass=user)(msDS-SupportedEncryptionTypes=*))'
        ATTRI_TO_SEARCH = ['msDS-SupportedEncryptionTypes', 'sAMAccountName']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No LAPS Found"))
        else:
            print(success('Found LAPS Information'))
            try:
                if os.path.exists(f"LAPS.txt"):
                    os.remove(f"LAPS.txt")
                with open(f"LAPS.txt", 'a') as f:
                    print(check_success('Output LAPS Info to file'))
                    for entry in self.ldapconn.entries:
                        samaccount = str(entry.samaccount)

                        # Print one samaccount per line
                        f.write(str(samaccount) + '\n')
                        # splitting on space will only show the date, rather than date and time
                        print(samaccount)
                    f.close()
            except Exception as e:
                print(check_error(f"Error checking for LAPS: {e}"))
        print("")

    def get_domain_sid(self) -> None:
        OBJ_TO_SEARCH = f'(&(sAMAccountName={self.args.username}))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No SID Found"))
        else:
            print(success('Found Domain SID'))
            try:
                for entry in self.ldapconn.entries:
                    sid = str(entry.objectSid)
                    grab_sid = sid.split("-")[:-1]
                    dom_sid = "-".join(grab_sid[:-1])
                    print(dom_sid)
            except Exception as e:
                print(check_error(f"Error checking for LAPS: {e}"))
        print("")

    def stop_enum(self) -> None:
        self.endtime = datetime.now()
        total = self.endtime - self.begintime
        total = str(total)
        print(success(f"LDAP Enumeration completed in {total}"))
        self.ldapconn.unbind()
        quit()

    def setup_impacket(self, dc_ip) -> list:
        impacket_args = []
        if dc_ip:
            impacket_args.append("-dc-ip")
            impacket_args.append(dc_ip)
        process =  subprocess.run(impacket_args, check=True, stdout=subprocess.PIPE)
        return process.stdout.decode().splitlines()

    def exploit_kerberoastable(self, targetUser: str, username: str, password: str, service:str, output_file: str) -> bool:
        successful = False
        # stripped_username = self.args.hash
        print(username)

    def main(self) -> None:
        self.args()
        self.banner()
        if self.args.hash:
            if not ":" in self.args.hash:
                self.password = f"aad3b435b51404eeaad3b435b51404ee:{self.args.hash}"
            else:
                self.password = self.args.hash
            self.ldap_connect_ntlm(self.args.domaincontroller, self.username, self.password)
        elif self.args.password:
            self.ldap_connect_cred(self.args.domaincontroller, self.username, self.password)
            
        self.kerberoast_accounts()
        self.asreproast_accounts()
        self.server_search()
        self.mssql_search()
        self.dc_search()
        self.admin_count_search()
        self.find_fields()
        self.find_ad_printers()
        if self.args.all:
            self.get_domain_sid()
            self.find_password_policy()
            self.get_all_users()
            self.get_all_computers()
            self.get_all_groups()
            self.get_gpo()
            self.get_laps()
        if self.args.sid:
            self.get_domain_sid()
        if self.args.passpol:
            self.find_password_policy()
        if self.args.users:
            self.get_all_users()
        if self.args.computers:
            self.get_all_computers()
        if self.args.groups:
            self.get_all_groups()
        if self.args.gpo:
            self.get_gpo()
        if self.args.laps:
            self.get_laps()
        self.stop_enum()

if __name__ == "__main__":
    LDAPEnum().main()
