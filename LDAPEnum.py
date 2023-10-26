#!/usr/bin/env python3

import ipaddress
import socket
from ldap3 import Server, Connection, ALL, NTLM
import ldap3
from datetime import datetime
import os
import os.path
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

def header(msg: str) -> str:
    return colors.HEADER + msg + colors.ENDC

def bold(msg: str) -> str:
    return colors.BOLD + msg + colors.ENDC

def check_error(msg: str) -> str:
    minus = colors.FAIL + '['  + '-' + ']' + colors.ENDC + ' '
    return minus + msg + '\n'

def check_success(msg: str) -> str:
    plus = colors.OKGREEN + '['  + '+' + ']' + colors.ENDC + ' '
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
    def __init__(self):
        pass

    def banner(self):
        print(bold(header('''
 /$$       /$$$$$$$   /$$$$$$  /$$$$$$$  /$$$$$$$$                                  
| $$      | $$__  $$ /$$__  $$| $$__  $$| $$_____/                                  
| $$      | $$  \ $$| $$  \ $$| $$  \ $$| $$       /$$$$$$$  /$$   /$$ /$$$$$$/$$$$ 
| $$      | $$  | $$| $$$$$$$$| $$$$$$$/| $$$$$   | $$__  $$| $$  | $$| $$_  $$_  $$
| $$      | $$  | $$| $$__  $$| $$____/ | $$__/   | $$  \ $$| $$  | $$| $$ \ $$ \ $$
| $$      | $$  | $$| $$  | $$| $$      | $$      | $$  | $$| $$  | $$| $$ | $$ | $$
| $$$$$$$$| $$$$$$$/| $$  | $$| $$      | $$$$$$$$| $$  | $$|  $$$$$$/| $$ | $$ | $$
|________/|_______/ |__/  |__/|__/      |________/|__/  |__/ \______/ |__/ |__/ |__/

        ''')))
        print("Author: Mark Dube\n")

    def args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-D', '--domaincontroller', type=str, help="Domain Controller")
        parser.add_argument('-H', '--hash', help="hash")
        parser.add_argument('-u', '--username', help="Username")
        parser.add_argument('-p', '--password', help="Password")
        parser.add_argument('-P', '--passpol', action='store_true', help="Print out users. Default: will only output to file.")
        parser.add_argument('-U', '--users', action='store_true', help="Print out users. Default: will only output to file.")
        parser.add_argument('-G', '--groups', action='store_true', help="Print out groups. Default: will only output to file.")
        parser.add_argument('-C', '--computers', action='store_true', help="Print out computers. Default: will only output to file.")
        parser.add_argument('-O', '--obfuscate', action='store_true', help="Obfuscate Queries. Default: Will not obfuscate.")
        self.args = parser.parse_args()

        self.hostname = self.args.domaincontroller
        self.username = self.args.username
        self.password = self.args.password

    def __search_ldap_server(self, OBJ_TO_SEARCH: str, ATTRI_TO_SEARCH: str | list) -> None:
        if self.args.obfuscate:
            # find everything between = and )
            query = re.findall(r'\((.*?)\)', OBJ_TO_SEARCH)
            # Turn first value from query into hex
            obfuscated_query = query[0].split("=")[1].encode('utf-8').hex(sep='\\')

            new = query[0].split("=")[1]
            newnew = f"={new})"
            # replace query with obfuscated query
            bar = str(f"=\\{obfuscated_query})")
            OBJ_TO_SEARCH = OBJ_TO_SEARCH.replace(newnew, bar)

        self.ldapconn.search(self.dom_1, OBJ_TO_SEARCH, attributes=ATTRI_TO_SEARCH)

    def authenticated_bind(self, hostname: str, username: str, password: str) -> None:
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
                print(f"LDAPS on port 636 also failed with error: {e}")

        with open(f"{hostname}.LDAPDump.txt", 'w') as f:
            f.write(str(self.server.info))
        print(check_success("Attempting to identify a domain naming convention...\n" + colors.ENDC))
        with open(f"{hostname}.LDAPDump.txt", 'r') as f:
            for line in f:
                if line.startswith("    DC="):
                    self.name_context = line.strip()
                    self.long_dc = self.name_context
                    self.dc_val = (self.name_context.count('DC='))
                    self.name_context = self.name_context.replace(
                        "DC=", "")
                    self.name_context = self.name_context.replace(",", ".")
                    if "ForestDnsZones" in self.name_context:
                        continue
                    else:
                        break
        self.dir_name = f"{self.name_context}"
        self.domain = self.name_context
        print(check_success(f'Creating a folder named {self.dir_name} to host file output.\n'))
        domain_contents = self.domain.split(".")
        print(check_success(f"Possible domain name found"))
        print(self.name_context)
        self.dom_1 = f"{self.long_dc}"
        try:
            self.ldapconn = Connection(
                self.server, user=f"{domain_contents[self.dc_val - 2]}\\{username}", password=password, auto_bind=True)
            self.ldapconn.bind()
        except ldap3.core.exceptions.LDAPBindError:
            print("Invalid credentials. Please try again.")
            quit()
        print(check_success(f"Connected to {hostname}\n"))


    def ntlm_bind(self, hostname: str, username: str, password: str) -> None:
        try:
            self.begintime = datetime.now()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            try:
                host_with_port = f'ldaps://{hostname}:636'
                self.server = Server(str(f'{host_with_port}'),
                                     port=636, use_ssl=True, get_info=ALL)
            except:
                self.server = Server(str(hostname), get_info=ALL)
            self.ldapconn = Connection(self.server, auto_bind=True)
            with open(f"{hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            print(success("Let's try to identify a domain naming convention for the domain.\n"))
            with open(f"{hostname}.ldapdump.txt", 'r') as f:
                for line in f:
                    if line.startswith("    DC="):
                        self.name_context = line.strip()
                        self.long_dc = self.name_context
                        self.dc_val = (self.name_context.count('DC='))
                        self.name_context = self.name_context.replace(
                            "DC=", "")
                        self.name_context = self.name_context.replace(",", ".")
                        if "ForestDnsZones" in self.name_context:
                            continue
                        else:
                            break
            self.dir_name = f"{self.name_context}"
            self.domain = self.name_context
            print(success(f'Creating a folder named {self.dir_name} to host file output.\n'))
            try:
                os.mkdir(self.dir_name)
                os.rename(f"{hostname}.ldapdump.txt",
                          f"ldapdump.txt")
            except FileExistsError:
                os.remove(f"ldapdump.txt")
                os.rename(f"{hostname}.ldapdump.txt",
                          f"ldapdump.txt")
                pass
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(success(f"Possible domain name found - {self.name_context}"))
            self.dom_1 = f"{self.long_dc}"
            try:
                self.ldapconn = Connection(
                    self.server, user=f"{self.domain}\\{username}", password=password, auto_bind=True, authentication=NTLM)
                self.ldapconn.bind()
            except ldap3.core.exceptions.LDAPBindError:
                print("Invalid credentials. Please try again.")
                quit()

        except (ipaddress.AddressValueError, socket.herror):
            print(
                "[error] Invalid IP Address or unable to contact host. Please try again.")
            quit()
        except socket.timeout:
            print(
                "[error] Timeout while trying to contact the host. Please try again.")
            quit()
        # except Exception as e:
        #     print(f"[error] - {e}")
        #     quit()




    def kerberoast_accounts(self) -> None:
        # Query LDAP for Kerberoastable users - searching for SPNs where user is a normal user and account is not disabled
        OBJ_TO_SEARCH = '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No Kerberoastable Users"))
        else:
            ldap_entries = self.ldapconn.entries
            print(success("Kerberoastable Users"))
            ldap_entries = str(ldap_entries)
            for kerb_users in self.ldapconn.entries:
                print(kerb_users.sAMAccountName)
        print("")

    def asreproast_accounts(self):
        # Query LDAP for ASREPRoastable Users
        OBJ_TO_SEARCH = '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))'

        ATTRI_TO_SEARCH = 'sAMAccountName'
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error("No ASREPRoastable Users"))
        else:
            ldap_entries = self.ldapconn.entries
            print(success("ASREPRoastable Users"))
            ldap_entries = str(ldap_entries)
            for asrep_users in self.ldapconn.entries:
                print(asrep_users.sAMAccountName)
        print("")

    def server_search(self) -> None:
        # Query LDAP for computer accounts
        OBJ_TO_SEARCH = '(&(objectClass=computer)(!(objectclass=msDS-ManagedServiceAccount)))'
        ATTRI_TO_SEARCH = ['name', 'operatingsystem']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        ldap_entries = self.ldapconn.entries
        print(success("Domain Joined Servers"))
        ldap_entries = str(ldap_entries)
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
        ldap_entries = self.ldapconn.entries
        print(success('Domain Controllers'))
        ldap_entries = str(ldap_entries)
        for dc_accounts in self.ldapconn.entries:
            try:
                print(dc_accounts.dNSHostName)
            except ldap3.core.exceptions.LDAPCursorAttributeError:
                print(dc_accounts.name)
        print("")

    def trusted_domains(self) -> None:
        OBJ_TO_SEARCH = '(objectclass=trusteddomain)'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not str(self.ldapconn.entries):
            print(error('No Domain Trusts Found\n'))
        else:
            print(success('\nDomain Trusts'))
            for trust_vals in self.ldapconn.entries:
                if trust_vals.trustDirection == 0:
                    trust_id = "Disabled"
                if trust_vals.trustDirection == 1:
                    trust_id = "<- Inbound"
                if trust_vals.trustDirection == 2:
                    trust_id = "-> Outbound"
                if trust_vals.trustDirection == 3:
                    trust_id = "<-> Bi-Directional"

                    print(f"{trust_id} trust with {trust_vals.trustPartner}")
        print("")

    def mssql_search(self) -> None:
        # Query LDAP for MSSQL Servers
        OBJ_TO_SEARCH = '(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        if not self.ldapconn.entries:
            print(error('No MSSQL Servers Found'))
        else:
            print(success('MSSQL Servers'))
            if os.path.exists(f"mssqlservers.txt"):
                os.remove(f"mssqlservers.txt")
            with open(f"mssqlservers.txt", 'a') as f:
                f.write(str(self.ldapconn.entries))
                f.close()
            with open(f"mssqlservers.txt", 'r+') as f:
                comp_val = 0
                for line in f:
                    if line.startswith('    dNSHostName: '):
                        comp_name = line.strip()
                        comp_name = comp_name.replace('dNSHostName: ', '')
                        comp_name = comp_name.replace('$', '')
                        print(comp_name)
                        comp_val += 1
                        if comp_val >= 25:
                            print(success(f'Truncating results at 25. Check {self.domain}.computers.txt for full details.'))
                            break
                f.close()
        print("")

    def admin_count_search(self) -> None:
        # Query LDAP for users with adminCount=1
        OBJ_TO_SEARCH = '(&(!(memberof=Builtin))(adminCount=1)(objectclass=person)(objectCategory=Person))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        ldap_entries = self.ldapconn.entries
        # print('\n' + '-'*29 + 'Protected Admin Users' + '-'*29 + '\n\nThese are user accounts with adminCount=1 set\n')
        print(success('Protected Admin Users'))
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
        print(success('Checking for printers connected to Active Directory environment'))
        OBJ_TO_SEARCH = '(&(uncName=*lon-prnt*)(objectCategory=printQueue)(printColor=TRUE))'
        ATTRI_TO_SEARCH = ldap3.ALL_ATTRIBUTES
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        for entry in self.ldapconn.entries:
            print(entry)
        print("")

    def find_password_policy(self) -> None:
        print(success('Domain Password Policy'))
        OBJ_TO_SEARCH = '(objectClass=*)'
        ATTRI_TO_SEARCH =  ['forceLogoff', 'lockoutDuration', 'lockOutObservationWindow', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        ldap_entries = str(self.ldapconn.entries)
        self.dir_name = f"{self.name_context}"
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


    def store_password_cleartext(self) -> None:
        print(success('Potential Cleartext Passwords'))
        OBJ_TO_SEARCH = '(&(objectclass=user)(objectCategory=*)(useraccountcontrol=128))'
        ATTRI_TO_SEARCH = ['sAMAccountName', 'displayname', 'lastlogontimestamp', 'lastlogon', 'whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        ldap_entries = str(self.ldapconn.entries)
        self.dir_name = f"{self.name_context}"
        print(ldap_entries)
        print("")

    def get_all_users(self) -> None:
        print(success('All Domain Users'))
        OBJ_TO_SEARCH = '(&(objectclass=user)(objectcategory=person)(objectcategory=user))'
        ATTRI_TO_SEARCH = ['name', 'sAMAccountName', 'whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        self.dir_name = f"{self.name_context}"
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
        OBJ_TO_SEARCH = '(&(objectclass=computer))'
        ATTRI_TO_SEARCH = [ 'sAMAccountName', 'name','operatingSystem','operatingSystemServicePack','whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
# Perform the LDAP search
        self.dir_name = f"{self.name_context}"
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
        OBJ_TO_SEARCH = '(&(objectclass=group))'
        ATTRI_TO_SEARCH = [ 'sAMAccountName', 'name','whencreated', 'whenchanged']
        self.__search_ldap_server(OBJ_TO_SEARCH, ATTRI_TO_SEARCH)
        self.dir_name = f"{self.name_context}"
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

    def stop_enum(self) -> None:
        self.endtime = datetime.now()
        total = self.endtime - self.begintime
        total = str(total)
        print(success(f"LDAP Enumeration completed in {total}"))
        self.ldapconn.unbind()
        quit()

    def main(self) -> None:
        self.args()
        self.banner()
        # if self.args.domaincontroller:
        #     self.check_ports(self.args.domaincontroller)
        if self.args.hash:
            if not ":" in self.args.hash:
                self.password = f"aad3b435b51404eeaad3b435b51404ee:{self.args.hash}"
            self.ntlm_bind(self.args.domaincontroller, self.username, self.password)
        elif self.args.password:
            self.authenticated_bind(self.args.domaincontroller, self.username, self.password)
            
        self.kerberoast_accounts()
        self.asreproast_accounts()
        self.server_search()
        self.dc_search()
        self.mssql_search()
        self.admin_count_search()
        self.find_fields()
        self.find_ad_printers()
        if self.args.passpol:
            self.find_password_policy()
        # self.store_password_cleartext()
        if self.args.users:
            self.get_all_users()
        if self.args.computers:
            self.get_all_computers()
        if self.args.groups:
            self.get_all_groups()
        self.stop_enum()

if __name__ == "__main__":
    LDAPEnum().main()
