#!/usr/bin/env python3

import ipaddress
import socket
from ldap3 import Server, Connection, ALL, NTLM
import ldap3
import sys
from datetime import datetime
import os
import os.path
import argparse
import textwrap

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

def blue(msg: str) -> str:
    return colors.OKBLUE + msg + colors.ENDC

def green(msg: str) -> str:
    return colors.OKGREEN + msg + colors.ENDC

def warning(msg: str) -> str:
    return colors.WARNING + msg + colors.ENDC

def fail(msg: str) -> str:
    return colors.FAIL + msg + colors.ENDC

def bold(msg: str) -> str:
    return colors.BOLD + msg + colors.ENDC

def error(msg: str) -> str:
    minus = colors.FAIL + '['  + '-' + ']' + colors.ENDC + ' '
    return minus + msg

def success(msg: str) -> str:
    plus = colors.OKGREEN + '['  + '+' + ']' + colors.ENDC + ' '
    return plus + msg


class LDAP:
    def __init__(self):
        pass

    def banner(self):
        print(bold(header('''
$$$$$$$$\ $$\    $$\ $$\      $$\       $$\       $$$$$$$\   $$$$$$\  $$$$$$$\        $$$$$$$$\                                   
$$  _____|$$ |   $$ |$$$\    $$$ |      $$ |      $$  __$$\ $$  __$$\ $$  __$$\       $$  _____|                                  
$$ |      $$ |   $$ |$$$$\  $$$$ |      $$ |      $$ |  $$ |$$ /  $$ |$$ |  $$ |      $$ |      $$$$$$$\  $$\   $$\ $$$$$$\$$$$\  
$$$$$\    \$$\  $$  |$$\$$\$$ $$ |      $$ |      $$ |  $$ |$$$$$$$$ |$$$$$$$  |      $$$$$\    $$  __$$\ $$ |  $$ |$$  _$$  _$$\ 
$$  __|    \$$\$$  / $$ \$$$  $$ |      $$ |      $$ |  $$ |$$  __$$ |$$  ____/       $$  __|   $$ |  $$ |$$ |  $$ |$$ / $$ / $$ |
$$ |        \$$$  /  $$ |\$  /$$ |      $$ |      $$ |  $$ |$$ |  $$ |$$ |            $$ |      $$ |  $$ |$$ |  $$ |$$ | $$ | $$ |
$$ |         \$  /   $$ | \_/ $$ |      $$$$$$$$\ $$$$$$$  |$$ |  $$ |$$ |            $$$$$$$$\ $$ |  $$ |\$$$$$$  |$$ | $$ | $$ |
\__|          \_/    \__|     \__|      \________|\_______/ \__|  \__|\__|            \________|\__|  \__| \______/ \__| \__| \__|

        ''')))
        print("Author: Mark Dube\n")

    def args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-DC', '--domaincontroller', type=str, help="Domain Controller")
        parser.add_argument('-a', '--anon', action='store_true', help="anonymous")
        parser.add_argument('-H', '--hash', help="anonymous")
        parser.add_argument('-U', '--username', help="Username")
        parser.add_argument('-P', '--password', help="Password")
        self.args = parser.parse_args()

        self.hostname = self.args.domaincontroller
        self.username = self.args.username
        self.password = self.args.password

    def check_ports(self, subnet):
        socket.setdefaulttimeout(0.05)
        ports_wanted = [389, 636, 3269]
        print(success(f'Checking for possible domain controllers on {subnet} subnet'))

        for host in range(1, 254):
            for port in ports_wanted:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ip_address = subnet[:subnet.rfind('.')+1] + str(host)
                    s.connect((ip_address, port))

                    if port in ports_wanted:
                        try:
                            host_resolve = socket.gethostbyaddr(ip_address)[0]
                            print(success(f'Possible Domain controller found at {ip_address} - {host_resolve}'))
                        except Exception:
                            print(success(f'Possible Domain controller found at {ip_address}'))
                            break
                    s.close()
                except (ConnectionRefusedError, AttributeError, OSError):
                    pass
        print(header("\n[info] Scan of the provided subnet is complete. Try to use any identified IP addresses for additional enumeration."))

    def anonymous_bind(self, hostname):
        try:
            self.t1 = datetime.now()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            try:
                s.connect(hostname, 636)
                server_val = f'ldaps://{hostname}:636'
                self.server = Server(str(f'{server_val}'),
                                     port=636, use_ssl=True, get_info=ALL)
            except:
                self.server = Server(str(hostname), get_info=ALL)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            print("[info] Let's try to identify a domain naming convention for the domain.\n")
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
                    if "dNSHostName" in self.name_context:
                        print(self.server.info)
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(f"[success] Possible domain name found - {self.name_context}\n")
            
            self.dom_1 = f"{self.long_dc}"
            print(f'[info] All set for now. Come back with credentials to dump additional domain information. Full raw output saved as {hostname}.ldapdump.txt\n')
            self.t2 = datetime.now()
            total = self.t2 - self.t1
            total = str(total)
            print( f"LDAP enumeration completed in {total}.\n")
        except (ipaddress.AddressValueError, socket.herror):
            print("[error] Invalid IP Address or unable to contact host. Please try again.")
            quit()
        except socket.timeout:
            print( "[error] Timeout while trying to contact the host. Please try again.")
            quit()
        except Exception as e:
            print(f"[error] - {e}")
            quit()

    def authenticated_bind(self, hostname, username, password):
        self.t1 = datetime.now()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(5)
        try:
            print(colors.OKBLUE + "Attempting LDAPS" + colors.ENDC)
            server_val = f'ldaps://{hostname}:636'
            self.server = Server(str(server_val), port=636, use_ssl=True, get_info=ALL)
            self.conn = Connection(self.server, auto_bind=True)
        except:
            try:
                print(error("LDAPS failed, attempting LDAP"))
                server_val = f'ldap://{hostname}:389'
                self.server = Server(str(server_val), port=389, use_ssl=True, get_info=ALL)
                self.conn = Connection(self.server, auto_bind=True)
                print(success("LDAP connection successful"))
            except Exception as e:
                print(f"LDAPS on port 636 also failed with error: {e}")

        with open(f"{hostname}.ldapdump.txt", 'w') as f:
            f.write(str(self.server.info))
        print( "[info] Let's try to identify a domain naming convention for the domain.\n")
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
        print(f'[info] Creating a folder named {self.dir_name} to host file output.\n')
        try:
            os.mkdir(self.dir_name)
            os.rename(f"{hostname}.ldapdump.txt",
                        f"{self.dir_name}\\{self.domain}.ldapdump.txt")
        except FileExistsError:
            os.remove(f"{self.dir_name}\\{self.domain}.ldapdump.txt")
            os.rename(f"{hostname}.ldapdump.txt",
                        f"{self.dir_name}\\{self.domain}.ldapdump.txt")
            pass
        domain_contents = self.domain.split(".")
        print(f"[success] Possible domain name found - {self.name_context}\n")
        self.dom_1 = f"{self.long_dc}"
        try:
            self.conn = Connection(
                self.server, user=f"{domain_contents[self.dc_val - 2]}\\{username}", password=password, auto_bind=True)
            self.conn.bind()
        except ldap3.core.exceptions.LDAPBindError:
            print("Invalid credentials. Please try again.")
            quit()
        print(f"[success] Connected to {hostname}.\n")
        self.kerberoast_accounts()
        self.aspreproast_accounts()
        self.server_search()
        self.ad_search()
        self.mssql_search()
        self.admin_count_search()
        self.find_fields()
        self.find_ad_printers()

    def ntlm_bind(self, hostname, username, password):
        try:
            self.t1 = datetime.now()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(5)
            try:
                server_val = f'ldaps://{hostname}:636'
                self.server = Server(str(f'{server_val}'),
                                     port=636, use_ssl=True, get_info=ALL)
            except:
                self.server = Server(str(hostname), get_info=ALL)
            self.conn = Connection(self.server, auto_bind=True)
            with open(f"{hostname}.ldapdump.txt", 'w') as f:
                f.write(str(self.server.info))
            print("[info] Let's try to identify a domain naming convention for the domain.\n")
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
            print(f'[info] Creating a folder named {self.dir_name} to host file output.\n')
            try:
                os.mkdir(self.dir_name)
                os.rename(f"{hostname}.ldapdump.txt",
                          f"{self.dir_name}\\{self.domain}.ldapdump.txt")
            except FileExistsError:
                os.remove(f"{self.dir_name}\\{self.domain}.ldapdump.txt")
                os.rename(f"{hostname}.ldapdump.txt",
                          f"{self.dir_name}\\{self.domain}.ldapdump.txt")
                pass
            self.domain = self.name_context
            domain_contents = self.domain.split(".")
            print(f"[success] Possible domain name found - {self.name_context}\n")
            self.dom_1 = f"{self.long_dc}"
            try:
                self.conn = Connection(
                    self.server, user=f"{self.domain}\\{username}", password=password, auto_bind=True, authentication=NTLM)
                self.conn.bind()
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

    def kerberoast_accounts(self):
        # Query LDAP for Kerberoastable users - searching for SPNs where user is a normal user and account is not disabled
        self.conn.search(f'{self.dom_1}', '(&(&(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512))(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))',
                         attributes=[ldap3.ALL_ATTRIBUTES])
        if not self.conn.entries:
            print(colors.FAIL + '\n' + '-'*29 + 'No Kerberoastable Users' + '-'*28 + '\n' + colors.ENDC)
        else:
            entries_val = self.conn.entries
            print(colors.HEADER + '\n' + '-'*30 + 'Kerberoastable Users' + '-'*30 + '\n' + colors.ENDC)
            entries_val = str(entries_val)
            for kerb_users in self.conn.entries:
                print(kerb_users.sAMAccountName)
            if os.path.exists(f"{self.dir_name}\\{self.domain}.kerberoast.txt"):
                os.remove(f"{self.dir_name}\\{self.domain}.kerberoast.txt")
            with open(f"{self.dir_name}\\{self.domain}.kerberoast.txt", 'w') as f:
                f.write(entries_val)
                f.close()

    def aspreproast_accounts(self):
        # Query LDAP for ASREPRoastable Users
        self.conn.search(f'{self.dom_1}', '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))', attributes=[
            'sAMAccountName'])
        if not self.conn.entries:
            print(colors.FAIL + '\n' + '-'*29 + 'No ASREPRoastable Users' + '-'*28 + '\n' + colors.ENDC)
        else:
            entries_val = self.conn.entries
            print(colors.HEADER + '\n' + '-'*30 + 'ASREPRoastable Users' + '-'*30 + '\n' + colors.ENDC)
            entries_val = str(entries_val)
            for asrep_users in self.conn.entries:
                print(asrep_users.sAMAccountName)
            if os.path.exists(f"{self.dir_name}\\{self.domain}.asreproast.txt"):
                os.remove(f"{self.dir_name}\\{self.domain}.asreproast.txt")
            with open(f"{self.dir_name}\\{self.domain}.asreproast.txt", 'w') as f:
                f.write(entries_val)
                f.close()

    def server_search(self):
        # Query LDAP for computer accounts
        self.conn.search(f'{self.dom_1}', '(&(objectClass=computer)(!(objectclass=msDS-ManagedServiceAccount)))',
                         attributes=['name', 'operatingsystem'])
        entries_val = self.conn.entries
        print('\n' + '-'*37 + 'Servers' + '-'*36 + '\n')
        entries_val = str(entries_val)
        for comp_account in self.conn.entries:
            comp_account1 = str(comp_account).lower()
            if "server" in comp_account1:
                print(f"{comp_account.name} - {comp_account.operatingsystem}")
        if os.path.exists(f"{self.dir_name}\\{self.domain}.servers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.servers.txt")
        with open(f"{self.dir_name}\\{self.domain}.servers.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def ad_search(self):
        # Query LDAP for domain controllers
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*31 + 'Domain Controllers' + '-'*31 + '\n')
        entries_val = str(entries_val)
        for dc_accounts in self.conn.entries:
            try:
                print(dc_accounts.dNSHostName)
            except ldap3.core.exceptions.LDAPCursorAttributeError:
                print(dc_accounts.name)

        if os.path.exists(f"{self.dir_name}\\{self.domain}.domaincontrollers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.domaincontrollers.txt")
        with open(f"{self.dir_name}\\{self.domain}.domaincontrollers.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def trusted_domains(self):
        self.conn.search(f'{self.dom_1}', '(objectclass=trusteddomain)',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*33 + 'Trusted Domains' + '-'*32 + '\n')
        entries_val = str(entries_val)
        for trust_vals in self.conn.entries:
            if trust_vals.trustDirection == 0:
                trust_id = "Disabled"
            if trust_vals.trustDirection == 1:
                trust_id = "<- Inbound"
            if trust_vals.trustDirection == 2:
                trust_id = "-> Outbound"
            if trust_vals.trustDirection == 3:
                trust_id = "<-> Bi-Directional"

                print(f"{trust_id} trust with {trust_vals.trustPartner}")
        if os.path.exists(f"{self.dir_name}\\{self.domain}.domaintrusts.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.domaintrusts.txt")
        with open(f"{self.dir_name}\\{self.domain}.domaintrusts.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def mssql_search(self):
        # Query LDAP for MSSQL Servers
        self.conn.search(f'{self.dom_1}', '(&(sAMAccountType=805306368)(servicePrincipalName=MSSQL*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        if not self.conn.entries:
            print(colors.FAIL + '\n' + '-'*33 + 'No MSSQL Servers' + '-'*31 + '\n' + colors.ENDC)
        else:
            entries_val = self.conn.entries
            print('\n' + '-'*34 + 'MSSQL Servers' + '-'*33 + '\n')
            entries_val = str(entries_val)
            if os.path.exists(f"{self.dir_name}\\{self.domain}.mssqlservers.txt"):
                os.remove(f"{self.dir_name}\\{self.domain}.mssqlservers.txt")
            with open(f"{self.dir_name}\\{self.domain}.mssqlservers.txt", 'a') as f:
                f.write(entries_val)
                f.close()
            with open(f"{self.dir_name}\\{self.domain}.mssqlservers.txt", 'r+') as f:
                comp_val = 0
                for line in f:
                    if line.startswith('    dNSHostName: '):
                        comp_name = line.strip()
                        comp_name = comp_name.replace('dNSHostName: ', '')
                        comp_name = comp_name.replace('$', '')
                        print(comp_name)
                        comp_val += 1
                        if comp_val >= 25:
                            print(f'\n[info] Truncating results at 25. Check {self.domain}.computers.txt for full details.')
                            break
                f.close()

    def exchange_search(self):
        # Query LDAP for Exchange Servers
        self.conn.search(f'{self.dom_1}', '(&(objectCategory=Computer)(servicePrincipalName=exchangeMDB*))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*32 + 'Exchange Servers' + '-'*32 + '\n')
        entries_val = str(entries_val)
        if os.path.exists(f"{self.dir_name}\\{self.domain}.exchangeservers.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.exchangeservers.txt")
        with open(f"{self.dir_name}\\{self.domain}.exchangeservers.txt", 'a') as f:
            f.write(entries_val)
            f.close()
        with open(f"{self.dir_name}\\{self.domain}.exchangeservers.txt", 'r+') as f:
            comp_val = 0
            for line in f:
                if line.startswith('    sAMAccountName: '):
                    comp_name = line.strip()
                    comp_name = comp_name.replace('sAMAccountName: ', '')
                    comp_name = comp_name.replace('$', '')
                    print(comp_name)
                    comp_val += 1
                    if comp_val >= 25:
                        print(f'\n[info] Truncating results at 25. Check {self.domain}.computers.txt for full details.')
                        break
            f.close()

    def admin_count_search(self):
        # Query LDAP for users with adminCount=1
        self.conn.search(f'{self.dom_1}', '(&(!(memberof=Builtin))(adminCount=1)(objectclass=person)(objectCategory=Person))',
                         attributes=ldap3.ALL_ATTRIBUTES)
        entries_val = self.conn.entries
        print('\n' + '-'*29 + 'Protected Admin Users' + '-'*29 + '\n\nThese are user accounts with adminCount=1 set\n')
        entries_val = str(entries_val)
        for admin_count_val in self.conn.entries:
            print(success(str(admin_count_val.name)))
        if os.path.exists(f"{self.dir_name}\\{self.domain}.admincount.txt"):
            os.remove(f"{self.dir_name}\\{self.domain}.admincount.txt")
        with open(f"{self.dir_name}\\{self.domain}.admincount.txt", 'a') as f:
            f.write(entries_val)
            f.close()

    def find_fields(self):
        print('\n[info] Checking user descriptions for interesting information.\n')
        self.conn.search(f"{self.dom_1}", '(&(objectClass=person)(objectCategory=Person))', attributes=[
                         'sAMAccountname', 'description'])
        for entry in self.conn.entries:
            if entry.description == 'Built-in account for administering the computer/domain':
                pass
            if entry.description == 'Built-in account for guest access to the computer/domain':
                pass
            val1 = str(entry.description)
            val2 = str(entry.sAMAccountname)
            # pass_val = 'pass'
            val3 = val1.lower()
            if "pass" in val3 or "pwd" in val3 or "cred" in val3:
                print(f'User: {val2} - Description: {val1}')

    def find_ad_printers(self):
        print('\n[info] Checking for printers connected to Active Directory environment.\n')
        self.conn.search(f"{self.dom_1}", '(&(uncName=*lon-prnt*)(objectCategory=printQueue)(printColor=TRUE))', attributes=ldap3.ALL_ATTRIBUTES)
        for entry in self.conn.entries:
            print(entry)

    def stop_enum(self):
        self.t2 = datetime.now()
        total = self.t2 - self.t1
        total = str(total)
        print(f"\nLDAP enumeration completed in {total}.\n")
        self.conn.unbind()
        quit()

    def main(self):
        self.args()
        self.banner()
        # if self.args.domaincontroller:
        #     self.check_ports(self.args.domaincontroller)
        if self.args.anon:
            self.anonymous_bind(self.args.domaincontroller)
        elif self.args.hash:
            if not ":" in self.args.hash:
                self.password = f"aad3b435b51404eeaad3b435b51404ee:{self.args.hash}"
            self.ntlm_bind(self.args.domaincontroller, self.username, self.password)
        elif self.args.password:
            self.authenticated_bind(self.args.domaincontroller, self.username, self.password)
            
        self.stop_enum()
