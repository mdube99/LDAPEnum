# LDAPEnum

LDAP Enumeration tool as an alternative to enum4linux. Allows for obfuscation of LDAP queries by turning certain queries into hex code.

![header](https://github.com/mdube99/LDAPEnum/blob/main/.img/header.png)

## Usage

```
usage: python3 LDAPEnum.py -D 10.10.0.44 -u test -p test -A
         [-h] [-D DOMAINCONTROLLER] [-H HASH] [-u USERNAME] [-p PASSWORD] [-A] [-P] [-U] [-G] [-C] [-O]
                                                                     [--gpo] [--sid] [-L]

options:
  -h, --help            show this help message and exit
  -D DOMAINCONTROLLER, --domaincontroller DOMAINCONTROLLER
                        Domain Controller
  -H HASH, --hash HASH  hash
  -u USERNAME, --username USERNAME
                        Username
  -p PASSWORD, --password PASSWORD
                        Password
  -A, --all             Print all available options
  -P, --passpol         Print out password policy
  -U, --users           Print out domain users.
  -G, --groups          Print out domain groups.
  -C, --computers       Print out domain computers.
  -O, --obfuscate       (Experimental) Obfuscate LDAP Queries
  --gpo                 Print out Group Policy Objects
  --sid                 Print out Domain SID
  -L, --laps            Print out LAPS information.
```
