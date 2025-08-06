# ldapenum

`ldapenum.py` is a Python 3 script designed for enumerating Active Directory environments through LDAP. It allows security professionals and system administrators to quickly gather information about domain users, groups, computers, policies, and potential misconfigurations using either password or NTLM hash-based authentication.

The script is built using the `ldap3` library and is designed to be a single-file, dependency-light tool for reconnaissance during security assessments.

## Features

  - **Flexible Authentication**: Connect using either a clear-text password or an NTLM hash.
  - **Comprehensive Enumeration**: Gathers a wide range of domain information, including:
      - Kerberoastable & AS-REP Roastable accounts
      - Domain Controllers and MSSQL Servers
      - Users with privileged attributes (`adminCount=1`)
      - All domain users, groups, and computers
      - Domain password policy
      - Group Policy Objects (GPOs)
      - LAPS (Local Administrator Password Solution) data
      - Domain SID
  - **Finds Common Misconfigurations**:
      - Searches user description fields for potential credentials.
  - **Saves Output**: Automatically logs detailed results to `.txt` files for easy review (e.g., `users.txt`, `groups.txt`, `computers.txt`).
  - **Experimental Obfuscation**: Includes an option to obfuscate LDAP queries by hex-encoding values, which may help bypass simple detection rules.

## Requirements

  - Python 3.x
  - `ldap3` library

## Installation

1.  Clone the repository or download the `ldapenum.py` script.
2.  Install the required `ldap3` library:
    ```bash
    pip install ldap3
    ```

## Usage

The script requires a domain controller, a username, and credentials (password or hash) to run.

```bash
python3 ldapenum.py -D <DC_IP_or_HOSTNAME> -u <USERNAME> -p <PASSWORD> [OPTIONS]
```

### Arguments

| Argument               | Description                                                               |
| ---------------------- | ------------------------------------------------------------------------- |
| `-D`, `--domaincontroller` | **(Required)** IP address or hostname of the Domain Controller.           |
| `-u`, `--username`     | **(Required)** A valid domain username.                                   |
| `-p`, `--password`     | A valid domain password.                                                  |
| `-H`, `--hash`         | An NTLM hash for pass-the-hash authentication.                            |
| `-A`, `--all`          | Run all enumeration checks, including users, groups, computers, GPO, etc. |
| `-P`, `--passpol`      | Enumerate the domain password policy.                                     |
| `-U`, `--users`        | Enumerate all domain users.                                               |
| `-G`, `--groups`       | Enumerate all domain groups.                                              |
| `-C`, `--computers`    | Enumerate all domain computers.                                           |
| `--gpo`                | Enumerate Group Policy Objects.                                           |
| `--sid`                | Enumerate the Domain SID.                                                 |
| `-L`, `--laps`         | Enumerate LAPS information.                                               |
| `-O`, `--obfuscate`    | (Experimental) Attempt to obfuscate LDAP queries.                         |
| `-v`, `--verbose`      | Verbose mode. Prints the LDAP queries being run.                          |

## Examples

#### 1. Standard Enumeration with a Password

This runs the default set of checks (Kerberoastable, AS-REP Roastable, privileged users, DCs, MSSQL servers, etc.).

```bash
python3 ldapenum.py -D 10.10.10.100 -u jdoe -p 'Password123!'
```

#### 2. Comprehensive Enumeration with the `-A` flag

This runs all enumeration modules available in the script.

```bash
python3 ldapenum.py -D corp.local -u jdoe -p 'Password123!' -A
```

#### 3. Authentication with an NTLM Hash

Use the `-H` flag to authenticate with a user's NTLM hash.

```bash
python3 ldapenum.py -D 10.10.10.100 -u svc_admin -H 'a9f62bf4be137155415789225c59e7f9'
```

#### 4. Enumerating Only Domain Users and Groups

Specify the exact information you want to retrieve. The output will also be saved to `users.txt` and `groups.txt`.

```bash
python3 ldapenum.py -D 10.10.10.100 -u jdoe -p 'Password123!' -U -G
```

#### 5. Using Verbose and Obfuscation Mode

Run a full scan while printing the (obfuscated) LDAP queries to the console.

```bash
python3 ldapenum.py -D 10.10.10.100 -u jdoe -p 'Password123!' -A -v -O
```
