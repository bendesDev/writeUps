# security-writeups

Write-ups de pentest e Red Team (HackTheBox, TryHackMe e CTFs) documentados
no formato de metodologia real — recon, exploração, causa raiz e
remediação. Foco em Active Directory, aplicações web e infraestrutura
Linux/Windows.

Cada máquina tem uma versão em português (`README.md`) e uma em inglês
(`README.en.md`).

## Estrutura

```
writeUps/
├── templates/
│   └── TEMPLATE.md            ← modelo base para qualquer write-up novo
├── htb/                       ← HackTheBox (Retired Machines apenas)
│   ├── Getting-Started/
│   ├── Nibbles/
│   ├── Oopsie/
│   └── Vaccine/
└── thm/                       ← TryHackMe
    ├── CowboyHacker/
    ├── Guided-Pentest-Infra/
    └── RecruitX/
```

Cada write-up segue a mesma estrutura: **Resumo/TL;DR → Reconhecimento →
Obtenção de Acesso → Escalação de Privilégio → Causa Raiz & Remediação →
Lições Aprendidas**. O objetivo é registrar não só o "como", mas o
raciocínio por trás de cada decisão técnica.

## Índice

| Máquina | Plataforma | Dificuldade | Tags |
|---|---|---|---|
| [Oopsie](htb/Oopsie/README.md) ([EN](htb/Oopsie/README.en.md)) | HackTheBox | Easy | IDOR, upload irrestrito, SUID path traversal |
| [Vaccine](htb/Vaccine/README.md) ([EN](htb/Vaccine/README.en.md)) | HackTheBox | Easy | FTP anônimo, SQL injection, sudo GTFOBins |
| [Nibbles](htb/Nibbles/README.md) | HackTheBox | Easy | Nibbleblog, CVE-2015-6967, sudo misconfig |
| [Getting Started](htb/Getting-Started/README.md) ([EN](htb/Getting-Started/README.en.md)) | HackTheBox | Very Easy | GetSimple CMS, credenciais padrão, sudo PHP |
| [RecruitX v2.4](thm/RecruitX/README.md) ([EN](thm/RecruitX/README.en.md)) | TryHackMe | — | IDOR, account takeover, RCE via upload bypass |
| [Cowboy Hacker](thm/CowboyHacker/README.md) ([EN](thm/CowboyHacker/README.en.md)) | TryHackMe | — | FTP anônimo, brute force, GTFOBins (tar) |
| [Guided Pentest — Infra](thm/Guided-Pentest-Infra/README.md) ([EN](thm/Guided-Pentest-Infra/README.en.md)) | TryHackMe | Easy (guiado) | Recon de infra, escalada de privilégios |

## Política de publicação

- **HackTheBox:** apenas *Retired Machines*, em conformidade com os ToS
  da plataforma. Flags nunca são publicadas por completo — sempre
  parcialmente redigidas (ex: `af13b0be...eacf`).
- **TryHackMe / CTFs:** publicados após o encerramento do evento/sala,
  quando aplicável, com o mesmo critério de redação de flags.

## Sobre

Escritos por [bendesDev](https://github.com/bendesDev) — Networks/Infra &
Security Analyst, em transição para Red Team / pentest.
