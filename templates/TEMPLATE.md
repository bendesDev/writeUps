# [Nome da Máquina] — HackTheBox

**Plataforma:** HackTheBox
**Dificuldade:** [Easy / Medium / Hard]
**SO:** [Linux / Windows]
**Data:** DD/MM/AAAA
**Tags:** #enum #foothold #privesc #[outras]
**Status:** Retired ✅ (publicação em conformidade com os ToS do HTB)

---

## Resumo

Breve parágrafo (3-5 linhas): qual foi o vetor inicial, qual vulnerabilidade central
foi explorada (com CVE se houver), e qual foi o caminho de escalação de privilégio.
Isso permite que quem leia o write-up entenda o essencial sem precisar ler tudo.

**Técnicas demonstradas:** enumeração web, [ex: unrestricted file upload / RCE],
[ex: credential guessing], privilege escalation via [ex: sudoers misconfiguration].

---

## 1. Reconhecimento

### 1.1 Varredura de portas

```
[comando nmap + output]
```

Breve interpretação do resultado: quais serviços chamam atenção e por quê.

### 1.2 Enumeração do serviço web

```
[curl / gobuster / etc + output]
```

Explicar o raciocínio de cada passo — não só "o que" foi rodado, mas "por que"
esse foi o próximo passo lógico dado o que já se sabia até ali.

---

## 2. Obtendo Acesso (Foothold)

### 2.1 Vulnerabilidade identificada

Nome da vulnerabilidade, versão afetada, e **CVE** (se existir), com uma frase
de contexto sobre o que ela permite.

### 2.2 Exploração

```
[payload / comando / output]
```

### 2.3 Rota alternativa (se aplicável)

Se você usou Metasploit ou outra ferramenta além do caminho manual, documente
aqui como uma segunda opção — mostra domínio de mais de uma abordagem.

```
[msfconsole / script / output]
```

---

## 3. Escalação de Privilégio

### 3.1 Enumeração local

```
[sudo -l / linpeas / etc + output]
```

### 3.2 Exploração

```
[comando + output]
```

### 3.3 Caminho alternativo de privesc (opcional, mas valorizado)

Máquinas mais antigas costumam ter mais de um vetor (kernel exploit, serviço
mal configurado, etc). Documentar uma segunda rota mostra profundidade de
enumeração, não só "segui o primeiro caminho que funcionou".

---

## 4. Flags

```
user.txt: [redigido/hash parcial ou omitido]
root.txt: [redigido/hash parcial ou omitido]
```

> Nunca publique a flag completa — é a única informação que o HTB pede para
> não vazar, mesmo em máquinas retired.

---

## 5. Causa Raiz & Remediação

- **Causa raiz:** o que, na configuração/código, permitiu a exploração.
- **Remediação:** o que um time de segurança faria para corrigir (patch,
  hardening de configuração, validação de input, política de senha, etc).
- **Lição para ambientes reais:** uma frase conectando isso a um cenário
  corporativo (ex: PCI-CP, AD, infraestrutura) — isso é o que diferencia
  o write-up de portfólio de um write-up genérico de CTF.

---

## Referências

- CVE-XXXX-XXXXX
- [Links de exploit-db, advisories, etc]
