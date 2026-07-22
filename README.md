<div align="center">

# 🔺 Teste #02 — Escalada de Privilégio via Backdoor em Sudoers

### Simulação de persistência via `/etc/sudoers.d/`, detecção via FIM + análise de logs de sudo no Wazuh

![Wazuh](https://img.shields.io/badge/SIEM-Wazuh_4.14-1A73E8?style=for-the-badge&logo=wazuh&logoColor=white)
![MITRE](https://img.shields.io/badge/MITRE_ATT%26CK-T1548.003_%7C_T1078-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Detec%C3%A7%C3%A3o_confirmada-brightgreen?style=for-the-badge)

</div>

---

## 🎯 Objetivo

Simular uma técnica clássica de **persistência e escalada de privilégio**: um atacante que já obteve acesso a uma conta de baixo privilégio cria um "backdoor" de sudo (permissão de root sem senha) para um usuário, garantindo acesso irrestrito mesmo após a vulnerabilidade inicial ser corrigida.

**Técnicas MITRE ATT&CK envolvidas:**
- [T1548.003 — Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/)
- [T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)

## 🗺️ Cenário

| | |
|---|---|
| **Alvo** | `endpoint-linux` (Ubuntu 22.04, GCP) |
| **Usuário "comprometido"** | `usuarioteste` (sem privilégios de sudo antes do teste) |
| **Ação simulada** | Criação de arquivo em `/etc/sudoers.d/` concedendo `NOPASSWD:ALL` |
| **SIEM** | Wazuh Manager (GCP) |

---

## 🧨 Passo 1 — Criar o backdoor de privilégio

> ⚠️ Editar `/etc/sudoers` diretamente é arriscado — um erro de sintaxe quebra o `sudo` no sistema inteiro. O método usado (e também o mais comum em ataques reais, por ser discreto) é criar um arquivo separado em `/etc/sudoers.d/`, incluído automaticamente pelo sudoers principal.

```bash
echo "usuarioteste ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/backdoor-teste
sudo chmod 440 /etc/sudoers.d/backdoor-teste
```

## 🕵️ Passo 2 — Explorar o backdoor (do ponto de vista do "atacante")

```bash
sudo su - usuarioteste
whoami
# usuarioteste

sudo whoami
# root  ← sem pedir senha!

sudo cat /etc/shadow
# leitura do arquivo de hashes de senha do sistema

exit
```
<img width="767" height="124" alt="Captura de tela 2026-07-21 134707" src="https://github.com/user-attachments/assets/5f23423b-5894-4ce0-a570-13f50bf76b50" />

---

## 📊 Passo 3 — Detecção no Wazuh

### 3.1 — FIM: criação e modificação do arquivo de backdoor

<img width="1886" height="818" alt="Captura de tela 2026-07-21 134237" src="https://github.com/user-attachments/assets/809882c3-d67b-4aa7-9be2-f73e4c4cf330" />

---
| Time | Path | Action | Rule description | Level | Rule ID |
|---|---|---|---|---|---|
| Jul 21, 2026 @ 13:40:04.842 | `/etc/sudoers.d/backdoor-teste` | `added` | File added to the system | 5 | 554 |
| Jul 21, 2026 @ 13:40:04.865 | `/etc/sudoers.d/backdoor-teste` | `modified` | Integrity checksum changed | 7 | 550 |

O segundo evento (nível 7, mais alto) corresponde ao `chmod 440` — o FIM tratou a mudança de permissão como uma alteração distinta e mais sensível que a criação inicial.

---
<img width="1918" height="910" alt="Captura de tela 2026-07-21 135801" src="https://github.com/user-attachments/assets/7297233c-6d44-4fd8-90cd-8201f0054f56" />

---
### 3.2 — Uso de sudo pelo analista (criação da sessão de teste)

```json
{
  "rule": {
    "id": "5402",
    "level": 3,
    "description": "Successful sudo to ROOT executed.",
    "mitre": { "id": ["T1548.003"], "tactic": ["Privilege Escalation", "Defense Evasion"] }
  },
  "data": {
    "srcuser": "daviiqtrader",
    "dstuser": "root",
    "command": "/usr/bin/su - usuarioteste"
  }
}
```

Log correspondente da sessão PAM aberta:

```json
{
  "rule": {
    "id": "5501",
    "level": 3,
    "description": "PAM: Login session opened.",
    "mitre": {
      "id": ["T1078"],
      "tactic": ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"]
    }
  },
  "full_log": "sudo[2147]: pam_unix(sudo:session): session opened for user root(uid=0) by daviiqtrader(uid=1001)"
}
```
<img width="960" height="862" alt="Captura de tela 2026-07-21 134914" src="https://github.com/user-attachments/assets/a9c77536-709a-4935-8e08-c5452aee7f8c" />

---
### 3.3 — 🚨 Exploração real do backdoor pelo usuário de baixo privilégio

Este é o evento-chave do teste: `usuarioteste` — que **não tinha permissão de sudo antes do teste** — executando comandos como root **sem fornecer senha**, graças exclusivamente ao arquivo criado no Passo 1.

```json
{
  "agent": { "name": "endpoint-linux", "ip": "IP" },
  "data": {
    "srcuser": "usuarioteste",
    "dstuser": "root",
    "tty": "pts/1",
    "pwd": "/home/usuarioteste",
    "command": "/usr/bin/cat /etc/shadow"
  },
  "rule": {
    "id": "5403",
    "level": 4,
    "description": "First time user executed sudo.",
    "groups": ["syslog", "sudo"],
    "mitre": {
      "id": ["T1548.003"],
      "tactic": ["Privilege Escalation", "Defense Evasion"],
      "technique": ["Sudo and Sudo Caching"]
    }
  },
  "full_log": "sudo[2163]: usuarioteste : TTY=pts/1 ; PWD=/home/usuarioteste ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
}
```

### 🔍 Por que esse último evento é o mais relevante

| Aspecto | Observação |
|---|---|
| **Regra `5403`** (não `5402`) | O Wazuh distingue a **primeira vez** que um usuário específico executa sudo — um sinal de anomalia comportamental, já que `usuarioteste` nunca havia usado sudo antes |
| **Comando executado** | `cat /etc/shadow` — leitura do arquivo de hashes de senha, uma das ações pós-exploração mais críticas possíveis |
| **Nenhuma senha fornecida** | Resultado direto do `NOPASSWD:ALL` configurado no backdoor |
| **MITRE ATT&CK** | Mapeado automaticamente para `T1548.003`, tática de Privilege Escalation e Defense Evasion |

---

## 🧠 Lições aprendidas

1. **FIM em tempo real é essencial para `/etc/sudoers.d/`** — sem o monitoramento configurado nesse diretório (feito na calibração inicial do lab), a criação do backdoor passaria completamente despercebida até o momento da exploração.
2. **Regras de sudo diferenciam contexto, não só o comando** — o Wazuh distingue "uso normal de sudo por quem sempre usou" (`5402`) de "primeira vez que esse usuário usa sudo" (`5403`), um sinal de detecção comportamental valioso para reduzir falsos positivos em ambientes com muitos administradores legítimos.
3. **Mapeamento MITRE ATT&CK dinâmico** — diferentes eventos do mesmo cenário mapearam para técnicas e táticas diferentes (`T1548.003` para o uso de sudo, `T1078` para a sessão de conta válida), mostrando como múltiplos artefatos de log se conectam a diferentes estágios de uma mesma cadeia de ataque (kill chain).
4. **A criação de contas de teste isoladas** (`usuarioteste`) foi essencial para isolar claramente, nos logs, o que era atividade do analista (`daviiqtrader`) e o que era a "vítima" simulada — replicável para qualquer teste futuro que envolva contas de baixo privilégio.

---

## 📎 Referências

- [MITRE ATT&CK T1548.003 — Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Wazuh — File Integrity Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html)

---

<br>
<img width="1886" height="818" alt="Captura de tela 2026-07-21 134237" src="https://github.com/user-attachments/assets/59bec680-2f83-449f-8834-207db6f53aaa" />

---
>
> Esse teste reforçou pra mim o valor de correlacionar múltiplas fontes de telemetria (FIM + logs de autenticação) em vez de olhar para um único alerta isoladamente — é assim que se reconstrói a história completa de um incidente.
>
> Documentação completa (comandos, JSON dos eventos e análise) no repositório: [link do GitHub]
>
> #cybersecurity #soc #siem #wazuh #blueteam #homelab #infosec #mitreattack #privilegeescalation
