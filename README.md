# Samba Audit Dashboard

Sistema de relatório e auditoria de acesso ao Samba. Lê os eventos do `vfs_full_audit`
no syslog, grava em SQLite e mostra um painel web.

## Funcionalidades

- **Tempo Real:** ranking de usuários, arquivos mais acessados e quem mais apagou, além dos últimos eventos.
- **Conectograma 2D/3D:** atividade dos usuários nas pastas de `/dados`, ao vivo (three.js).
- **Histórico e Busca:** tabela de eventos e impressão do relatório em PDF.

## Como funciona

    Samba (full_audit) -> syslog (LOCAL5) -> app.py (lê o log) -> SQLite -> API Flask -> painel web

## Requisitos

- Linux com Samba e `vfs_full_audit`; syslog gravando em `/var/log/syslog`
- Python 3 e Flask (`apt install python3-flask` ou `pip install flask`)
- Permissão de leitura no syslog (normalmente root ou grupo `adm`)
- O navegador precisa de internet: o painel carrega Tailwind, Chart.js e three.js de CDNs

## Configuração do Samba (exemplo)

    vfs objects = ... full_audit
    full_audit:prefix = %u|%I|%S
    full_audit:success = renameat unlinkat fchmod fchown write pwrite openat
    full_audit:failure = none
    full_audit:priority = NOTICE
    full_audit:facility = LOCAL5

No Debian/Ubuntu, o rsyslog padrão já grava a facility `local5` em `/var/log/syslog`.
Cada evento chega como `smbd_audit: usuario|ip|share|operacao|status|...|caminho`.

## Instalação

    git clone https://github.com/ranzes/samba-audit-dashboard.git /opt/samba_audit
    cd /opt/samba_audit
    python3 app.py

Abra `http://SERVIDOR:3000`. Exemplo de serviço systemd:

    [Unit]
    Description=Samba Audit Dashboard Web
    After=network.target smbd.service

    [Service]
    WorkingDirectory=/opt/samba_audit
    EnvironmentFile=-/opt/samba_audit/.env
    ExecStart=/usr/bin/python3 /opt/samba_audit/app.py
    Restart=always

    [Install]
    WantedBy=multi-user.target

## Variáveis de ambiente

Veja `.env.example`. Todas são opcionais.

| Variável | Padrão |
|---|---|
| `SAMBA_AUDIT_DB` | `samba_audit.db` (relativo à pasta de execução) |
| `SAMBA_AUDIT_LOG` | `/var/log/syslog` |
| `SAMBA_AUDIT_BASE_DIR` | `/dados` |
| `SAMBA_AUDIT_HOST` | `0.0.0.0` |
| `SAMBA_AUDIT_PORT` | `3000` |

## Rotas

| Rota | Descrição |
|---|---|
| `/` | Painel |
| `/api/dashboard` | Rankings (calculados em segundo plano) |
| `/api/logs?limit=N` | Últimos N eventos |
| `/api/radar/dirs?setor=X` | Pastas de `/dados` para o conectograma |
| `/api/radar/events?after_id=N` | Novos eventos para o conectograma |
| `/radar` | Conectograma em página avulsa |

## Limitações conhecidas

- **Sem login.** Leia o [SECURITY.md](SECURITY.md) antes de publicar.
- `/api/logs` só aplica o `limit`; os filtros de data, usuário, IP e arquivo da tela de Histórico ainda não são aplicados no servidor.
- O banco cresce sem limite e não tem índices além do `id`. Os rankings consideram os 2 milhões de registros mais recentes.
- Dependência de CDNs externas no navegador.
- Ainda não há licença definida.
