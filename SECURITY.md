# Política de Segurança

## Atenção: o painel não tem autenticação

Quem alcançar a porta do painel vê quem acessou, alterou, renomeou e apagou cada arquivo.
Por isso:

- **Nunca exponha o painel na internet.**
- Publique-o atrás de um reverse proxy (por exemplo, Nginx Proxy Manager) com HTTPS e
  uma **Access List** (rede do TI ou usuário e senha).
- Limite a porta do painel ao IP do proxy (firewall) ou, se o proxy estiver na mesma máquina,
  use `SAMBA_AUDIT_HOST=127.0.0.1`.

## Dados sensíveis

O banco SQLite contém usuários, IPs e caminhos de arquivos. Este repositório é público:
**nunca** faça commit de `*.db`, `*.db-wal`, `*.db-shm`, backups (`*.bkp`), logs ou do arquivo `.env`.
O `.gitignore` já cobre esses casos. Confira com `git status` antes de cada commit.

## Privilégios

O app precisa ler `/var/log/syslog`. Em vez de rodar como root, considere um usuário
dedicado no grupo `adm` (no Debian/Ubuntu esse grupo lê o syslog).

## Reportando vulnerabilidades

Não abra uma issue pública com detalhes. Use "Report a vulnerability" na aba Security
do repositório (se estiver habilitado) ou contate o mantenedor pelo perfil do GitHub.
