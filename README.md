# gopn - Um Gerenciador Avançado para OpenVPN3

![Go Version](https://img.shields.io/badge/go-1.21%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

`gopn` é um wrapper CLI (Interface de Linha de Comando) robusto e rico em funcionalidades, escrito em Go, para simplificar e automatizar o gerenciamento de conexões do `openvpn3`. Ele transforma a interação com o `openvpn3` em um fluxo de trabalho rápido, eficiente e amigável ao usuário.

## Por que usar o `gopn`?

Enquanto o cliente `openvpn3` é poderoso, seu uso diário pode ser repetitivo. O `gopn` atua como uma camada de conveniência inteligente, permitindo que você gerencie perfis de conexão, automatize logins complexos (com MFA) e controle suas sessões com comandos simples e intuitivos.

## Funcionalidades Principais

- 💾 **Gerenciamento de Perfis:** Salve e gerencie múltiplos perfis de conexão VPN em um arquivo de configuração simples.
- ⚡️ **Conexão Rápida e Flexível:** Conecte-se usando um nome de perfil e refine a conexão com flags (`--timeout`, `--ask-user`, etc.).
- 🔐 **Autenticação Inteligente:** Lida com prompts de senha de forma segura e possui lógica aprimorada para códigos MFA/TOTP.
- 🔌 **Desconexão Seletiva:** Desconecte todas as sessões ativas de uma vez ou apenas a sessão de um perfil específico.
- 📋 **Listagem Clara:** Visualize todos os seus perfis salvos com um único comando.
- 🚦 **Controle de Processo:** Suporte a `Ctrl+C` para cancelamento gracioso da conexão e timeouts configuráveis.
- 🐛 **Modo Verbose:** Use a flag `-v` para obter mais detalhes sobre o processo de conexão, ideal para depuração.

## Pré-requisitos

Antes de usar o `gopn`, você **precisa** ter os seguintes programas instalados no seu sistema:

1.  **Go:** Necessário para compilar o projeto (versão 1.21 ou superior).
2.  **OpenVPN3 Client:** O `gopn` é um wrapper, portanto ele **precisa** do `openvpn3` para funcionar.
    - Em **Arch Linux**: `yay -S openvpn3`
    - Em outras distribuições, siga as instruções do [site oficial do OpenVPN](https://openvpn.net/openvpn-3-linux/).

## Instalação (Compilando do Código-Fonte)

Para instalar o `gopn`, você pode compilar diretamente a partir do código-fonte.

```bash
# 1. Clone o repositório do GitHub
git clone https://github.com/PedroCamargo-dev/gopn.git

# 2. Entre no diretório do projeto
cd gopn

# 3. Compile o programa
go build -o gopn

# 4. (Opcional, mas recomendado) Mova o binário para uma pasta no seu PATH
#    Isso permite que você execute o comando 'gopn' de qualquer lugar.
sudo mv gopn /usr/local/bin/
```

## Como Usar

`gopn` utiliza uma estrutura de comandos simples e clara.

### `add`

Adiciona um novo perfil de conexão ao seu arquivo de configuração.

**Uso:** `gopn add <nome-do-perfil> <caminho/para/arquivo.ovpn> <seu-username>`
```bash
gopn add trabalho ~/vpn/empresa.ovpn p.test
```

---
### `connect`

Conecta-se a um perfil salvo. Este comando aceita várias flags para personalizar a conexão.

**Uso:** `gopn connect [flags] <nome-do-perfil>`
```bash
gopn connect trabalho
```

**Flags disponíveis:**
| Flag | Descrição | Padrão |
| :--- | :--- | :--- |
| `-ask-user` | Força a pergunta do nome de usuário, mesmo que já esteja salvo no perfil. | `false` |
| `-mfa` | Força a pergunta do código MFA, sem perguntar "Possui MFA?". | `false` |
| `-v` | Ativa o modo verbose, mostrando mais detalhes da conexão. | `false` |
| `-timeout <segundos>` | Define um tempo limite em segundos para a tentativa de conexão. | `0` (sem timeout) |

---
### `disconnect`

Encerra sessões VPN ativas. Pode ser usado de duas formas:

**1. Desconectar todas as sessões:**
```bash
gopn disconnect
```

**2. Desconectar a sessão de um perfil específico:**
```bash
gopn disconnect trabalho
```
---
### `list` e `help`

-   **`gopn list`**: Mostra todos os perfis salvos.
-   **`gopn help`**: Exibe a mensagem de ajuda com todos os comandos e exemplos.

---
### Exemplos de Uso

```bash
# Adicionar um perfil para a rede corporativa
gopn add corp /etc/openvpn/configs/corp.ovpn p.test

# Conectar-se normalmente (perguntará sobre MFA)
gopn connect corp

# Conectar-se forçando a pergunta do MFA e com um timeout de 30 segundos
gopn connect -mfa -timeout 30 corp

# Desconectar apenas a sessão corporativa
gopn disconnect corp

# Desconectar todas as conexões ativas
gopn disconnect
```

## Configuração

O `gopn` armazena seus perfis em um arquivo JSON localizado em `~/.config/gopn/profiles.json`.

## Licença

Distribuído sob a licença [MIT](LICENSE).