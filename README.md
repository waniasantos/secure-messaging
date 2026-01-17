# Sistema de Mensageria Segura

**Trabalho de Segurança da Informação**  
**UFC Campus Quixadá - Prof. Michel Sales Bonfim**

Sistema de mensageria multicliente com protocolo de segurança baseado em TLS 1.3.


---


## Sobre o Projeto

Sistema de mensagens seguras onde múltiplos clientes se conectam a um servidor central e trocam mensagens criptografadas.

**Garantias de Segurança:**
- **Confidencialidade** - AES-128-GCM
- **Integridade** - Tag de autenticação GCM
- **Autenticidade** - Certificado RSA + Assinatura Digital
- **Forward Secrecy** - ECDHE (chaves efêmeras)
- **Anti-Replay** - Números de sequência monotônicos

**Protocolo Implementado:**
1. **Handshake:** ECDHE + RSA + HKDF (derivação de chaves TLS 1.3)
2. **Comunicação:** AES-128-GCM com AAD (Associated Authenticated Data)


---


## Pré-requisitos

### Python 3.8+

Verificar versão:
```bash
python3 --version
```

### Biblioteca cryptography

Ubuntu/Debian:
```bash
sudo apt install python3-cryptography
```
---

## Estrutura do Projeto

```
secure-messaging/
├── crypto_utils.py      # Funções criptográficas (ECDHE, RSA, HKDF, AES-GCM)
├── generate_certs.py    # Gerador de certificado RSA autoassinado
├── server.py            # Servidor de mensageria
├── client.py            # Cliente interativo
└── README.md            
```

---


## Como Rodar a Aplicação

### Passo 1: Gerar Certificado do Servidor

**Obrigatório antes de iniciar o servidor pela primeira vez.**

```bash
python3 generate_certs.py
```
**Arquivos gerados:**
- `server.key` - Chave privada RSA
- `server.crt` - Certificado público X.509


### Passo 2: Iniciar o Servidor

Execute:

```bash
python3 server.py
```

**Deixe este terminal aberto.** O servidor ficará rodando e mostrará logs das conexões e mensagens.


### Passo 3: Conectar Clientes

**Cada cliente precisa de um terminal separado.**

```bash
python3 client.py <nome_client>
```

#### Terminal 1 - Cliente Fernanda

```bash
python3 client.py fernanda
```

#### Terminal 2 - Cliente Ana

```bash
python3 client.py ana
```


### Passo 4: Enviar Mensagens

No terminal de cada cliente, digite mensagens no formato:

```
destinatario:mensagem
```

---


## Equipe

**Integrantes:**
- Luis Felipe Morais de Lima - 538605 
- Paulo Vitor Pinheiro da Silva - 542156 
- Wania Kelly dos Santos Oliveira - 540491 
