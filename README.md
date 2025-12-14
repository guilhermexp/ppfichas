# PPPoker Fichas

Envio automatizado de fichas para PPPoker.

## Quick Start

```bash
# 1. Instalar
./install.sh && source ~/.zshrc

# 2. Usar
ppfichas
```

## Configuracao

**IMPORTANTE:** Edite a senha sudo no arquivo `realtime_transfer.py`:

```python
SUDO_PASS = '0000'  # <- Troque pela sua senha
```

## Dependencias

O instalador instala automaticamente, mas se precisar manual:

```bash
# Homebrew (se nao tiver)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# cliclick (automacao de cliques)
brew install cliclick

# requests (Python)
pip3 install requests
```

## Antes de Usar

1. PPPoker instalado e logado
2. Senha sudo configurada no `realtime_transfer.py`
3. Permissao de Acessibilidade:
   - System Settings > Privacy & Security > Accessibility
   - Adicionar **Terminal** na lista

## Exemplo

```
$ ppfichas

========================================
   PPPOKER - ENVIO DE FICHAS
========================================

ID do jogador: 8980655
Quantidade de fichas: 100

>>> Enviando 100 fichas para 8980655...

[+] RDKEY capturado: abc123...
[+] Connected to 47.254.71.136:4000
[+] Login successful!
[+] SUCESSO! 100 fichas -> 8980655
```

## Envio em Lote

```bash
# Cria arquivo com transferencias
echo "8980655,100" >> transfers.txt
echo "1234567,50" >> transfers.txt

# Executa todas
python3 ~/Ppfichas/realtime_transfer.py --batch transfers.txt
```

## Erros Comuns

| Erro | Solucao |
|------|---------|
| rdkey error8 | Execute novamente |
| Clique nao funciona | Adicionar Terminal em Acessibilidade |
| cliclick not found | `brew install cliclick` |
| sudo: incorrect password | Editar SUDO_PASS em realtime_transfer.py |
