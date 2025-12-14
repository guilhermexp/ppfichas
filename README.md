# PPPoker Fichas

Envio automatizado de fichas para PPPoker.

## Quick Start

```bash
# 1. Instalar
./install.sh && source ~/.zshrc

# 2. Usar
ppfichas
```

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

## Antes de Usar

1. PPPoker instalado e logado
2. Permissao de Acessibilidade:
   - System Settings > Privacy & Security > Accessibility
   - Adicionar **Terminal** na lista

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
