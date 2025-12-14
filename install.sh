#!/bin/bash
#
# PPPoker Fichas - Instalador
# Uso: ./install.sh
#

set -e

INSTALL_DIR="$HOME/Ppfichas"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo ""
echo "========================================"
echo "   PPPOKER FICHAS - INSTALADOR"
echo "========================================"
echo ""

# 1. Copia arquivos para ~/Ppfichas (se não estiver lá)
if [ "$SCRIPT_DIR" != "$INSTALL_DIR" ]; then
    echo "[1/5] Copiando arquivos para $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"
    cp "$SCRIPT_DIR/fichas" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/realtime_transfer.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/pppoker_direct_api.py" "$INSTALL_DIR/"
else
    echo "[1/5] Arquivos já em $INSTALL_DIR"
fi

# 2. Torna executável
echo "[2/5] Configurando permissões..."
chmod +x "$INSTALL_DIR/fichas"

# 3. Instala requests (Python)
echo "[3/5] Instalando dependências Python..."
pip3 install requests --quiet 2>/dev/null || pip3 install requests

# 4. Instala cliclick (se não tiver)
echo "[4/5] Verificando cliclick..."
if ! command -v cliclick &> /dev/null; then
    echo "    Instalando cliclick via Homebrew..."
    if ! command -v brew &> /dev/null; then
        echo "    [!] Homebrew não encontrado. Instalando..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install cliclick
else
    echo "    cliclick já instalado"
fi

# 5. Configura alias
echo "[5/5] Configurando comando global..."
SHELL_RC="$HOME/.zshrc"
if [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
fi

ALIAS_LINE="alias ppfichas=\"$INSTALL_DIR/fichas\""

if ! grep -q "ppfichas" "$SHELL_RC" 2>/dev/null; then
    echo "" >> "$SHELL_RC"
    echo "# PPPoker Fichas" >> "$SHELL_RC"
    echo "$ALIAS_LINE" >> "$SHELL_RC"
    echo "    Alias adicionado ao $SHELL_RC"
else
    echo "    Alias já existe"
fi

echo ""
echo "========================================"
echo "   INSTALACAO CONCLUIDA!"
echo "========================================"
echo ""
echo "Execute agora:"
echo "    source $SHELL_RC"
echo ""
echo "Depois, de qualquer terminal:"
echo "    pppokerfichas"
echo ""
echo "IMPORTANTE: Verifique as permissoes de Acessibilidade:"
echo "    System Settings > Privacy & Security > Accessibility"
echo "    Adicione o Terminal na lista"
echo ""
