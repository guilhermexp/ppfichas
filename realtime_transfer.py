#!/usr/bin/env python3
"""
PPPoker Realtime Transfer System
Automatiza captura de rdkey e transferência de fichas

Usage:
    python3 realtime_transfer.py --target 8980655 --amount 100
    python3 realtime_transfer.py --batch transfers.txt
"""

import subprocess
import re
import time
import argparse
import sys
import os

# Importa cliente TCP
from pppoker_direct_api import PPPokerClient

# Configuração da conta
UID = 13204081
CLUBE_ID = 3330646
LIGA_ID = 1765
SUDO_PASS = ''  # <- CONFIGURE SUA SENHA SUDO AQUI
PCAP_FILE = '/tmp/pppoker_transfer.pcap'

# Hashes para ignorar (ícones, etc)
IGNORE_HASHES = {
    '4181b6e840d2766873be4c015db0d67e',
    '00000000000000000000000000000000',
}


def run_sudo(cmd):
    """Executa comando com sudo"""
    proc = subprocess.Popen(
        ['sudo', '-S'] + cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    proc.stdin.write(f'{SUDO_PASS}\n'.encode())
    proc.stdin.flush()
    return proc


def extract_rdkey_from_pcap(pcap_file):
    """Extrai rdkey do pcap - método confiável"""
    try:
        with open(pcap_file, 'rb') as f:
            data = f.read()

        text = data.decode('latin-1', errors='ignore')

        # Procura UserLoginREQ e pega o hash logo depois
        if 'UserLoginREQ' in text:
            pos = text.find('UserLoginREQ')
            chunk = text[pos:pos+200]
            matches = re.findall(r'[a-f0-9]{32}', chunk)
            for m in matches:
                if m not in IGNORE_HASHES:
                    return m

        # Fallback: qualquer hash 32-char não ignorado
        matches = re.findall(r'[a-f0-9]{32}', text)
        for m in matches:
            if m not in IGNORE_HASHES:
                return m

    except Exception as e:
        print(f'[-] Erro ao extrair rdkey: {e}')

    return None


def click_conectar_button():
    """Clica no botão Conectar do PPPoker"""
    # Pega posição da janela via AppleScript
    get_coords = '''
    tell application "PPPoker" to activate
    delay 0.3
    tell application "System Events"
        tell process "PPPoker"
            set winPos to position of window 1
            set winSize to size of window 1
            set btnX to (item 1 of winPos) + ((item 1 of winSize) / 2)
            set btnY to (item 2 of winPos) + ((item 2 of winSize) * 0.72)
            return ((round btnX) as string) & "," & ((round btnY) as string)
        end tell
    end tell
    '''

    try:
        result = subprocess.run(['osascript', '-e', get_coords],
                                capture_output=True, text=True, timeout=10)
        coords = result.stdout.strip()

        if coords and ',' in coords:
            # Clica duas vezes pra garantir
            subprocess.run(['/opt/homebrew/bin/cliclick', 'c:' + coords])
            time.sleep(0.2)
            subprocess.run(['/opt/homebrew/bin/cliclick', 'c:' + coords])
            return True
    except Exception as e:
        print(f'[-] Erro ao clicar: {e}')

    return False


def capture_with_app_restart():
    """
    Captura rdkey reiniciando o PPPoker
    1. Inicia tcpdump
    2. Fecha PPPoker
    3. Abre PPPoker
    4. Clica em Conectar
    5. Espera login
    6. Para tcpdump
    7. Extrai rdkey
    """
    print('[1/6] Iniciando captura de tráfego...')

    # Mata tcpdump anterior se existir
    subprocess.run(['sudo', '-S', 'pkill', '-f', 'tcpdump.*port 4000'],
                   input=f'{SUDO_PASS}\n'.encode(), capture_output=True)
    time.sleep(0.5)

    # Inicia tcpdump em background
    tcpdump_proc = run_sudo(['tcpdump', '-i', 'any', '-c', '200', '-w', PCAP_FILE, 'port', '4000'])
    time.sleep(1)

    print('[2/6] Fechando PPPoker...')
    subprocess.run(['pkill', '-x', 'PPPoker'], capture_output=True)
    time.sleep(2)

    print('[3/6] Abrindo PPPoker...')
    subprocess.run(['open', '-a', 'PPPoker'], capture_output=True)
    time.sleep(3)  # Espera janela carregar

    print('[4/6] Clicando em Conectar...')
    click_conectar_button()

    print('[5/6] Aguardando login (8s)...')
    time.sleep(8)

    print('[6/6] Parando captura...')
    subprocess.run(['sudo', '-S', 'pkill', '-f', 'tcpdump'],
                   input=f'{SUDO_PASS}\n'.encode(), capture_output=True)
    time.sleep(1)

    # Extrai rdkey
    rdkey = extract_rdkey_from_pcap(PCAP_FILE)

    if rdkey:
        print(f'[+] RDKEY capturado: {rdkey}')
    else:
        print('[-] Falha ao capturar rdkey')

    return rdkey


def transfer_chips(rdkey: str, target: int, amount: int) -> bool:
    """Executa transferência de fichas"""
    print(f'\n[*] Conectando ao servidor...')

    client = PPPokerClient(UID, rdkey)

    if not client.connect():
        print('[-] Falha na conexão')
        return False

    if not client.login():
        print('[-] Falha no login (rdkey inválido?)')
        client.close()
        return False

    # Entra no clube (opcional)
    client.enter_club(CLUBE_ID)

    # Transfere
    result = client.transfer_chips(
        target_player_id=target,
        amount=amount,
        clube_id=CLUBE_ID,
        liga_id=LIGA_ID
    )

    client.close()

    if result['success']:
        print(f'[+] SUCESSO! {amount} fichas -> {target}')
        return True
    else:
        print(f'[-] FALHOU: {result.get("error", "Erro desconhecido")}')
        return False


def single_transfer(target: int, amount: int):
    """Transferência única"""
    print('=' * 50)
    print('PPPoker Auto Transfer')
    print('=' * 50)

    rdkey = capture_with_app_restart()

    if not rdkey:
        print('\n[ERRO] Não conseguiu capturar rdkey')
        return False

    return transfer_chips(rdkey, target, amount)


def batch_transfer(filename: str):
    """Transferência em lote"""
    print('=' * 50)
    print('PPPoker Batch Transfer')
    print('=' * 50)

    # Lê transferências do arquivo
    transfers = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split(',')
                if len(parts) >= 2:
                    transfers.append({
                        'target': int(parts[0]),
                        'amount': int(parts[1])
                    })

    if not transfers:
        print('[-] Nenhuma transferência no arquivo')
        return

    print(f'\nCarregadas {len(transfers)} transferências')

    # Captura rdkey uma vez
    rdkey = capture_with_app_restart()

    if not rdkey:
        print('[ERRO] Não conseguiu capturar rdkey')
        return

    success = 0
    failed = 0

    for i, t in enumerate(transfers, 1):
        print(f'\n[{i}/{len(transfers)}] {t["target"]} <- {t["amount"]} fichas')

        if transfer_chips(rdkey, t['target'], t['amount']):
            success += 1
        else:
            failed += 1
            # Tenta novo rdkey se falhou
            print('[*] Capturando novo rdkey...')
            new_rdkey = capture_with_app_restart()
            if new_rdkey:
                rdkey = new_rdkey

        time.sleep(1)

    print(f'\n{"=" * 50}')
    print(f'Resultado: {success} sucesso, {failed} falhas')


def main():
    parser = argparse.ArgumentParser(
        description='PPPoker Auto Transfer - Envia fichas automaticamente',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Exemplos:
  python3 realtime_transfer.py --target 8980655 --amount 100
  python3 realtime_transfer.py --batch transfers.txt

O script automaticamente:
  1. Fecha o PPPoker
  2. Captura o tráfego
  3. Abre o PPPoker
  4. Extrai o rdkey do login
  5. Executa a transferência
        '''
    )
    parser.add_argument('--target', type=int, help='ID do jogador destino')
    parser.add_argument('--amount', type=int, help='Quantidade de fichas')
    parser.add_argument('--batch', help='Arquivo com transferências (formato: target,amount)')

    args = parser.parse_args()

    if args.batch:
        batch_transfer(args.batch)
    elif args.target and args.amount:
        success = single_transfer(args.target, args.amount)
        sys.exit(0 if success else 1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
