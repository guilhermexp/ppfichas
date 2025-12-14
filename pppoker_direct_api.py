#!/usr/bin/env python3
"""
PPPoker Direct API Client
Reverse engineered protocol for chip transfers

Usage:
    # Transfer chips
    python pppoker_direct_api.py transfer --uid 8980655 --rdkey YOUR_RDKEY --target 4210947 --amount 100

    # Get rdkey (capture from app or use HTTP login)
    The rdkey can be obtained by:
    1. Capturing traffic from PPPoker app (tcpdump)
    2. HTTP login endpoint (requires password)
"""

import socket
import struct
import time
import argparse
import sys
import hashlib

try:
    import requests
except ImportError:
    requests = None  # HTTP login won't work without requests


def encode_varint(value):
    """Encode integer as protobuf varint"""
    parts = []
    while value > 127:
        parts.append((value & 0x7F) | 0x80)
        value >>= 7
    parts.append(value)
    return bytes(parts)


def decode_varint(data, offset=0):
    """Decode protobuf varint from bytes"""
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        result |= (byte & 0x7F) << shift
        offset += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result, offset


def build_message(msg_name: str, payload: bytes) -> bytes:
    """Build a PPPoker TCP message"""
    msg_name_bytes = msg_name.encode('utf-8')
    padding = b'\x00\x00\x00\x00'
    content = struct.pack('>H', len(msg_name_bytes)) + msg_name_bytes + padding + payload
    return struct.pack('>I', len(content)) + content


def parse_response(data: bytes) -> dict:
    """Parse PPPoker response message"""
    if len(data) < 6:
        return {'error': 'Data too short', 'raw': data.hex()}

    total_len = struct.unpack('>I', data[0:4])[0]
    name_len = struct.unpack('>H', data[4:6])[0]
    msg_name = data[6:6+name_len].decode('utf-8')
    payload_start = 6 + name_len + 4
    payload = data[payload_start:4+total_len]

    return {
        'message': msg_name,
        'payload': payload,
        'payload_hex': payload.hex() if payload else ''
    }


def build_user_login_req(uid: int, rdkey: str) -> bytes:
    """Build pb.UserLoginREQ message"""
    payload = b''
    payload += bytes([0x08]) + encode_varint(uid)
    rdkey_bytes = rdkey.encode('utf-8')
    payload += bytes([0x12]) + encode_varint(len(rdkey_bytes)) + rdkey_bytes
    payload += b'\x1a\x064.2.56'
    payload += b'\x22\x0e192.168.31.107'
    payload += b'\x30\x00'
    payload += b'\x3a\x03ios'
    payload += b'\x40\x00'
    server = 'usbr-allentry.cozypoker.net:4000'
    payload += bytes([0x4a]) + encode_varint(len(server)) + server.encode()
    payload += b'\x52\x06Brazil'
    return build_message('pb.UserLoginREQ', payload)


def build_heartbeat_req() -> bytes:
    """Build pb.HeartBeatREQ message"""
    return build_message('pb.HeartBeatREQ', b'')


def http_login(username: str, password: str) -> dict:
    """
    Login via HTTP API to get fresh rdkey

    Args:
        username: Email or phone number
        password: Account password

    Returns:
        dict with uid, rdkey, gserver_ip, gserver_port on success
    """
    url = "https://www.cozypoker.net/poker/api/login.php"

    # Generate a fake IMEI for device identification
    imei = hashlib.md5(f"{username}{time.time()}".encode()).hexdigest()

    data = {
        'type': '1',  # 1 = login with password
        'region': '2',
        'code': '',
        'username': username,
        'password': password,
        't': '0',
        'uid': '0',
        'rdkey': '',
        'os': 'ios',
        'distributor': '0',
        'sub_distributor': '0',
        'country': 'BR',
        'appid': 'globle',
        'clientvar': '4.2.56',
        'imei': imei,
        'device_token': '',
        'platform_type': '4',
        'lang': 'pt',
        'languagecode': 'pt',
        'app_build_code': '221',
        'isioscheck': '1',
        'operating_company': 'unknow',
        'app_type': '1',
    }

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'PPPoker/114 CFNetwork/3860.300.31 Darwin/25.2.0',
        'Accept': '*/*',
        'Accept-Language': 'pt-BR,pt;q=0.9',
    }

    try:
        # Disable SSL verification (PPPoker uses custom certs)
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        resp = requests.post(url, data=data, headers=headers, timeout=30, verify=False)
        result = resp.json()

        if result.get('code') == 0:
            return {
                'success': True,
                'uid': result.get('uid'),
                'rdkey': result.get('rdkey'),
                'gserver_ip': result.get('gserver_ip'),
                'gserver_port': result.get('gserver_port', 4000),
            }
        else:
            return {
                'success': False,
                'error': result.get('msg', 'Unknown error'),
                'response': result
            }
    except Exception as e:
        return {'success': False, 'error': str(e)}


def build_club_info_req(clube_id: int) -> bytes:
    """
    Build pb.ClubInfoREQ message - enter/select club

    Args:
        clube_id: ID do clube para entrar (ex: 4210947)
    """
    payload = b''
    # Field 1: clube_id
    payload += bytes([0x08]) + encode_varint(clube_id)
    # Field 2: flag (1 = enter/select)
    payload += bytes([0x10, 0x01])
    return build_message('pb.ClubInfoREQ', payload)


def build_export_game_data_req(club_id: int, user_id: int, liga_id: int, email: str,
                                date_start: str, date_end: str,
                                transacoes: bool = True,
                                relatorio_diamante: bool = True) -> bytes:
    """
    Build pb.ExportGameDataREQ message for exporting club data to email

    Args:
        club_id: Club ID (Field 1)
        user_id: User ID (Field 4)
        liga_id: Liga/Federation ID (Field 8)
        email: Destination email
        date_start: Start date (YYYYMMDD)
        date_end: End date (YYYYMMDD)
        transacoes: Include transactions
        relatorio_diamante: Include diamond report
    """
    from datetime import datetime, timedelta

    # Parse dates
    start_dt = datetime.strptime(date_start, '%Y%m%d')
    end_dt = datetime.strptime(date_end, '%Y%m%d')

    # Generate day timestamps
    day_timestamps = []
    current = start_dt
    while current <= end_dt:
        ts = int(current.replace(hour=0, minute=0, second=0).timestamp())
        day_timestamps.append(ts)
        current += timedelta(days=1)

    # End timestamp (23:59:59)
    end_timestamp = int(end_dt.replace(hour=23, minute=59, second=59).timestamp())

    # Build payload
    payload = b''

    # Field 1: Club ID
    payload += b'\x08' + encode_varint(club_id)

    # Field 2: Day timestamps (repeated)
    for ts in day_timestamps:
        payload += b'\x10' + encode_varint(ts)

    # Field 3: End timestamp
    payload += b'\x18' + encode_varint(end_timestamp)

    # Field 4: User ID
    payload += b'\x20' + encode_varint(user_id)

    # Field 5: Email
    email_bytes = email.encode('utf-8')
    payload += b'\x2a' + encode_varint(len(email_bytes)) + email_bytes

    # Field 6: Unknown (-3 as unsigned 64-bit)
    payload += b'\x30' + encode_varint(0xFFFFFFFFFFFFFFFD)

    # Field 7: Language
    payload += b'\x3a\x02pt'

    # Field 8: Liga ID
    payload += b'\x40' + encode_varint(liga_id)

    # Field 9: Transações
    payload += b'\x48' + encode_varint(1 if transacoes else 0)

    # Field 10: Relatório diamante
    payload += b'\x50' + encode_varint(1 if relatorio_diamante else 0)

    # Field 11: Unknown (0)
    payload += b'\x58' + encode_varint(0)

    # Field 12: Date start
    payload += b'\x60' + encode_varint(int(date_start))

    # Field 13: Date end
    payload += b'\x68' + encode_varint(int(date_end))

    # Field 14: Unknown (0)
    payload += b'\x70' + encode_varint(0)

    # Field 15: Game type (609 = all)
    payload += b'\x78' + encode_varint(609)

    # Field 16: Flag (1)
    payload += b'\x80\x01' + encode_varint(1)

    # Field 17: Flag (0)
    payload += b'\x88\x01' + encode_varint(0)

    return build_message('pb.ExportGameDataREQ', payload)


def build_add_coin_req(clube_id: int, liga_id: int, target_player_id: int,
                       amount: int, sender_id: int) -> bytes:
    """
    Build pb.AddCoinREQ message for chip transfer

    Args:
        clube_id: ID do clube onde acontece a transferência (ex: 4210947)
        liga_id: ID da liga/federação (ex: 3357)
        target_player_id: ID do jogador que recebe as fichas (ex: 2647904)
        amount: Quantidade de fichas
        sender_id: ID do usuário autenticado que envia (ex: 8980655)
    """
    timestamp = int(time.time())
    txn_id = f"{clube_id}_{sender_id}_{timestamp}"

    payload = b''
    # Field 1: clube_id
    payload += bytes([0x08]) + encode_varint(clube_id)
    # Field 4: liga_id
    payload += bytes([0x20]) + encode_varint(liga_id)
    # Field 5: type (0 = standard)
    payload += bytes([0x28, 0x00])
    # Field 6: target_player_id (quem recebe)
    payload += bytes([0x30]) + encode_varint(target_player_id)
    # Field 7: amount (multiplicado por 100 - protocolo interno usa centavos)
    payload += bytes([0x38]) + encode_varint(amount * 100)
    # Field 8: transaction_id
    txn_bytes = txn_id.encode('utf-8')
    payload += bytes([0x42]) + encode_varint(len(txn_bytes)) + txn_bytes

    return build_message('pb.AddCoinREQ', payload)


class PPPokerClient:
    """PPPoker TCP client"""

    SERVERS = [
        '47.254.71.136',  # Primary
        '47.89.212.243',  # Alt 1
        '47.254.69.45',   # Alt 2
    ]

    def __init__(self, uid: int, rdkey: str):
        self.uid = uid
        self.rdkey = rdkey
        self.sock = None
        self.connected = False
        self.authenticated = False

    def connect(self, server: str = None) -> bool:
        """Connect to game server"""
        servers = [server] if server else self.SERVERS

        for srv in servers:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.settimeout(10)
                self.sock.connect((srv, 4000))
                self.connected = True
                print(f"[+] Connected to {srv}:4000")
                return True
            except Exception as e:
                print(f"[-] Failed to connect to {srv}: {e}")
                continue

        return False

    def send(self, data: bytes) -> bool:
        """Send data"""
        if not self.connected:
            return False
        try:
            self.sock.sendall(data)
            return True
        except Exception as e:
            print(f"[-] Send error: {e}")
            return False

    def recv(self, size: int = 4096) -> bytes:
        """Receive data"""
        if not self.connected:
            return b''
        try:
            return self.sock.recv(size)
        except Exception as e:
            print(f"[-] Recv error: {e}")
            return b''

    def login(self) -> bool:
        """Authenticate to server"""
        if not self.connected:
            return False

        login_req = build_user_login_req(self.uid, self.rdkey)
        self.send(login_req)
        time.sleep(0.5)

        resp = self.recv()
        if not resp:
            print("[-] No login response")
            return False

        parsed = parse_response(resp)
        if parsed['message'] != 'pb.UserLoginRSP':
            print(f"[-] Unexpected response: {parsed['message']}")
            return False

        if b'error' in parsed['payload']:
            error_msg = parsed['payload'].decode('utf-8', errors='ignore')
            print(f"[-] Login error: {error_msg}")
            return False

        print(f"[+] Login successful!")
        self.authenticated = True

        # Send heartbeat to confirm
        self.send(build_heartbeat_req())
        time.sleep(0.3)
        hb_resp = self.recv()
        if hb_resp:
            hb_parsed = parse_response(hb_resp)
            if hb_parsed['message'] == 'pb.HeartBeatRSP':
                print(f"[+] Session verified with heartbeat")

        return True

    def enter_club(self, clube_id: int, silent: bool = True) -> bool:
        """
        Enter/select a club before doing operations

        Args:
            clube_id: ID do clube para entrar (ex: 4210947)
            silent: Se True, não mostra mensagens de erro (padrão)
        """
        if not self.authenticated:
            return False

        club_req = build_club_info_req(clube_id)
        self.send(club_req)
        time.sleep(0.3)

        # Read responses - may get ClubInfoRSP or other messages
        for _ in range(3):
            resp = self.recv()
            if not resp:
                continue

            parsed = parse_response(resp)

            if parsed['message'] == 'pb.ClubInfoRSP':
                return True
            elif parsed['message'] in ['pb.HeartBeatRSP', 'pb.CallGameBRC', 'pb.PushBRC']:
                time.sleep(0.1)
                continue

        return True  # Continue anyway - transfer works without entering club

    def transfer_chips(self, target_player_id: int, amount: int,
                       clube_id: int, liga_id: int = 3357) -> dict:
        """
        Transfer chips to target player

        Args:
            target_player_id: ID do jogador que recebe (ex: 2647904)
            amount: Quantidade de fichas
            clube_id: ID do clube (ex: 4210947)
            liga_id: ID da liga (ex: 3357)
        """
        if not self.authenticated:
            return {'success': False, 'error': 'Not authenticated'}

        print(f"\n[*] Transferindo {amount} fichas para jogador {target_player_id}...")
        print(f"    Clube: {clube_id}, Liga: {liga_id}, Sender: {self.uid}")

        transfer_req = build_add_coin_req(
            clube_id=clube_id,
            liga_id=liga_id,
            target_player_id=target_player_id,
            amount=amount,
            sender_id=self.uid
        )

        print(f"    Request hex: {transfer_req.hex()}")
        self.send(transfer_req)
        time.sleep(0.5)

        # Read responses until we get AddCoinRSP (skip heartbeats)
        for _ in range(5):
            resp = self.recv()
            if not resp:
                return {'success': False, 'error': 'No response'}

            parsed = parse_response(resp)
            print(f"    Received: {parsed['message']}")

            if parsed['message'] == 'pb.AddCoinRSP':
                break
            elif parsed['message'] in ['pb.HeartBeatRSP', 'pb.CallGameBRC', 'pb.PushBRC']:
                # Skip heartbeats and broadcasts, wait for AddCoinRSP
                time.sleep(0.3)
                continue
            else:
                print(f"    Payload hex: {parsed.get('payload_hex', 'N/A')}")
                # Continue waiting, might get more messages
                time.sleep(0.3)
                continue
        else:
            return {'success': False, 'error': 'No AddCoinRSP received'}

        if parsed['message'] != 'pb.AddCoinRSP':
            return {'success': False, 'error': f"Unexpected: {parsed['message']}"}

        # Parse response payload
        payload = parsed['payload']
        if len(payload) > 0:
            result_code, _ = decode_varint(payload, 1)  # Skip field tag
            if result_code == 0:
                print(f"[+] Transfer successful!")
                return {'success': True, 'response': parsed}
            else:
                print(f"[-] Transfer failed with code: {result_code}")
                return {'success': False, 'error': f"Code {result_code}"}

        return {'success': False, 'error': 'Unknown', 'response': parsed}

    def export_data(self, club_id: int, liga_id: int, email: str, date_start: str, date_end: str,
                    transacoes: bool = True, relatorio_diamante: bool = True) -> dict:
        """
        Export club data to email

        Args:
            club_id: Club ID
            liga_id: Liga/Federation ID
            email: Destination email
            date_start: Start date (YYYYMMDD)
            date_end: End date (YYYYMMDD)
            transacoes: Include transactions
            relatorio_diamante: Include diamond report

        Returns:
            dict with 'success' and 'message' keys
        """
        if not self.authenticated:
            return {'success': False, 'error': 'Not authenticated'}

        print(f"\n[*] Exportando dados do clube {club_id}...")
        print(f"    Liga: {liga_id}, User: {self.uid}")
        print(f"    Período: {date_start} - {date_end}")
        print(f"    Email: {email}")

        export_req = build_export_game_data_req(
            club_id=club_id,
            user_id=self.uid,
            liga_id=liga_id,
            email=email,
            date_start=date_start,
            date_end=date_end,
            transacoes=transacoes,
            relatorio_diamante=relatorio_diamante
        )

        self.send(export_req)
        time.sleep(1)

        # Read response
        for _ in range(5):
            resp = self.recv()
            if not resp:
                time.sleep(0.3)
                continue

            parsed = parse_response(resp)
            print(f"    Received: {parsed['message']}")

            if parsed['message'] == 'pb.ExportGameDataRSP':
                # Check for success (Field 1 = 0)
                if b'\x08\x00' in resp or parsed['payload'] == b'\x08\x00':
                    print(f"[+] Export enviado com sucesso!")
                    return {'success': True, 'message': f'Planilha enviada para {email}'}
                else:
                    return {'success': False, 'error': 'Export failed', 'response': parsed}
            elif parsed['message'] in ['pb.HeartBeatRSP', 'pb.CallGameBRC']:
                time.sleep(0.3)
                continue

        return {'success': False, 'error': 'No ExportGameDataRSP received'}

    def close(self):
        """Close connection"""
        if self.sock:
            self.sock.close()
        self.connected = False
        self.authenticated = False


def main():
    parser = argparse.ArgumentParser(description='PPPoker Direct API Client')
    subparsers = parser.add_subparsers(dest='command')

    # Transfer command
    transfer_parser = subparsers.add_parser('transfer', help='Transfer chips')
    transfer_parser.add_argument('--uid', type=int, required=True, help='Seu user ID (sender)')
    transfer_parser.add_argument('--rdkey', required=True, help='Session key (32 char hex)')
    transfer_parser.add_argument('--target', type=int, required=True, help='ID do jogador que recebe')
    transfer_parser.add_argument('--amount', type=int, required=True, help='Quantidade de fichas')
    transfer_parser.add_argument('--clube', type=int, required=True, help='ID do clube (ex: 4210947)')
    transfer_parser.add_argument('--liga', type=int, default=3357, help='ID da liga (default: 3357)')
    transfer_parser.add_argument('--server', help='Server IP (optional)')

    # Test command
    test_parser = subparsers.add_parser('test', help='Test connection and auth')
    test_parser.add_argument('--uid', type=int, required=True, help='Your user ID')
    test_parser.add_argument('--rdkey', required=True, help='Your session key')

    # Login command (HTTP login to get rdkey)
    login_parser = subparsers.add_parser('login', help='HTTP login to get rdkey')
    login_parser.add_argument('--username', required=True, help='Email or phone')
    login_parser.add_argument('--password', required=True, help='Account password')

    # Full transfer with auto-login
    auto_parser = subparsers.add_parser('auto', help='Transfer with auto HTTP login')
    auto_parser.add_argument('--username', required=True, help='Email or phone')
    auto_parser.add_argument('--password', required=True, help='Account password')
    auto_parser.add_argument('--target', type=int, required=True, help='ID do jogador que recebe')
    auto_parser.add_argument('--amount', type=int, required=True, help='Quantidade de fichas')
    auto_parser.add_argument('--clube', type=int, required=True, help='ID do clube')
    auto_parser.add_argument('--liga', type=int, default=3357, help='ID da liga')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == 'test':
        client = PPPokerClient(args.uid, args.rdkey)
        if client.connect():
            if client.login():
                print("\n[SUCCESS] Authentication working!")
            else:
                print("\n[FAILED] Authentication failed")
            client.close()

    elif args.command == 'transfer':
        client = PPPokerClient(args.uid, args.rdkey)
        server = args.server if hasattr(args, 'server') else None

        if not client.connect(server):
            print("[-] Could not connect to any server")
            sys.exit(1)

        if not client.login():
            print("[-] Authentication failed")
            client.close()
            sys.exit(1)

        # Enter the club first
        client.enter_club(args.clube)

        result = client.transfer_chips(
            target_player_id=args.target,
            amount=args.amount,
            clube_id=args.clube,
            liga_id=args.liga
        )

        client.close()

        if result['success']:
            print(f"\n[SUCCESS] Transferido {args.amount} fichas para jogador {args.target}")
        else:
            print(f"\n[FAILED] {result.get('error', 'Unknown error')}")
            sys.exit(1)

    elif args.command == 'login':
        print(f"[*] Fazendo HTTP login com {args.username}...")
        result = http_login(args.username, args.password)

        if result['success']:
            print(f"\n[SUCCESS] Login HTTP OK!")
            print(f"  UID: {result['uid']}")
            print(f"  RDKEY: {result['rdkey']}")
            print(f"  Server: {result.get('gserver_ip')}:{result.get('gserver_port')}")
        else:
            print(f"\n[FAILED] {result.get('error', 'Unknown error')}")
            if 'response' in result:
                print(f"  Response: {result['response']}")
            sys.exit(1)

    elif args.command == 'auto':
        # Step 1: HTTP Login
        print(f"[1] Fazendo HTTP login com {args.username}...")
        login_result = http_login(args.username, args.password)

        if not login_result['success']:
            print(f"[-] HTTP Login failed: {login_result.get('error')}")
            sys.exit(1)

        uid = login_result['uid']
        rdkey = login_result['rdkey']
        server = login_result.get('gserver_ip')

        print(f"    UID: {uid}, RDKEY: {rdkey[:8]}...{rdkey[-8:]}")

        # Step 2: TCP Connect
        print(f"\n[2] Conectando ao servidor {server}:4000...")
        client = PPPokerClient(uid, rdkey)

        if not client.connect(server):
            print("[-] Could not connect to server")
            sys.exit(1)

        # Step 3: TCP Login
        print(f"\n[3] Autenticando via TCP...")
        if not client.login():
            print("[-] TCP Authentication failed")
            client.close()
            sys.exit(1)

        # Step 4: Enter Club
        print(f"\n[4] Entrando no clube {args.clube}...")
        client.enter_club(args.clube)

        # Step 5: Transfer
        print(f"\n[5] Transferindo {args.amount} fichas para {args.target}...")
        result = client.transfer_chips(
            target_player_id=args.target,
            amount=args.amount,
            clube_id=args.clube,
            liga_id=args.liga
        )

        client.close()

        if result['success']:
            print(f"\n{'='*50}")
            print(f"[SUCCESS] Transferido {args.amount} fichas para jogador {args.target}")
            print(f"{'='*50}")
        else:
            print(f"\n[FAILED] {result.get('error', 'Unknown error')}")
            sys.exit(1)


if __name__ == '__main__':
    main()
