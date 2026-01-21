import asyncio
import os
import struct
import signal
import re
import argparse
import websockets
from crypto_utils import Crypto
from cryptography.hazmat.primitives import serialization
from cryptography import x509

class SecureMessagingServer:
    ROTATION_INTERVAL = 1000

    def __init__(self):
        self.sessions = {}  
        self.load_certificate()
        self.stop_future = asyncio.Future()
    
    def load_certificate(self):
        try:
            with open("server.key", "rb") as f:
                self.rsa_private_key = serialization.load_pem_private_key(
                    f.read(), 
                    password=None
                )
            
            with open("server.crt", "rb") as f:
                self.certificate_bytes = f.read()
            
            print("[OK] Certificado RSA carregado")
            
        except FileNotFoundError:
            print("[ERRO] Certificado não encontrado!")
            print("Execute: python3 generate_certs.py")
            exit(1)

    def validate_client_id(self, client_id):
        if not re.match(r'^[a-zA-Z0-9_-]{1,16}$', client_id):
            raise ValueError(f"Client ID '{client_id}' possui formato inválido (apenas a-z, 0-9, _, -)")
        
        if client_id in self.sessions:
            raise ValueError(f"Client ID '{client_id}' já está em uso")

    async def perform_handshake(self, websocket):
        try:
            data = await websocket.recv()
            
            if len(data) < 2: return None

            id_length = struct.unpack('!H', data[:2])[0]
            if len(data) < 2 + id_length: return None

            client_id = data[2:2+id_length].decode('utf-8')
            pk_client_bytes = data[2+id_length:]
            
            try:
                self.validate_client_id(client_id)
            except ValueError as e:
                print(f"[REJEITADO] {e}")
                return None

            print(f"[HANDSHAKE] Iniciado: {client_id}")
            
            sk_server, pk_server = Crypto.generate_ecdhe_keypair()
            pk_server_bytes = Crypto.serialize_public_key(pk_server)
            
            salt = os.urandom(32)
            
            transcript = pk_server_bytes + client_id.encode() + pk_client_bytes + salt
            signature = Crypto.sign_rsa(self.rsa_private_key, transcript)
            
            response = (
                struct.pack('!H', len(pk_server_bytes)) + pk_server_bytes +
                struct.pack('!H', len(self.certificate_bytes)) + self.certificate_bytes +
                struct.pack('!H', len(signature)) + signature +
                salt
            )
            
            await websocket.send(response)
            
            pk_client = Crypto.deserialize_public_key(pk_client_bytes)
            shared_secret = Crypto.compute_shared_secret(sk_server, pk_client)
            
            key_c2s, key_s2c = Crypto.derive_tls13_keys(shared_secret, salt)
            
            self.sessions[client_id] = {
                'websocket': websocket,
                'key_c2s': key_c2s,
                'key_s2c': key_s2c,
                'seq_recv': 0,
                'seq_send': 0,
                'salt': salt
            }
            
            print(f"[OK] Sessão estabelecida: {client_id}")
            
            return client_id
            
        except websockets.exceptions.ConnectionClosed:
            return None
        except Exception as e:
            print(f"[ERRO] Erro no handshake: {e}")
            return None
    
    async def process_messages(self, websocket, client_id):
        session = self.sessions[client_id]
        
        try:
            async for frame in websocket:
                
                if len(frame) < 52: continue
                
                nonce = frame[:12]
                sender = frame[12:28].decode('utf-8').rstrip('\x00')
                recipient = frame[28:44].decode('utf-8').rstrip('\x00')
                seq_no = struct.unpack('!Q', frame[44:52])[0]
                ciphertext = frame[52:]
                
                if seq_no <= session['seq_recv']:
                    print(f"[AVISO] Replay detectado de {sender} (seq {seq_no})")
                    continue
                
                session['seq_recv'] = seq_no
                
                if seq_no > 0 and seq_no % self.ROTATION_INTERVAL == 0:
                    print(f"[ROTACAO] Atualizando chave de recebimento de {client_id}")
                    session['key_c2s'] = Crypto.rotate_key(session['key_c2s'])

                aad = (
                    sender.encode('utf-8').ljust(16, b'\x00') +
                    recipient.encode('utf-8').ljust(16, b'\x00') +
                    struct.pack('!Q', seq_no)
                )
                
                try:
                    plaintext = Crypto.decrypt_aes_gcm(
                        session['key_c2s'],
                        nonce,
                        ciphertext,
                        aad
                    ).decode('utf-8')
                    
                    print(f"[RECEBIDO] {sender} → {recipient}: {plaintext}")
                    
                except Exception as e:
                    print(f"[ERRO] Falha ao decifrar de {sender}: {e}")
                    continue
                
                if recipient == "__SERVER__":
                    if plaintext == "/users":
                        await self.send_user_list(sender)
                    continue

                if recipient in self.sessions:
                    await self.forward_message(recipient, sender, plaintext)
                else:
                    await self.send_system_message(sender, f"Erro: {recipient} não está conectado.")
                    
        except websockets.exceptions.ConnectionClosed:
            print(f"[LOGOUT] {client_id} desconectou")
        except Exception as e:
            print(f"[ERRO] Erro processando mensagens de {client_id}: {e}")
    
    async def forward_message(self, recipient_id, sender_id, message):
        dest_session = self.sessions[recipient_id]
        dest_session['seq_send'] += 1
        
        if dest_session['seq_send'] > 0 and dest_session['seq_send'] % self.ROTATION_INTERVAL == 0:
            print(f"[ROTACAO] Atualizando chave de envio para {recipient_id}")
            dest_session['key_s2c'] = Crypto.rotate_key(dest_session['key_s2c'])

        salt_prefix = dest_session['salt'][4:8]
        nonce = salt_prefix + struct.pack('!Q', dest_session['seq_send'])
        
        aad = (
            sender_id.encode('utf-8').ljust(16, b'\x00') +
            recipient_id.encode('utf-8').ljust(16, b'\x00') +
            struct.pack('!Q', dest_session['seq_send'])
        )
        
        ciphertext = Crypto.encrypt_aes_gcm(
            dest_session['key_s2c'],
            nonce,
            message,
            aad
        )
        
        frame = (
            nonce +
            sender_id.encode('utf-8').ljust(16, b'\x00') +
            recipient_id.encode('utf-8').ljust(16, b'\x00') +
            struct.pack('!Q', dest_session['seq_send']) +
            ciphertext
        )
        

        try:
            await dest_session['websocket'].send(frame)
        except Exception:
            pass


    async def send_system_message(self, recipient_id, message):
        await self.forward_message(recipient_id, "__SERVER__", message)

    async def send_user_list(self, requester_id):
        online_users = [uid for uid in self.sessions.keys() if uid != requester_id]
        if online_users:
            msg = f"Usuários online: {', '.join(online_users)}"
        else:
            msg = "Apenas você está online."
        
        await self.send_system_message(requester_id, msg)

    async def graceful_shutdown(self):
        print("\n[SHUTDOWN] Encerrando servidor...")
        self.stop_future.set_result(True)

        for client_id, session in list(self.sessions.items()):
            await session['websocket'].close()

    async def handle_client(self, websocket):
        client_id = None
        try:
            client_id = await self.perform_handshake(websocket)
            if client_id:
                await self.process_messages(websocket, client_id)
        except Exception as e:
            print(f"[ERRO] {e}")
        finally:
            if client_id and client_id in self.sessions:
                del self.sessions[client_id]

    async def start(self, host='127.0.0.1', port=8888):
        print("="*60)
        print("SERVIDOR DE MENSAGERIA SEGURA (WEBSOCKETS)")
        print("="*60)
        print(f"Endereço: ws://{host}:{port}")
        print(f"[MODO] Compatível com ngrok http")
        print(f"[OK] Aguardando conexões...\n")
        
        async with websockets.serve(self.handle_client, host, port):
            await self.stop_future  

async def main():
    parser = argparse.ArgumentParser(description="Servidor de Mensageria Segura (WebSockets)")
    parser.add_argument("--host", default="127.0.0.1", help="Interface (padrão 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8888, help="Porta (padrão 8888)")
    
    args = parser.parse_args()
    
    server = SecureMessagingServer()
    
    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(server.graceful_shutdown()))
        
    await server.start(args.host, args.port)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass