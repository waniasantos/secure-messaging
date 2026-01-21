import asyncio
import os
import struct
import sys
import re
import argparse
import websockets
from crypto_utils import Crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

class SecureMessagingClient:
    MAX_MESSAGE_SIZE = 4096
    ROTATION_INTERVAL = 1000

    def __init__(self, client_id):
        self.client_id = client_id
        self.websocket = None
        self.key_c2s = None
        self.key_s2c = None
        self.seq_send = 0
        self.seq_recv = 0
        self.salt = None
        self.pinned_cert_bytes = None
    
    def load_pinned_cert(self):
        try:
            with open("server.crt", "rb") as f:
                self.pinned_cert_bytes = f.read()
        except FileNotFoundError:
            print("[ERRO] 'server.crt' não encontrado no diretório atual.")
            return False
        return True

    async def connect(self, uri):
        if not self.load_pinned_cert():
            return False

        try:
            print(f"[CONEXAO] Conectando a {uri}...")
            # Conexão WebSocket
            self.websocket = await websockets.connect(uri)
            
            print(f"[HANDSHAKE] Enviando Hello...")
            sk_client, pk_client = Crypto.generate_ecdhe_keypair()
            pk_client_bytes = Crypto.serialize_public_key(pk_client)
            
            message = (
                struct.pack('!H', len(self.client_id)) +
                self.client_id.encode('utf-8') +
                pk_client_bytes
            )
            
            await self.websocket.send(message)
            
            # Aguardar resposta (Server Hello)
            data = await self.websocket.recv()
            
            offset = 0
            pk_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            pk_server_bytes = data[offset:offset+pk_len]
            offset += pk_len
            
            cert_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            cert_bytes = data[offset:offset+cert_len]
            offset += cert_len
            
            sig_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            signature = data[offset:offset+sig_len]
            offset += sig_len
            
            self.salt = data[offset:offset+32]
            
            if cert_bytes != self.pinned_cert_bytes:
                print("[FATAL] Certificado do servidor diferente do local (Pinning falhou)!")
                return False
            
            certificate = x509.load_pem_x509_certificate(cert_bytes)
            server_public_key = certificate.public_key()
            
            transcript = pk_server_bytes + self.client_id.encode() + pk_client_bytes + self.salt
            
            if not Crypto.verify_rsa(server_public_key, signature, transcript):
                print("[ERRO] Assinatura RSA inválida!")
                return False
            
            print(f"[OK] Servidor autenticado via RSA")
            
            pk_server = Crypto.deserialize_public_key(pk_server_bytes)
            shared_secret = Crypto.compute_shared_secret(sk_client, pk_server)
            
            self.key_c2s, self.key_s2c = Crypto.derive_tls13_keys(shared_secret, self.salt)
            
            print(f"[OK] Chaves derivadas com HKDF")
            print(f"[OK] Sessão segura estabelecida\n")
            
            return True
            
        except Exception as e:
            print(f"[ERRO] Falha na conexão: {e}")
            return False
    
    async def send_message(self, recipient, message):
        encoded_msg = message.encode('utf-8')
        if len(encoded_msg) > self.MAX_MESSAGE_SIZE:
             print(f"[ERRO] Mensagem muito grande")
             return

        self.seq_send += 1
        
        if self.seq_send > 0 and self.seq_send % self.ROTATION_INTERVAL == 0:
            print(f"[ROTACAO] Atualizando chave de envio...")
            self.key_c2s = Crypto.rotate_key(self.key_c2s)

        nonce = self.salt[:4] + struct.pack('!Q', self.seq_send)
        
        aad = (
            self.client_id.encode('utf-8').ljust(16, b'\x00') +
            recipient.encode('utf-8').ljust(16, b'\x00') +
            struct.pack('!Q', self.seq_send)
        )
        
        ciphertext = Crypto.encrypt_aes_gcm(
            self.key_c2s,
            nonce,
            encoded_msg,
            aad
        )
        
        frame = (
            nonce +
            self.client_id.encode('utf-8').ljust(16, b'\x00') +
            recipient.encode('utf-8').ljust(16, b'\x00') +
            struct.pack('!Q', self.seq_send) +
            ciphertext
        )
        

        try:
            await self.websocket.send(frame)
        except Exception as e:
            print(f"[ERRO] Falha ao enviar: {e}")
            return

        
        if recipient == "__SERVER__":
            print(f"(Comando enviado ao sistema)")
        else:
            print(f"[ENVIO] Enviado para {recipient}: {message}")
    
    async def receive_messages(self):
        try:
            async for frame in self.websocket:
                nonce = frame[:12]
                sender = frame[12:28].decode('utf-8').rstrip('\x00')
                recipient = frame[28:44].decode('utf-8').rstrip('\x00')
                seq_no = struct.unpack('!Q', frame[44:52])[0]
                ciphertext = frame[52:]
                
                if seq_no <= self.seq_recv:
                    continue
                
                self.seq_recv = seq_no
                
                if seq_no > 0 and seq_no % self.ROTATION_INTERVAL == 0:
                    print(f"[ROTACAO] Atualizando chave de recebimento...")
                    self.key_s2c = Crypto.rotate_key(self.key_s2c)

                aad = (
                    sender.encode('utf-8').ljust(16, b'\x00') +
                    recipient.encode('utf-8').ljust(16, b'\x00') +
                    struct.pack('!Q', seq_no)
                )
                
                try:
                    plaintext = Crypto.decrypt_aes_gcm(
                        self.key_s2c,
                        nonce,
                        ciphertext,
                        aad
                    ).decode('utf-8')
                    
                    if sender == "__SERVER__":
                        print(f"\n[SISTEMA] {plaintext}")
                    else:
                        print(f"\n[RECEBIMENTO] {sender}: {plaintext}")
                    
                    print(f"({self.client_id})> ", end='', flush=True)
                    
                except Exception as e:
                    print(f"\n[ERRO] Falha ao decifrar: {e}")

        except websockets.exceptions.ConnectionClosed:
           print("\n[CONEXAO] Servidor desconectou.")
    
    async def interactive_mode(self):
        receive_task = asyncio.create_task(self.receive_messages())
        
        print("="*60)
        print("MODO INTERATIVO (WebSocket)")
        print("="*60)
        print("Formato: destinatario:mensagem")
        print("Exemplo: alice:Oi, tudo bem?")
        print("Comandos: /users, sair")
        print("="*60 + "\n")
        
        try:
            while True:
                loop = asyncio.get_event_loop()
                user_input = await loop.run_in_executor(
                    None,
                    input,
                    f"({self.client_id})> "
                )
                
                user_input = user_input.strip()
                if not user_input: continue

                if user_input.lower() in ['sair', 'exit', 'quit']:
                    break
                
                if user_input.lower() == '/users':
                    await self.send_message("__SERVER__", "/users")
                    continue
                
                if ':' not in user_input:
                    print("[AVISO] Use: destinatario:mensagem")
                    continue
                
                recipient, message = user_input.split(':', 1)
                await self.send_message(recipient.strip(), message.strip())
                
        except KeyboardInterrupt:
            pass
            
        finally:
            receive_task.cancel()
            await self.websocket.close()


async def main():
    parser = argparse.ArgumentParser(description="Cliente de Mensageria Segura (WebSockets)")
    parser.add_argument("client_id", help="ID do cliente")
    parser.add_argument("--host", default="127.0.0.1", help="Host (padrão: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8888, help="Porta (padrão: 8888)")
    parser.add_argument("--wss", action="store_true", help="Usar WebSockets Seguro (wss://) - Necessário para ngrok https")
    
    args = parser.parse_args()
    
    if not re.match(r'^[a-zA-Z0-9_-]{1,16}$', args.client_id):
        print(f"[ERRO] ID inválido")
        return
    
    protocol = "wss" if args.wss else "ws"
    uri = f"{protocol}://{args.host}:{args.port}"
    
    # Se o host já tiver schema, usa ele
    if "://" in args.host:
        uri = args.host
    
    client = SecureMessagingClient(args.client_id)
    
    if await client.connect(uri):
        await client.interactive_mode()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass