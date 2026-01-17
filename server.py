import asyncio
import os
import struct
from crypto_utils import Crypto
from cryptography.hazmat.primitives import serialization
from cryptography import x509


class SecureMessagingServer:    
    def __init__(self):
        self.sessions = {}  # {client_id: {writer, key_c2s, key_s2c, seq_recv, seq_send}}
        self.load_certificate()
    
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
            print("Execute: python generate_certs.py")
            exit(1)
    
    async def perform_handshake(self, reader, writer):
        try:
            data = await reader.read(2048)
            
            id_length = struct.unpack('!H', data[:2])[0]
            client_id = data[2:2+id_length].decode('utf-8')
            pk_client_bytes = data[2+id_length:]
            
            print(f"[HANDSHAKE] Iniciado: {client_id}")
            
            sk_server, pk_server = Crypto.generate_ecdhe_keypair()
            pk_server_bytes = Crypto.serialize_public_key(pk_server)
            
            salt = os.urandom(32)
            
            transcript = pk_server_bytes + pk_client_bytes + client_id.encode() + salt
            signature = Crypto.sign_rsa(self.rsa_private_key, transcript)
            
            response = (
                struct.pack('!H', len(pk_server_bytes)) + pk_server_bytes +
                struct.pack('!H', len(self.certificate_bytes)) + self.certificate_bytes +
                struct.pack('!H', len(signature)) + signature +
                salt
            )
            
            writer.write(response)
            await writer.drain()
            
            pk_client = Crypto.deserialize_public_key(pk_client_bytes)
            shared_secret = Crypto.compute_shared_secret(sk_server, pk_client)
            
            key_c2s, key_s2c = Crypto.derive_tls13_keys(shared_secret, salt)
            
            self.sessions[client_id] = {
                'writer': writer,
                'key_c2s': key_c2s,    # cliente → servidor
                'key_s2c': key_s2c,    # servidor → cliente
                'seq_recv': 0,         # contador anti-replay (recebidas)
                'seq_send': 0          # contador anti-replay (enviadas)
            }
            
            print(f"[OK] Sessão estabelecida: {client_id}")
            print(f"Chaves derivadas com HKDF\n")
            
            return client_id
            
        except Exception as e:
            print(f"[ERRO] Erro no handshake: {e}")
            return None
    
    async def process_messages(self, reader, client_id):
        session = self.sessions[client_id]
        
        try:
            while True:
                size_bytes = await reader.readexactly(4)
                frame_size = struct.unpack('!I', size_bytes)[0]
                
                frame = await reader.readexactly(frame_size)
                
                nonce = frame[:12]
                sender = frame[12:28].decode('utf-8').rstrip('\x00')
                recipient = frame[28:44].decode('utf-8').rstrip('\x00')
                seq_no = struct.unpack('!Q', frame[44:52])[0]
                ciphertext = frame[52:]
                
                if seq_no <= session['seq_recv']:
                    print(f"[AVISO] Replay detectado de {sender} (seq {seq_no})")
                    continue
                
                session['seq_recv'] = seq_no
                
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
                
                if recipient in self.sessions:
                    await self.forward_message(recipient, sender, plaintext)
                else:
                    print(f"[AVISO] Destinatário {recipient} não está online")
                    
        except asyncio.IncompleteReadError:
            print(f"[LOGOUT] {client_id} desconectou")
        except Exception as e:
            print(f"[ERRO] Erro processando mensagens de {client_id}: {e}")
    
    async def forward_message(self, recipient_id, sender_id, message):
        dest_session = self.sessions[recipient_id]
        dest_session['seq_send'] += 1
        
        nonce = os.urandom(12)
        
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
        
        dest_session['writer'].write(struct.pack('!I', len(frame)) + frame)
        await dest_session['writer'].drain()
    
    async def handle_client(self, reader, writer):
        client_id = None
        
        try:
            client_id = await self.perform_handshake(reader, writer)
            
            if client_id:
                await self.process_messages(reader, client_id)
                
        except Exception as e:
            print(f"[ERRO] Erro: {e}")
            
        finally:
            if client_id and client_id in self.sessions:
                del self.sessions[client_id]
                print(f"[AVISO] {client_id} removido das sessões")
            
            writer.close()
            await writer.wait_closed()
    
    async def start(self, host='127.0.0.1', port=8888):
        server = await asyncio.start_server(
            self.handle_client,
            host,
            port
        )
        
        addr = server.sockets[0].getsockname()
        print("="*60)
        print("SERVIDOR DE MENSAGERIA SEGURA")
        print("="*60)
        print(f"Endereço: {addr[0]}:{addr[1]}")
        print(f"[SEGURANCA] Protocolo: ECDHE + RSA + HKDF + AES-128-GCM")
        print(f"[OK] Tudo certo. Aguardando conexões...\n")
        
        async with server:
            await server.serve_forever()


async def main():
    server = SecureMessagingServer()
    await server.start()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nServidor encerrado")