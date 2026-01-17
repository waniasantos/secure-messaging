import asyncio
import os
import struct
import sys
from crypto_utils import Crypto
from cryptography import x509
from cryptography.hazmat.primitives import serialization


class SecureMessagingClient:    
    def __init__(self, client_id):
        self.client_id = client_id
        self.reader = None
        self.writer = None
        self.key_c2s = None  # cliente >> servidor
        self.key_s2c = None  # servidor >> cliente
        self.seq_send = 0
        self.seq_recv = 0
    
    async def connect(self, host='127.0.0.1', port=8888):
        try:
            self.reader, self.writer = await asyncio.open_connection(host, port)
            
            print(f"[CONEXAO] Conectando como '{self.client_id}'...")

            sk_client, pk_client = Crypto.generate_ecdhe_keypair()
            pk_client_bytes = Crypto.serialize_public_key(pk_client)
            
            message = (
                struct.pack('!H', len(self.client_id)) +
                self.client_id.encode('utf-8') +
                pk_client_bytes
            )
            
            self.writer.write(message)
            await self.writer.drain()
            
            data = await self.reader.read(4096)
            
            offset = 0

            # pk_servidor (65 bytes)
            pk_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            pk_server_bytes = data[offset:offset+pk_len]
            offset += pk_len
            
            # certificado X.509
            cert_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            cert_bytes = data[offset:offset+cert_len]
            offset += cert_len
            
            # assinatura RSA-PSS
            sig_len = struct.unpack('!H', data[offset:offset+2])[0]
            offset += 2
            signature = data[offset:offset+sig_len]
            offset += sig_len
            
            # salt para HKDF (32 bytes)
            salt = data[offset:offset+32]
            
            certificate = x509.load_pem_x509_certificate(cert_bytes)
            server_public_key = certificate.public_key()
            
            transcript = pk_server_bytes + pk_client_bytes + self.client_id.encode() + salt
            
            if not Crypto.verify_rsa(server_public_key, signature, transcript):
                print("[ERRO] Assinatura RSA inválida!")
                return False
            
            print(f"[OK] Servidor autenticado via RSA")
            
            pk_server = Crypto.deserialize_public_key(pk_server_bytes)
            shared_secret = Crypto.compute_shared_secret(sk_client, pk_server)
            
            self.key_c2s, self.key_s2c = Crypto.derive_tls13_keys(shared_secret, salt)
            
            print(f"[OK] Chaves derivadas com HKDF")
            print(f"[OK] Sessão segura estabelecida\n")
            
            return True
            
        except Exception as e:
            print(f"[ERRO] Falha na conexão: {e}")
            return False
    
    async def send_message(self, recipient, message):
        self.seq_send += 1
        
        nonce = os.urandom(12)
        
        aad = (
            self.client_id.encode('utf-8').ljust(16, b'\x00') +
            recipient.encode('utf-8').ljust(16, b'\x00') +
            struct.pack('!Q', self.seq_send)
        )
        
        ciphertext = Crypto.encrypt_aes_gcm(
            self.key_c2s,
            nonce,
            message,
            aad
        )
        
        frame = (
            nonce +
            self.client_id.encode('utf-8').ljust(16, b'\x00') +
            recipient.encode('utf-8').ljust(16, b'\x00') +
            struct.pack('!Q', self.seq_send) +
            ciphertext
        )
        
        self.writer.write(struct.pack('!I', len(frame)) + frame)
        await self.writer.drain()
        
        print(f"[ENVIO] Enviado para {recipient}: {message}")
    
    async def receive_messages(self):
        try:
            while True:
                size_bytes = await self.reader.readexactly(4)
                frame_size = struct.unpack('!I', size_bytes)[0]
                
                frame = await self.reader.readexactly(frame_size)
                
                nonce = frame[:12]
                sender = frame[12:28].decode('utf-8').rstrip('\x00')
                recipient = frame[28:44].decode('utf-8').rstrip('\x00')
                seq_no = struct.unpack('!Q', frame[44:52])[0]
                ciphertext = frame[52:]
                
                if seq_no <= self.seq_recv:
                    print(f"[AVISO] Mensagem antiga ignorada (seq {seq_no})")
                    continue
                
                self.seq_recv = seq_no
                
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
                    
                    print(f"\n[RECEBIMENTO] {sender}: {plaintext}")
                    print(f"({self.client_id})> ", end='', flush=True)
                    
                except Exception as e:
                    print(f"\n[ERRO] Falha ao decifrar: {e}")
                    
        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"\n[ERRO] Falha ao receber: {e}")
    
    async def interactive_mode(self):
        receive_task = asyncio.create_task(self.receive_messages())
        
        print("="*60)
        print("MODO INTERATIVO")
        print("="*60)
        print("Formato: destinatario:mensagem")
        print("Exemplo: alice:Oi, tudo bem?")
        print("Digite 'sair' para encerrar\n")
        
        try:
            while True:
                loop = asyncio.get_event_loop()
                user_input = await loop.run_in_executor(
                    None,
                    input,
                    f"({self.client_id})> "
                )
                
                if user_input.lower() in ['sair', 'exit', 'quit']:
                    print("Encerrando...")
                    break
                
                if ':' not in user_input:
                    print("[AVISO] Formato incorreto. Use: destinatario:mensagem")
                    continue
                
                recipient, message = user_input.split(':', 1)
                recipient = recipient.strip()
                message = message.strip()
                
                if not message:
                    print("[AVISO] Mensagem vazia")
                    continue
                
                await self.send_message(recipient, message)
                
        except KeyboardInterrupt:
            print("\n\nInterrompido pelo usuário")
            
        finally:
            receive_task.cancel()
            self.writer.close()
            await self.writer.wait_closed()


async def main():
    if len(sys.argv) < 2:
        print("="*60)
        print("[ERRO] ID do cliente não fornecido")
        print("="*60)
        print("Uso: python client.py <seu_id>")
        print("Exemplo: python client.py alice\n")
        return
    
    client_id = sys.argv[1]
    
    if len(client_id) > 16:
        print(f"[ERRO] ID muito longo (máximo 16 caracteres)")
        return
    
    client = SecureMessagingClient(client_id)
    
    if await client.connect():
        await client.interactive_mode()
    else:
        print("[ERRO] Falha na conexão com o servidor")


if __name__ == "__main__":
    asyncio.run(main())