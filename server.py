import os
import socket
import hashlib
import pickle
import threading
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from enum import Enum

class Opcode(Enum):
    KEY_VERIFICATION = 10
    SESSION_TOKEN = 20
    CLIENT_ENC_DATA = 30
    ENC_AGGR_RESULT = 40
    DISCONNECT = 50

def diffie_hellman_key_exchange(prime, base, private_key):
    public_key = pow(base, private_key, prime)
    # val = Opcode.SESSION_TOKEN.value
    return public_key

def generate_des_key(shared_secret):
    key = str(shared_secret).encode()[:7]
    return key.ljust(8, b'\x00')  

class Server:
    def __init__(self, host, port, prime, base):
        self.prime = prime
        self.base = base
        self.private_key = os.urandom(16)
        self.public_key = diffie_hellman_key_exchange(prime, base, int.from_bytes(self.private_key, "big"))
        self.host = host
        self.port = port
        self.client_info = {}
        self.client_lock = threading.Lock()
        self.client_keys = {}  
        self.client_tokens = {}

    def decrypt_message(self, client_id, encrypted_message):
        token_len = len(self.client_tokens[client_id])
        # print(f"Token length: {token_len}")
        # print(self.client_tokens[client_id])
        # actual_message = encrypted_message[:-token_len]
        actual_message = encrypted_message
        
        key1, key2 = self.client_keys[client_id]
        cipher1 = DES.new(key2, DES.MODE_ECB)  
        cipher2 = DES.new(key1, DES.MODE_ECB)  
        first_decrypt = cipher1.decrypt(actual_message)
        second_decrypt = cipher2.decrypt(first_decrypt)
        
        try:
            original = unpad(second_decrypt, 8)
            return original
        except ValueError as e:
            raise e

    def encrypt_message(self, client_id, message):
        key1, key2 = self.client_keys[client_id]
        cipher1 = DES.new(key1, DES.MODE_ECB)
        cipher2 = DES.new(key2, DES.MODE_ECB)
        encrypted = cipher1.encrypt(pad(message, 8))
        double_encrypted = cipher2.encrypt(encrypted)
        return double_encrypted
    
    def send_message(self, client_socket, opcode, message):
        message_data = {'opcode': opcode, 'message': message}
        client_socket.send(pickle.dumps(message_data))

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            print(f"Server listening on {self.host} {self.port}\n")
            
            while True:
                client_socket, addr = server_socket.accept()
                print(f"New client {addr} connected")
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,),
                    daemon=True
                )
                client_thread.start()

    def process_client_data(self, encrypted_data, hmac, client_id):
        with self.client_lock:
            token_len = 8 
            _, key2 = self.client_keys[client_id]
        
        actual_encrypted_data = encrypted_data[:-token_len]
        print(f"Received encrypted data: {actual_encrypted_data}")
        received_token = encrypted_data[-token_len:]
        print(f"Received token: {received_token}")

        if received_token != self.client_tokens[client_id]:
            # self.send_message(self.client_sockets[client_id], 40, "wrongtoken")
            # # raise ValueError("Invalid session token")
            # print("Invalid session token")
            # return None
            print("Invalid session token")
            error_message = "Invalid session token"
            response = {'opcode': 40, 'message': "wrongtoken"}
            return response
        

        computed_hmac = hashlib.sha256(actual_encrypted_data + key2).hexdigest()
        print(f"Computed HMAC: {computed_hmac}")

        if computed_hmac != hmac:
            print("HMAC verification failed")
            error_message = "HMAC verification failed"
            response = {'opcode': 40, 'message': "wronghmac"}
            return response
        
        print("\nSession token verified successfully")
        print("HMAC verified successfully\n")
        print(actual_encrypted_data)
        decrypted_data = self.decrypt_message(client_id, actual_encrypted_data)
        print(f"Decrypted data: {decrypted_data}")
        return decrypted_data
    
    def is_valid_number(self, value):
        try:
            float(value)  
            return True
        except ValueError:
            return False


    def handle_client(self, client_socket):
        try:
            client_id = client_socket.getpeername()
            client_data = pickle.loads(client_socket.recv(1024))

            if client_data['opcode'] != 10:
                raise ValueError("Expected opcode 10 for key exchange")
            client_public_key = int(client_data['message'])
            print(f"Received client public key : {client_public_key}")

            self.send_message(client_socket, 10, str(self.public_key))

            shared_secret = diffie_hellman_key_exchange(self.prime, client_public_key, int.from_bytes(self.private_key, "big"))
            
            with self.client_lock:
                key1 = generate_des_key(shared_secret)
                key2 = generate_des_key(shared_secret + 1)
                self.client_keys[client_id] = (key1, key2)
            
            print(f"DES key 1: {key1}")
            print(f"DES key 2: {key2}")
            print(f"\nKey exchange complete for client {client_id}\n")

            session_token = os.urandom(8)
            print(f"Session token for client {client_id} : {session_token}")
            cipher = DES.new(key1, DES.MODE_ECB)
            encrypted_token = cipher.encrypt(pad(session_token, 8))
            
            with self.client_lock:
                self.client_tokens[client_id] = session_token
                # print("------")
                # print(self.client_tokens)
                # print("------")
            
            self.send_message(client_socket, 20, encrypted_token)

            with self.client_lock:
                self.client_info[client_id] = []

            while True:
                try:
                    print("\n-------------------------------------------\n")
                    temp = pickle.loads(client_socket.recv(1024))
                    if not temp:
                        print("Client disconnected abruptly.")   
                        break

                    if temp['opcode'] == 30:
                        data = temp['message']
                        hmac = data['hmac']
                        encrypted_message = data['message']
                        
                        print(f"Received HMAC: {hmac}")
                        
                        decrypted_data = self.process_client_data(encrypted_message, hmac, client_id)
                        if isinstance(decrypted_data, dict) and decrypted_data['opcode'] == 40:
                            self.send_message(client_socket, 40, decrypted_data['message'])
                            return  
                        
                        new_val = decrypted_data.decode()
                        
                        with self.client_lock:
                            if not self.is_valid_number(new_val):
                                print("Invalid data received")
                                self.send_message(client_socket, 40, "wronginfo")
                                continue
                                
                            self.client_info[client_id].append(new_val)
                            sum = 0
                            try:
                                for i in self.client_info[client_id]:
                                    sum += float(i)
                            except ValueError as e:
                                print(f"Error: {e}")
                                print("Invalid data received")
                                self.send_message(client_socket, 40, "wronginfo")
                                continue
                            
                        aggregated_result = "Aggregated result: " + str(sum)
                        print(f"Sending result to client {client_id}: {aggregated_result}")
                        
                        encrypted_result = self.encrypt_message(client_id, aggregated_result.encode())
                        response = {
                            'opcode': 40, 
                            'message': encrypted_result, 
                            'hmac': hashlib.sha256(aggregated_result.encode() + self.client_keys[client_id][1]).hexdigest()
                        }
                        self.send_message(client_socket, 40, response)

                    elif temp['opcode'] == 50:
                        print(f"Client {client_id} disconnected.")
                        return

                except (OSError, ConnectionResetError, EOFError):
                    print("Client disconnected abruptly.")
                    break 

                except Exception as e:
                    print(f"Error handling client {client_id}: {e}")
                    break
        except (OSError, ConnectionResetError, EOFError):
            print("Client disconnected abruptly.")
            
        except Exception as e:
            print(f"Error with client {client_id}: {e}")
        finally:
            with self.client_lock:
                if client_id in self.client_keys:
                    del self.client_keys[client_id]
                if client_id in self.client_tokens:
                    del self.client_tokens[client_id]
                if client_id in self.client_info:
                    del self.client_info[client_id]
            client_socket.close()

if __name__ == "__main__":
    prime = 23  
    base = 5
    num = int(input("Enter 65430 + n: "))    
    server = Server("localhost", 65430+num, prime, base)
    server.start()