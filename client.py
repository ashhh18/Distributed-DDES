import os
import socket
import hashlib
import pickle
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
    return public_key

def generate_des_key(shared_secret):
    key = str(shared_secret).encode()[:7]
    return key.ljust(8, b'\x00')  

class Client:
    def __init__(self, host, port, prime, base):
        self.prime = prime
        self.base = base
        self.private_key = os.urandom(16)
        self.public_key = diffie_hellman_key_exchange(prime, base, int.from_bytes(self.private_key, "big"))
        self.key1 = None
        self.key2 = None
        self.host = host
        self.port = port

    def decrypt_message(self, key1, key2, encrypted_message):
        cipher2 = DES.new(key2, DES.MODE_ECB)
        intermediate = cipher2.decrypt(encrypted_message)
        cipher1 = DES.new(key1, DES.MODE_ECB)
        decrypted = cipher1.decrypt(intermediate)
        original = unpad(decrypted, 8)
        return original

    def encrypt_message(self, key1, key2, message):
        cipher1 = DES.new(key1, DES.MODE_ECB)
        cipher2 = DES.new(key2, DES.MODE_ECB)
        padded_message = pad(message, 8)
        first_encrypt = cipher1.encrypt(padded_message)
        second_encrypt = cipher2.encrypt(first_encrypt)
        return second_encrypt

    def send_message(self, client_socket, opcode, message):
        message_data = {'opcode': opcode, 'message': message}
        to_display = ""
        if opcode == 30:
            to_display = message['message']
        elif opcode == 40:
            to_display = message['message']
        elif opcode == 50:
            to_display = ""
        print(f"Sending message : [OPCODE : {opcode}, MESSAGE : {message}]")
        client_socket.send(pickle.dumps(message_data))

    def communicate(self):

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.host, self.port))
            print(f"Connecting to server for key exchange on port {self.port}\n")
            self.send_message(client_socket, 10, str(self.public_key))

            server_response = pickle.loads(client_socket.recv(1024))

            if server_response['opcode'] != 10:
                raise ValueError("Invalid opcode received during key exchange")
            
            server_public_key = int(server_response['message'])
            print(f"Received server public key: {server_public_key}")
            shared_secret = diffie_hellman_key_exchange(self.prime, server_public_key, int.from_bytes(self.private_key, "big"))
            self.key1 = generate_des_key(shared_secret)
            self.key2 = generate_des_key(shared_secret + 1)
            print(f"DES key 1: {self.key1}")
            print(f"DES key 2: {self.key2}")
            print("\nKey exchange complete\n")
            
            token_response = pickle.loads(client_socket.recv(1024))
            if token_response['opcode'] != 20:
                raise ValueError("Invalid opcode in token exchange")
            encrypted_token = token_response['message']
            
            cipher = DES.new(self.key1, DES.MODE_ECB)
            print(f"Encrypted session token: {encrypted_token}")
            session_token = unpad(cipher.decrypt(encrypted_token), 8)
            print(f"Decrypted Session token: {session_token}")

            while True:
                print("\n-------------------------------------------\n")
                message = input("Enter number: ")
                if message.lower() == 'exit':
                    self.send_message(client_socket, 50, b'')
                    print("Exiting...")
                    break

                encrypted_data = self.encrypt_message(self.key1, self.key2, message.encode())
                message_with_token = encrypted_data + session_token  
                hmac = hashlib.sha256(encrypted_data + self.key2).hexdigest()
                
                data_to_send = {
                    'opcode': 30,
                    'message': message_with_token,
                    'hmac': hmac
                }
                self.send_message(client_socket, 30, data_to_send)

                response_data = pickle.loads(client_socket.recv(1024))

                if response_data['opcode'] == 40:
                    # print(response_data)
                    temp4 = response_data['message']
                    # print(type(temp4))
                    # print(temp4)

                    if temp4 == "wronginfo":
                        print("\nWARNING : Invalid data received")
                        continue
                    elif temp4 == "wronghmac":
                        print("\nWARNING : HMAC verification failed")
                        print("Terminating connection")
                        break
                    elif temp4 == "wrongtoken":
                        print("WARNING : Invalid session token")
                        print("\nTerminating connection")
                        break

                    encrypted_result = temp4['message']
                    result_hmac = temp4['hmac']
                    print(f"Encrypted result : {encrypted_result}")
                    # print(result_hmac)
                    decrypted_result = self.decrypt_message(self.key1, self.key2, encrypted_result)
                    print(f"{decrypted_result.decode()}")

if __name__ == "__main__":
    prime = 23 
    base = 5   
    num = int(input("Enter 65430 + n: ")) 
    
    client = Client("localhost", 65430+num, prime, base)
    client.communicate()
