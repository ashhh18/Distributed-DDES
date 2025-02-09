# Distributed-DDES

A client-server application implementing encryption, authentication, and session management. The application uses the Diffie-Hellman key exchange protocol and DES encryption to ensure secure communication between clients and the server.

## Features

- Diffie-Hellman key exchange for secure key establishment
- Double DES encryption for message confidentiality
- Session token authentication
- HMAC verification for message integrity
- Multi-threaded server supporting multiple concurrent clients
- Running sum calculation for each client session

### Execution flow

1. Client-Server connection establishment
2. Diffie-Hellman key exchange
3. Generation of two DES keys
4. Server issues encrypted session token
5. Secure message exchange:
   - Double encryption of messages
   - Session token verification
   - HMAC verification
   - Encrypted response with running sum

## Prerequisites
pip install pycryptodome


### Starting the Server

If multiple files for client are required : 
-> chmod +x create_files.sh
-> ./create_files.sh {n}

1. Run the server script:
```bash
python server.py
```
2. Enter the port offset when prompted:
```
Enter 65430 + n:
```
The server will start listening on port 65430 + n.

### Running the Client

1. Run the client script:
```bash
python client.py
```

2. Enter the same port offset as used for the server when prompted:
```
Enter 65430 + n:
```

3. Once connected, enter numbers to be added to your session's running sum:
- Type numbers to add them to the running sum
- Type 'exit' to terminate the connection


### Message Types (Opcodes)

- 10: Key Exchange
- 20: Session Token Distribution
- 30: Encrypted Client Data
- 40: Encrypted Server Response
- 50: Disconnect Signal

## Error Handling

The application handles various types of errors:
- Invalid data format
- Failed HMAC verification
- Invalid session tokens
- Connection issues
- Abrupt disconnections
