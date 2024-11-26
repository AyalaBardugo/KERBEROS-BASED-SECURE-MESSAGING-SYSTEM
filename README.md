# 🔐 Kerberos-Based Secure Messaging System

[![Security](https://img.shields.io/badge/Security-Enhanced-green.svg)](https://web.mit.edu/kerberos/)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/License-Academic-yellow.svg)]()
[![Protocol](https://img.shields.io/badge/Protocol-Kerberos-red.svg)]()

## 📋 Table of Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Security Features](#security-features)
- [Implementation Details](#implementation-details)
- [Project Structure](#project-structure)
- [Installation & Usage](#installation--usage)
- [Technical Documentation](#technical-documentation)
- [Security Considerations](#security-considerations)

## 🌟 Overview

This project implements a secure messaging system based on the Kerberos authentication protocol. It features a complete client-server architecture with encryption, authentication, and secure message transmission capabilities.

### Key Features
- ✅ Kerberos-based authentication system
- 🔒 AES-CBC encryption for secure communication
- 🎯 Multi-threaded server architecture
- 📝 Persistent client registration
- 🔑 Secure key distribution
- 📋 Message encryption and delivery confirmation

## 🏗️ Architecture

The system consists of three main components:

### 1. Authentication Server (KDC)
- Manages client registrations
- Handles key distribution
- Maintains client session information
- Implements the Key Distribution Center functionality

### 2. Message Server
- Receives encrypted messages from clients
- Verifies message authenticity
- Manages client sessions
- Handles message delivery

### 3. Client Application
- Implements user registration and authentication
- Handles secure message composition
- Manages key acquisition and ticket processing

## 🛡️ Security Features

### Encryption Implementation
```python
# AES-CBC encryption with 256-bit keys
class SecurityProtocol:
    def encrypt(self, message: bytes, key: bytes) -> bytes:
        iv = os.urandom(16)  # Random IV generation
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(message, AES.block_size))
```

### Protocol Features
- Random nonce generation for replay protection
- Secure ticket generation and validation
- Timestamp-based expiration
- SHA-256 password hashing
- AES-256 encryption in CBC mode

## 📦 Project Structure

```plaintext
project/
├── server/
│   ├── auth_server.py      # Authentication server implementation
│   ├── message_server.py   # Message server implementation
│   └── utils/
│       ├── crypto.py       # Cryptographic operations
│       └── protocol.py     # Protocol definitions
├── client/
│   ├── client_main.py     # Client application
│   └── utils/
│       ├── comm.py        # Communication handler
│       └── security.py    # Security operations
└── common/
    ├── constants.py       # Shared constants
    └── protocol_sizes.py  # Protocol specifications
```

## 🚀 Installation & Usage

1. System Requirements:
```bash
# Python 3.8+ or C++17
pip install pycryptodome  # For Python implementation
```

2. Configuration Files:
```plaintext
port.info    # Server port configuration
msg.info     # Message server details
me.info      # Client information
```

3. Running the System:
```bash
# Start Authentication Server
python auth_server.py

# Start Message Server
python message_server.py

# Run Client
python client_main.py
```

## 🔧 Technical Specifications

### Message Format
```plaintext
+----------------+------------------+------------------+
| Header (23b)   | Payload Size    | Encrypted Data   |
|                | (4b)            | (Variable)       |
+----------------+------------------+------------------+
```

### Protocol Codes
- Registration: 1024
- Key Request: 1027
- Message Send: 1029
- Success Response: 1600
- Error Response: 1601

## 🔍 Security Considerations

1. **Authentication**
   - Password hashing using SHA-256
   - Ticket-based authentication
   - Session key management

2. **Encryption**
   - AES-256 in CBC mode
   - Random IV generation
   - Secure key storage

3. **Protocol Security**
   - Replay attack prevention
   - Message integrity verification
   - Session timeout handling

## 💻 Development Practices

- Comprehensive error handling
- Thread safety implementation
- Modular architecture
- Extensive input validation
- Secure coding practices

## 📚 Documentation

Detailed documentation available for:
- Protocol specifications
- Security implementations
- API references
- Deployment guides

## 🤝 Contributing

This is an academic project developed for [Course Code: 20940]. Contributions should follow the project's coding standards and security requirements.

## 📜 License

This project is developed for academic purposes. All rights reserved.

---

*This project 
