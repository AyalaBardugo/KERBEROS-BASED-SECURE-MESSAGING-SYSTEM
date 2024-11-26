
# 🔐 KERBEROS BASED SECURE MESSAGING SYSTEM

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/Security-Encryption-green.svg)]()

## 📋 Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Security Features](#security-features)
- [Components](#components)
- [Installation](#installation)
- [Usage](#usage)

## 🌟 Overview

This project implements a secure messaging system based on the Kerberos authentication protocol. It features a complete client-server architecture with encryption, authentication, and secure message transmission capabilities.
### Key Features
- ✅ Kerberos-based authentication system
- 🔒 AES-CBC encryption for secure communication
- 🎯 Multi-threaded server architecture
- 📝 Persistent client registration
- 🔑 Secure key distribution
- 📋 Message encryption and delivery confirmation

## 🏗️ System Architecture

The system consists of three main components:

1. **Authentication Server**
   - Handles user registration and authentication
   - Manages symmetric key distribution
   - Maintains client records and sessions

2. **Message Server**
   - Relays encrypted messages between clients
   - Validates message authenticity
   - Manages message queuing and delivery

3. **Client Application**
   - Provides user interface for messaging
   - Handles local encryption/decryption
   - Manages user sessions and credentials

## 🛡️ Security Features

### Encryption
- AES-256 encryption in CBC mode
- Secure random IV generation
- Proper key derivation and management
- Protected key storage

### Authentication
- Secure password hashing using SHA-256
- Challenge-response authentication
- Session ticket management
- Expiration controls

### Protocol Security
- Protected against replay attacks
- Message integrity verification
- Secure key exchange protocol
- Time-based token validation

## 🔧 Components

### Client Module
```python
client_main.py
├── Registration handling
├── Authentication
├── Message encryption
└── Communication management
```

### Server Modules
```python
server_main.py
├── Client connection handling
├── Request processing
├── Session management
└── Response generation

message_server_main.py
├── Message routing
├── Encryption verification
├── Client session management
└── Message delivery
```

### Utility Modules
```python
crypto.py
├── AES encryption/decryption
├── Key generation
└── IV management

communication_handler.py
├── Socket management
├── Protocol implementation
└── Error handling
```

## 🚀 Installation & Usage

- System Requirements:
```bash
# Python 3.8+ or C++17
pip install pycryptodome  # For Python implementation
```

- Running the System:
```bash
# Start Authentication Server
python auth_server.py

# Start Message Server
python message_server.py

# Run Client
python client_main.py
```

## 🔍 Technical Details

### Protocol Specification

The system implements a custom secure messaging protocol with the following features:

#### Message Format
```
+-----------------+----------------+------------------+
| Header (23 bytes)| Payload Size   | Encrypted Payload|
+-----------------+----------------+------------------+
```

#### Authentication Flow
1. Client registration request
2. Server verification
3. Symmetric key exchange
4. Session ticket generation
5. Secure channel establishment

### Performance Considerations

- Asynchronous message handling
- Efficient memory usage
- Connection pooling
- Optimized encryption operations
