# TCP File Transfer System with SDN Integration

This project presents a reliable TCP-based file transfer system enhanced with Software-Defined Networking (SDN). It supports secure and efficient file transmission with dynamic network control. Key features include chunked data transfer with integrity verification, Go-Back-N retransmission, and SDN-based traffic redirection using Mininet and Ryu.

## 🔧 System Architecture

The system integrates traditional TCP socket communication with SDN-based dynamic traffic control. It consists of three core modules:

### 1. Client Module
- Authenticates user with student ID and MD5-hashed password.
- Splits files into chunks and computes MD5 hashes for integrity verification.
- Uploads chunks in parallel using multi-threading.
- Implements the Go-Back-N protocol for error detection and retransmission.

### 2. Server Module
- Verifies tokens and manages sessions.
- Receives and reassembles file chunks.
- Stores detailed logs with daily rotation in the `/log/` directory.

### 3. SDN Controller (Ryu-based)
- `ryu_forward.py`: Implements MAC-learning switch with basic forwarding.
- `ryu_redirect.py`: Redirects incoming traffic to alternative server nodes.
- Controllers dynamically install OpenFlow rules to control traffic flow in real-time.

## 🖧 Network Topology

The emulated network is defined using Mininet and includes:
- One client, two servers, one OpenFlow switch.

Static IP and MAC address configuration:
- **Client**: `10.0.1.5`, `00:00:00:00:00:03`  
- **Server 1**: `10.0.1.2`, `00:00:00:00:00:01`  
- **Server 2**: `10.0.1.3`, `00:00:00:00:00:02`  

This setup allows flexible routing and redirection logic for testing SDN-based control.

## 🌟 Key Features

- **Chunked Transmission**: Files are divided into fixed-size blocks with MD5 checksums for integrity validation.
- **Reliable Transfer**: Go-Back-N protocol supports retransmission upon packet loss or corruption.
- **Secure Authentication**: MD5-hashed ID login with token-based session control.
- **Programmable Networking**: Ryu controller enforces forwarding/redirection policies in real time.
- **Real-time Progress**: Transfer progress displayed using `tqdm` for user feedback.

## 🔁 File Transfer Workflow

1. **Authentication**: Client sends ID; server returns token upon verification.
2. **File Preparation**: Client computes MD5 hashes and splits file into chunks.
3. **Chunk Upload**: Parallel threads upload chunks, monitored with GBN protocol.
4. **SDN Flow Control**: Ryu controller dynamically decides packet forwarding or redirection.

## ⚙️ Technical Specifications

- **Packet size**: 20,480 bytes
- **Retries**: Max 3 attempts per chunk, 20-second retry interval
- **Logging**: Server logs stored and rotated daily
- **Error Handling**: Detects integrity mismatch, transmission failures, timeouts

## 📚 References

- [Ryu SDN Framework](https://osrg.github.io/ryu/)
- [Mininet](http://mininet.org/)
- [Python `socket` Documentation](https://docs.python.org/3/library/socket.html)
