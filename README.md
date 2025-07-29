# TCP_File_Transfer_System_with_SDN_Integration
This project presents a reliable TCP-based file transfer system that integrates Software-Defined Networking (SDN) to optimize network traffic. Key features include chunked data transmission with error detection and recovery, cryptographic data verification, and SDN-enabled dynamic flow control implemented through Mininet and Ryu controllers.

## Core Components​
### Client Module​
Initiates file transfer requests and handles user authentication​
Manages chunked file uploads with error recovery mechanisms​
Implements parallel transmission using multi-threading​
### Server Module​
Processes client requests and manages file storage/retrieval​
Handles authentication tokens and session management​
Maintains detailed logs with daily rotation in the log directory​
### SDN Controllers​
ryu_forward.py: Basic packet forwarding based on MAC address learning​
ryu_redirect.py: Advanced traffic redirection (e.g., from Server 1 to Server 2)​
Built using Ryu SDN Framework for programmable network control​
### Network Topology​
Defined in networkTopo.py using Mininet​
Consists of 1 client, 2 servers, and 1 OpenFlow switch​
Network configuration:​
Client: IP 10.0.1.5, MAC 00:00:00:00:00:03​
Server 1: IP 10.0.1.2, MAC 00:00:00:00:00:01​
Server 2: IP 10.0.1.3, MAC 00:00:00:00:00:02​
## Key Features​
Chunked File Transfer: Files divided into blocks for efficient transmission, with MD5 hashing for integrity verification​
Reliable Transmission: Implements Go-Back-N (GBN) protocol for error recovery and retransmission​
Secure Authentication: Uses MD5 hashing for password verification and token-based session management​
SDN Integration: Enables dynamic traffic control and redirection to optimize network performance​
Progress Tracking: Utilizes tqdm for real-time upload progress visualization​
## Prerequisites​
Python 3.x​
Mininet (network simulation tool)​
Ryu SDN Framework​
Required packages: tqdm, socket, json, hashlib, threading​
Install dependencies:​
pip install tqdm ryu​
​
## Usage Instructions​
### Network Setup​
sudo python3 networkTopo.py​
​
### SDN Controller Setup​
Basic Forwarding Controller:​
ryu-manager ryu_forward.py​
​
Traffic Redirection Controller:​
ryu-manager ryu_redirect.py​
​
### Server Setup​
Start the server on Server 1 or Server 2 (within Mininet CLI):​
python3 server.py --ip <server_ip> --port 1379​
​
### Client Setup​
Run the client to upload a file:​
python3 client.py --server_ip <server_ip> --id <student_id> --file_path <path_to_file>​
​
## File Transfer Workflow​
Authentication: Client logs in with student ID, password generated as MD5 hash of the ID, token issued on success​
File Preparation: File split into blocks, MD5 hashes computed for integrity checks​
Chunked Upload: Blocks uploaded in parallel using threads, GBN protocol ensures reliable transmission​
SDN Traffic Control: Ryu controller manages network flows, either forwarding or redirecting based on configuration​
## Technical Notes​
Maximum packet size: 20480 bytes​
Transmission retries: Up to 3 times with 20-second interval​
Error handling: Comprehensive mechanisms for transmission failures and integrity issues​
Logging: Detailed server logs stored in log directory with daily rotation​
