# 🔒 Forged-Cloud

Forged Cloud is a highly secure, 100% CLI-based private cloud file server written in Rust, designed to provide encrypted storage, secure uploads, and fine-grained access control for a trusted set of clients. The system combines a TLS-protected TCP control server with an HTTPS file server, enabling reliable and secure file exchange without graphical interfaces or external dependencies. Its architecture emphasizes security-first design, strict client and resource management, modularity, and efficient asynchronous concurrency, making it well suited for self-hosted, private, family, or small trusted environments.

# 🔐 Main Features:

**1. Secure Networking**
 * **TCP Server with TLS**
   
   Handles encrypted client connections over TCP, ensuring confidentiality and integrity of all data in transit. Supports only IPv4         connections for controlled deployment.

 * **HTTPS File Server**
   
   Serves files securely over HTTPS using Rustls and Hyper. Each file download is protected by a unique, expiring token, ensuring only      authorized clients can access the data.

 * **Mutual TLS (mTLS)**
   
   Supports client certificate cerification for an additional layer of security in trusted environments.

**2. Client Authentication & Access Control**

 * **Password-Based Authentication**
   
   Server passwords are hashed with Argon2 and stored securely in memory using Zeroizing to prevent accidental leaks.
  
 * **Login Attempt Monitoring & IP Banning**
   
   Automatically tracks failed login attempts per client IP. After three failed attempts, the IP is banned to mitigate brute-force          attacks.
   
 * **Session Management**
   
   Each client is assigned a UUID, and the server maintains an active session list with concurrent-safe updates.
   
 * **Inactivity Timeout**
   
   Clients are automatically disconnected after 2 minutes of inactivity, preserving resources and reducing attack surface.
   
 * **Connection Limits**

   The maximum number of concurrent clients can be configured at startup, allowing controlled resource usage depending on the deployment    environment.

**3. File Management & Safety**

 * **Sanitized File Access**
   
   Prevents path traversal or unauthorized file access. Only files within the designated ./files directory are accessible.
   
 * **Formatted File Listing**

   Provides a clear, organized listing of available files for clients.

 * **Secure File Reading**
   
   Efficiently reads files into memory while handling errors gracefully and logging only relevant security and system events.

 * **Safe Upload Handling**

   During uploads, if the file transfer is interrupted or the full file is not received, the partially written file is automatically        removed from the server to prevent corruption or storage abuse.

**4. Upload System**

 * **UPLOAD Command**
   
   Allows authenticated clients to upload files directly to the server.
   
 * **Maximum File Size Enforcement**

   The server allows configuration of a maximum upload size at startup. If a client attempts to upload a file larger than the allowed       limit, the upload is rejected before any data transfer begins.
   
 * **Low-Throughput Protection**

   The server actively monitors upload progress. If the transfer rate remains abnormally low for an extended period, the upload is          automatically terminated to prevent long-lasting resource consumption.

 * **Automatic Cleanup on Failure**

   In case of low transfer rate, client disconnection, or incomplete uploads, the server stops the upload and deletes the partially         written file immediately.
   
**5. Download Token System**

 * **Single-Use, Expiring Tokens**
   
   Each download request generates a unique token that expires after 5 minutes. Tokens are consumed on first use to prevent reuse.

 * **Token Cleanup**

   Periodic cleanup of expired or consumed tokens ensures memory efficiency and prevents stale access.

 * **Secure Download URLs**

   Tokens are embedded in HTTPS URLs, providing a safe and convenient download method without exposing file paths.

**6. Available Commands**

After successful authentication, clients can interact with the server using the following commands:

 * **LIST**

   Displays a formatted list of all available files on the server.

 * **DOWNLOAD <filename>**

   Generates a secure, temporary HTTPS download URL for the specified file.

 * **UPLOAD <path_to_file>**

   Uploads a local file to the server, subject to size limits and transfer-rate controls.

**7. Concurrency & Performance**

 * **Async Architecture with Tokio**

   Handles multiple clients concurrently without blocking.

 * **Client Isolation**

   Each client connection runs in a separate asynchronous task, reducing the risk of cascading failures.

 * **Resource-Aware Design**

   Upload throughput monitoring and connection limits prevent abusive or accidental resource exhaustion.

**8. Logging & Monitoring**

 * **Structured Logging with Tracing**

   Tracks authentication attempts, connections, disconnections, uploads, downloads, token usage, and security-relevant events.

**9. Modular & Extensible Design**

 * **Clean Architecture**

   Networking, authentication, file management, upload handling, token management, and security are separated into dedicated modules.

 * **Runtime Configuration**

   Administrators can configure:
   
     - Maximum concurrent clients
     - Maximum upload file size
     - Network binding and ports

 * **Easy to Extend**

   New commands, authentication mechanisms, or file operations can be integrated with minimal impact on existing code.

# ⚙️ PREVIOUS REQUIREMENTS:

 * **Rust's cargo package manager for compiling Rust.**
 * **Openssl for certificates and keys generation.**
 * **Git for additional package instalation.**

# 🚀 SETTING UP GUIDE:

  1. Get the repository: `git clone https://github.com/AdrianUrc/Forged-Cloud.git`
  2. Move in the 'Forged Cloud' repository and make executable the file 'setup.sh':
     - `cd Forged-Cloud`
     - `chmod +x setup.sh`
  3. Execute the file 'setup.sh':
     - This executable generates the crypto for TLS/mTLS autentication, install 'Forged-Cloud-Client' additional package to interact           with the cloud service via Command Line Interface (CLI), and also creates new certs directories for both repos.
     - It supports providing IPv4 or DNS via argument (example: ./setup.sh --ip 185.192.33.22 --dns rust-lang.org) -> OPTIONAL
  4. Run the Cloud Server:
     - Via binary: `cargo build --release` -> move the generated binary located in /Forged-Cloud/target/release/{} to /Forged-Cloud/{}
     - Via cargo: `cargo run -q`
  5. Access the Cloud Server:
     - Move to /Forged-Cloud-Client
     - Run the Cloud Client as same as the Cloud Server

# 👨🏻‍💻 USING THE SERVICE:

  * **UPLOADING FILES**
    
    - Command UPLOAD: `UPLOAD /home/user/secret_file.txt`
      (just needs to specify the file to upload, it is recommended to use absolute-path.)

  * **DOWNLOADING FILES**

    - Command DOWNLOAD: `DOWNLOAD file_name`
      (generates a temporary https-endpoint token (example: `https://domain.com/download/k1j311-3rf3-sfss-121311`))
    
    - COMBINE WITH WGET -> `wget https://domain.com/download/k1j311-3rf3-sfss-121311 --no-check-certificate`

  * **LISTING FILES**

    - Command LIST: `LIST`
      (prints formatted the available files in the server.)

# ⚠️ Author Note:

Forged Cloud is not intended for everyone. It is a privacy- and security-focused file server designed for users who value full control, minimalism, and explicit behavior over convenience. The project follows a UNIX-inspired philosophy, prioritizing efficiency, low resource usage, modularity, and predictable operation. Features are deliberately limited to what is strictly necessary, avoiding unnecessary abstraction, hidden automation, or heavyweight components. Forged Cloud is best suited for small, trusted environments and technically proficient users who prefer transparent security mechanisms, strong cryptography, and a system that is understandable, auditable, and self-hosted by design.
