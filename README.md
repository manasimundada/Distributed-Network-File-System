[![Review Assignment Due Date](https://web.iiit.ac.in/~siddharth.mago/images/sweets.png)](https://www.youtube.com/watch?v=bAN3KmTSy2Q&list=PLl4fleEI17jedKXDFRfk0z3KNb6MDpKMG&index=10)

# README for Network File System (NFS) Implementation

---

## Initialization

The initialization phase of our Network File System (NFS) involves setting up the **Naming Server (NM)**, **Storage Servers (SS)**, and **Clients**. [Here](https://web.iiit.ac.in/~amol.vijayachandran/) is a (hopefully) exhaustive explanation of how each component is implemented and configured.

### 1. Naming Server (NM)

#### Key Roles
- Acts as the **central directory service** for the NFS, facilitating communication between clients and storage servers.
- Maintains a **directory structure** using a Trie for efficient path lookups and maps each file or directory to its corresponding storage server.
- Manages storage servers' information, including their IP addresses, client ports, available paths, and status (running or not).
- Handles **client requests** such as READ, WRITE, DELETE, COPY, and CREATE by determining the appropriate storage server and forwarding these requests.

#### Data Structures
1. **Storage Server Management**:
   - `StorageServer` struct:
     - `id`: Unique identifier for each storage server.
     - `ip`: The IPv4 address of the storage server, stored as a string.
     - `client_port`: The port used for client-server communication.
     - `ss_socket`: The socket descriptor for communication with the storage server.
     - `nm_port`: Port used for Naming Server communication.
     - `num_paths`: Number of paths the storage server provides.
     - `paths`: Array of strings holding the accessible paths.
     - `running`: Boolean indicating if the storage server is active.
     - `last_heartbeat`: Timestamp of the last received heartbeat signal.
     - `beatcount`: Number of heartbeats received to track server health.

2. **Directory Structure**:
   - `TrieNode` struct:
     - `name`: Name of the file or directory.
     - `children`: Array of pointers to child TrieNodes, each representing a subdirectory or file.
     - `storage_server_id`: ID of the storage server where the file/directory resides.
   - **Root**: A global pointer to the root of the Trie, representing the base directory.

3. **Cache**:
   - `CacheEntry` struct:
     - `path`: Path of the file or directory.
     - `ss`: Pointer to the corresponding `StorageServer`.
   - **LRU Cache**: Fixed-size cache (`MAX_CACHE_SIZE = 100`) to store recent path lookups.
     - `cache`: Array of `CacheEntry` objects.
     - `cache_size`: Number of entries in the cache.
     - `cache_start`: Index pointing to the oldest cache entry for efficient replacement.

#### Initialization Steps
1. **Socket Creation**:
   - `create_socket()`: Creates a TCP socket using `socket(AF_INET, SOCK_STREAM, 0)`. If socket creation fails, the program exits with an error message.
   - **Port Assignment**: `setup_server_socket()` binds the socket to `INADDR_ANY` (all available network interfaces) and dynamically assigns a port using `getsockname()`. The port number is printed for reference.

2. **Server IP Addresses**:
   - `print_ip_addresses()`: Uses `getifaddrs()` to retrieve and display all available IPv4 addresses (excluding loopback) for the NM. This helps identify the server's network configuration.

3. **Storage Server Registration**:
   - **Adding Storage Servers**: `add_storage_server()` registers each storage server, storing details such as IP, client port, and accessible paths. Each path is added to the Trie using `add_path()`, which tokenizes the path and builds the directory structure.
   - **Logging**: Logs each registration to `log.txt` using `log_message()`.
   - **Heartbeat Monitoring**: A separate thread continuously monitors heartbeats from storage servers using `monitor_storage_servers()`. The `last_heartbeat` timestamp and `beatcount` are updated to track server health.

### 2. Storage Server (SS)

#### Key Roles
- Stores files and directories, handling requests from both the NM and clients.
- Provides functionalities like reading, writing, copying, creating, and deleting files and directories.
- Periodically sends **heartbeat messages** to the NM to indicate it is operational.

#### Data Structures
1. **Accessible Paths**:
   - `accessible_paths`: Array of strings, each representing a path accessible by the storage server.
   - `num_paths`: Number of accessible paths configured during initialization.

2. **Socket for NM Communication**:
   - `ns_socket`: Socket descriptor for communication with the Naming Server.

#### Initialization Steps
1. **Local IP Address**:
   - `get_local_ip()`: Retrieves the local IPv4 address using `getifaddrs()`, selecting the first non-loopback address.

2. **Registration with NM**:
   - `register_with_nm()`: Handles the entire registration process:
     - **Socket Creation**: Creates a TCP socket for communication with the NM.
     - **Connecting to NM**: Establishes a connection using the provided NM IP and port.
     - **Sending Registration Details**: Sends server type ("STORAGE_SERVER") and waits for acknowledgment. Constructs a registration message containing:
       - `ss_id`: Unique storage server ID.
       - `local_ip`: Local IP address of the storage server.
       - `nm_conn_port`: Port for NM communication.
       - `client_port`: Port for client communication.
       - **Accessible Paths**: Concatenates all accessible paths, separated by commas.
     - **Receiving Acknowledgment**: Waits for a response from the NM. If registration is successful, the message "REGISTRATION_SUCCESSFUL" is printed.

3. **Error Handling**:
   - If any step fails (e.g., socket creation, invalid NM address, or connection failure), the program exits with an appropriate error message.

### 3. Clients

#### Key Roles
- Clients are responsible for initiating and interacting with the Network File System (NFS) through the Naming Server (NM).
- They request operations like READ, WRITE, CREATE, DELETE, and COPY, which the NM processes by determining the appropriate Storage Server (SS) and establishing the necessary communication channel.

#### Initialization Steps
The client setup process is detailed and follows a structured flow to ensure proper connection and functionality within the NFS.

1. **Command-Line Argument Parsing**:
   - The client program accepts command-line arguments to establish a connection with the NM and to specify paths for file operations.
   - Arguments are parsed using `getopt()` to extract the Naming Server's IP and port:
     - `-n <NM IP>`: Specifies the IP address of the NM.
     - `-p <NM Port>`: Specifies the port number on which the NM is running.
   - Example usage: `./client -n 192.168.1.10 -p 5050`.

2. **Socket Creation for NM Communication**:
   - A **TCP socket** is created using `socket(AF_INET, SOCK_STREAM, 0)`:
     - `AF_INET`: Specifies IPv4 addressing.
     - `SOCK_STREAM`: Specifies a reliable, connection-oriented TCP protocol.
   - If socket creation fails, an error message is printed, and the program exits.

3. **Setting Up Connection Parameters**:
   - `struct sockaddr_in nm_addr` is initialized to specify the NM's address:
     - `nm_addr.sin_family = AF_INET`: Indicates the use of the IPv4 protocol.
     - `nm_addr.sin_port = htons(nm_port)`: Converts the NM port to network byte order.
     - `inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr)`: Converts the NM's IP address from a string to binary form and stores it in `nm_addr.sin_addr`.
   - The program ensures the IP and port information is correctly formatted and ready for connection.

4. **Connecting to the Naming Server**:
   - `connect()` is used to establish a TCP connection to the NM:
     - If the connection fails, an error message is printed, and the program exits.
   - Upon a successful connection, the client receives a welcome acknowledgment from the NM, confirming that the client is ready to issue requests.

5. **Sending Initial Request**:
   - The client constructs an initial message specifying its **connection type** as "CLIENT".
   - This message is sent to the NM using `send()` to notify that a client is ready for interaction.
   - The NM acknowledges this message, signaling that the client can begin sending operation requests.

6. **Handling User Input**:
   - The client waits for user input via the command line, which can be one of the supported operations:
     - **READ**: Requests the content of a specified file.
     - **WRITE**: Sends data to be written to a file, with options for synchronous or asynchronous writing.
     - **CREATE**: Requests the creation of a new file or directory.
     - **DELETE**: Requests the deletion of a specified file or directory.
     - **COPY**: Requests the copying of a file from one path to another.
   - Input is parsed and validated to ensure it conforms to expected formats. Invalid requests trigger an error message.

7. **Sending Operation Requests**:
   - Each user request is formatted as a command string and sent to the NM via `send()`.
   - The client then waits for a response from the NM, which typically includes:
     - **IP Address and Port**: If the operation involves direct communication with an SS.
     - **Error Codes**: If the operation cannot be performed, error messages are displayed.

8. **Direct Communication with Storage Servers**:
   - For operations requiring data transfer (e.g., READ or WRITE), the client uses the provided SS details to establish a new TCP connection.
   - Data packets are exchanged with the SS:
     - For **READ** operations, data is received and displayed until an "END" packet is sent.
     - For **WRITE** operations, data is transmitted in chunks, and the client awaits acknowledgment after each chunk.
   - Connections with SSs are closed once the operation completes or an error occurs.

9. **Error Handling and Feedback**:
   - The client checks for and appropriately handles errors at every step:
     - Connection failures to the NM or SS.
     - Invalid command formats or unsupported operations.
     - Responses from the NM or SS indicating issues like path not found or file already exists.
   - Descriptive error messages are displayed to assist users in understanding and correcting issues.

10. **Logging and Cleanup**:
   - All client activities, including sent commands and received responses, are logged for debugging purposes.
   - Upon termination, the client ensures that all sockets are closed, and any dynamically allocated resources are freed to prevent memory leaks.

---

## Implementation Details
### Storage Server Implementation

Our implementation of the Storage Server (SS) provides a comprehensive, technically detailed structure to handle multiple requests from the Naming Server (NM) and clients, ensuring robust file and directory management within a networked file system. [Here](https://web.iiit.ac.in/~shreeprabhas.e/)’s a detailed breakdown of how the various functionalities have been implemented:

---

#### 1. **Adding New Storage Servers**
   - **Registration with the Naming Server (NM)**
     - **Registration Request**: When a Storage Server is initialized, it sends a registration message to the NM using a dedicated socket (`ns_socket`). This message contains:
       - `STORAGE_SERVER`: Initial message to identify itself.
       - `REGISTER` followed by details:
         - **Server ID**: Unique identifier for the storage server.
         - **Local IP Address**: Obtained using `get_local_ip()` to ensure proper routing.
         - **Connection Port for NM**: Dynamically assigned by the OS and retrieved using `getsockname()`.
         - **Client Port**: Another dynamically assigned port for client communication.
         - **Accessible Paths**: A comma-separated list of directories accessible by the SS, passed as command-line arguments.
     - **Response Handling**: The NM confirms registration by sending a `REGISTRATION_SUCCESSFUL` message, which is verified to ensure the successful integration of the SS.

---

#### 2. **Commands Issued by the Naming Server (NM)**
   - **CREATE (File/Directory)**
     - **Command Handling**: When the NM issues a `CREATE` command:
       - The command is parsed to identify whether the target is a file or directory.
       - **File Creation**: If the path includes a file extension, `open()` is used with flags `O_WRONLY | O_CREAT | O_EXCL` to create a new file.
       - **Directory Creation**: If no extension is present, `mkdir()` is invoked to create a new directory.
       - **Acknowledgment**: Success or failure is communicated back to the NM with appropriate error codes or success messages.
   
   - **DELETE (File/Directory)**
     - **Command Handling**: The `DELETE` command specifies the path of the file or directory to remove.
       - **Path Validation**: `stat()` is called to check if the path exists.
       - **Deletion**: `remove()` is used to delete the specified entity, and an acknowledgment is sent back to the NM.
       - **Error Handling**: If the path does not exist or the deletion fails, descriptive error codes are sent.
   
   - **COPY (Files/Directories)**
     - **Command Parsing**: The `COPY` command specifies both source and destination paths.
       - **File Copying**: `copy_file()` uses `read()` and `write()` syscalls to transfer data from the source to the destination.
       - **Directory Copying**: `copy_directory()` recursively traverses subdirectories and copies each file, using `opendir()`, `readdir()`, and `mkdir()` for directories.
       - **Error and Status Reporting**: Success or failure is conveyed to the NM.

---

#### 3. **Client Interactions**
   - **READ a File**
     - **Request Handling**: Clients request file contents using the `READ` command.
       - **File Access**: `fopen()` is used in `rb` mode to read the file in binary format.
       - **Data Transmission**: The file content is sent in chunks of `BUFFER_SIZE` until EOF, followed by an `ACK: READ successful` message.
       - **Error Handling**: If the file cannot be opened, an error message is sent to the client.
   
   - **WRITE to a File**
     - **Request Parsing**: The `WRITE` command is parsed to determine if the operation is `SYNC` or `ASYNC`.
       - **Synchronous Write**: The data is written directly using `fwrite()` and a completion acknowledgment is sent.
       - **Asynchronous Write**: A separate thread (`handle_async_write()`) is created using `pthread_create()` to handle writing. Data packets are received and written in chunks, with a "STOP" message indicating the end.
       - **Acknowledgments**: Immediate acknowledgment (`async_ack` or `sync_ack`) is sent, with further confirmations as needed.
   
   - **INFO (Size and Permissions)**
     - **Metadata Retrieval**: `stat()` is called to fetch file size and permissions, and this information is formatted and sent to the client.
       - **Error Handling**: If `stat()` fails, an error message is returned.
   
   - **STREAM Audio Files**
     - **Streaming Implementation**: The `STREAM` command reads the file in chunks and sends data packets directly to the client until EOF.
       - **End of Transmission**: A final message indicates the completion of streaming.
       - **Error Handling**: If the file cannot be streamed, a descriptive error message is provided.

---

#### 4. **Directory Listing (TREE Command)**
   - **Recursive Directory Traversal**: `list_directory()` is implemented using `opendir()`, `readdir()`, and recursion to traverse directories and subdirectories.
     - **Formatting**: Each entry is formatted with indentation to visually represent the directory structure.
     - **Data Transmission**: The formatted directory tree is sent line-by-line to the client.
     - **Completion Acknowledgment**: `ACK: TREE successful` marks the end of the listing.

---

#### 5. **Heartbeat Mechanism**
   - **Periodic Heartbeat Messages**: The `heartbeat_thread()` sends a `HEARTBEAT <server_id>` message to the NM every `HEARTBEATFREQ` seconds to indicate the server is alive.
     - **Failure Handling**: If the NM connection is lost, the SS exits to prevent inconsistencies.

---

### Naming Server Implementation

The Naming Server (NM) in our Network File System (NFS) serves as the core management unit, facilitating efficient communication between clients and storage servers while maintaining the directory structure of the file system. [Here](https://web.iiit.ac.in/~vishal.rao/) is a breakdown of each functionality:

---

#### 1. Initialization and Setup
- **Log Initialization**:
  - At the start, `log.txt` is cleared to ensure clean logging for the current session. The `log_message()` function writes logs, appending details of each action taken by the NM.

- **Trie Structure for Directory Management**:
  - A **Trie** is used to maintain the hierarchical directory structure of the NFS. Each node (`TrieNode`) in the Trie represents a directory or file, with:
    - `name`: The name of the file or directory.
    - `children`: An array of pointers to child TrieNodes.
    - `storage_server_id`: The ID of the storage server where the file or directory resides.
  - **Root Node**: The root of the Trie is initialized at the start, representing the base of the directory structure with no associated storage server.

- **Socket Creation and Binding**:
  - `create_socket()` creates a TCP socket using `AF_INET` and `SOCK_STREAM`. The socket is configured for IPv4 communication.
  - `setup_server_socket()` binds the socket to a port and configures it to listen for incoming connections. The port is dynamically assigned using `getsockname()`.
  - **Listening for Connections**: The NM uses `listen()` to prepare for incoming connections, allowing for a maximum backlog of `SOMAXCONN`.

- **IP Address Retrieval**:
  - `print_ip_addresses()` retrieves and prints all non-loopback IPv4 addresses of the NM using `getifaddrs()` and `getnameinfo()`.

- **Thread Management**:
  - **Heartbeat Monitoring**: A thread (`monitor_storage_servers`) is created using `pthread_create()` to monitor the health of storage servers via periodic heartbeats.
  - **Connection Handling**: Separate threads are created for each client and storage server connection using `pthread_create()`. Each thread runs a `listener()` function to manage interactions.

---

#### 2. Storage Server Registration and Management
- **Registration Process**:
  - When a storage server connects, it sends a `REGISTER` message containing:
    - `ID`: Unique identifier for the storage server.
    - `IP`: The IP address of the storage server.
    - `nm_port`: Port for NM communication.
    - `client_port`: Port for client communication.
    - `paths`: Comma-separated list of accessible paths.
  - **Parsing and Validation**: The message is parsed, and if the storage server is new, a `StorageServer` struct is created and populated with the received details. If the storage server is reconnecting, its details are updated.
  - **Adding Paths**: The `add_storage_server()` function adds the paths to the Trie using `add_path()`, mapping each path to the server ID.
  - **Acknowledgment**: A `REGISTRATION_SUCCESSFUL` message is sent to confirm successful registration.

- **Heartbeat Monitoring**:
  - **Heartbeat Messages**: Storage servers periodically send `HEARTBEAT <server_id>` messages to indicate they are active. The NM updates `last_heartbeat` and `beatcount` for the server.
  - **Failure Detection**: If a storage server fails to send a heartbeat for `3 * HEARTBEATFREQ` seconds, it is marked as inactive, and `close_storage_server()` is called to remove its paths from the Trie and update its status.

---

#### 3. Client Request Handling
- **Request Parsing**:
  - `process_client_request()` handles all incoming requests from clients. The function first parses the request to identify the operation type (e.g., READ, WRITE, CREATE, DELETE, COPY).
  - **Command Extraction**: The command is tokenized using `strtok()`, and paths are extracted. If the operation is COPY, both source and destination paths are needed.

- **Path Resolution and Caching**:
  - **Cache Lookup**: The NM uses an LRU cache to speed up path resolution. `cache_lookup()` checks if the path is in the cache, and if not, `get_ss_for_path()` is used to traverse the Trie and find the associated storage server.
  - **Cache Updates**: If a cache miss occurs, the path and corresponding storage server are added to the cache using `cache_add()`.

---

#### 4. Handling Specific Operations
- **CREATE and DELETE**:
  - The NM establishes a connection with the storage server using `connect_to_ss()`.
  - The client’s message (e.g., CREATE or DELETE) is forwarded to the storage server via `send_data()`.
  - The NM waits for an acknowledgment from the storage server using `receive_data()`, which it then forwards to the client.

- **READ and WRITE**:
  - For READ operations, the NM identifies the appropriate storage server and sends the client the server’s IP and port. The client then directly communicates with the storage server.
  - For WRITE operations, the NM can handle both synchronous and asynchronous writes by relaying the request details to the storage server, which then writes the data and sends acknowledgments as needed.

- **COPY (File/Directory)**:
  - The NM checks the existence and type (file or directory) of the source path using `stat()`.
  - **Copy Execution**:
    - If the source is a directory, `copy_directory()` recursively copies all files and subdirectories.
    - If the source is a file, `copy_file()` handles the data transfer.
  - **Error Handling**: If the source path is invalid or the copy operation fails, error messages are sent back to the client.

---

#### 5. Storage Server Communication
- **Handling Messages from Storage Servers**:
  - `process_storage_server_message()` parses messages from storage servers, such as registration and heartbeat messages.
  - **Registration**: If the message is a `REGISTER` command, the NM validates and registers the storage server. Paths are added to the Trie, and an acknowledgment is sent.
  - **Heartbeat**: The NM updates the last heartbeat timestamp for the server and increments `beatcount`.

- **Connection Termination**:
  - `close_connection()` gracefully closes a socket and removes it from the master set.
  - If a storage server disconnects unexpectedly, `close_storage_server()` is called to handle cleanup.

---

#### 6. Logging and Debugging
- **Log Messages**: The `log_message()` function writes logs to `log.txt`, including timestamps, client requests, and storage server status updates.
- **Debug Output**: The NM prints debug information, such as added paths, server registrations, and cache hits/misses, to the console.

---

## Client Implementation

Our client implementation in the Network File System (NFS) is designed to handle a wide range of operations, including connecting to the Naming Server (NM) and Storage Servers (SS), sending and receiving data, and managing file operations efficiently. [Below](https://web.iiit.ac.in/~siddharth.mago/) is a description of each functionality and the technical details of our implementation:

---

#### 1. **Initialization and Setup**
- **Command-Line Argument Parsing**:
  - The client expects two arguments: the IP address of the NM and the port number. These arguments are parsed using `argv`:
    - `nm_IP = argv[1]`: The IP address of the NM.
    - `nm_PORT = atoi(argv[2])`: The port number converted to an integer.
  - The program validates that the correct number of arguments is provided; otherwise, it exits with a usage message.

- **Socket Creation and Connection**:
  - `create_socket()`: A function that creates a TCP socket using `socket(AF_INET, SOCK_STREAM, 0)`. If socket creation fails, an error is printed, and the program exits.
  - `connect_to_server(int sock_fd, char *ip, int port)`: This function establishes a connection to the specified server. It:
    - Initializes a `sockaddr_in` structure with the server’s IP and port.
    - Uses `inet_pton()` to convert the IP address from text to binary form.
    - Calls `connect()` to establish the connection, and if it fails, the program exits with an error message.

---

#### 2. **Communication with Naming Server (NM)**
- **Initial Connection**:
  - The client sends an identification message `"CLIENT"` to the NM using `send_data()`. The NM responds, and the client prints this response to confirm the successful establishment of the connection.

- **Request Handling**:
  - The client continuously waits for user input, which is read using `fgets()`. The newline character is stripped using `strcspn()`.
  - Commands such as `READ`, `WRITE`, `CREATE`, `DELETE`, `COPY`, and `TREE` are parsed and sent to the NM.
  - After sending a command, the client waits for a response from the NM. The response is processed to determine the next steps:
    - If the response contains an IP address and port (e.g., `"IP: 10.2.141.242 Port: 5050"`), the client connects to the specified SS to perform the requested operation.

---

#### 3. **Handling Specific Commands**
- **READ**:
  - The client sends a `READ` request to the SS and waits for the file content.
  - Data is received in chunks using `recv()`. Each chunk is printed until the server sends an `"ACK"` message indicating the end of the file.
  - Error messages beginning with `"ERR"` are printed if any issues occur.

- **WRITE**:
    - **Synchronous Write**:
        - The client first checks if the text to be written is a small amount (less than `WRITE_PACKET_SIZE`), then the text is written directly, using just one buffer. Otherwise, if `--SYNC` flag is present in the operation string, then the client sends the message synchronously even if it is large.
        - Data is read from `stdin` and sent directly to the SS using `send_data()`. The client waits for an acknowledgment (`sync_ack`) before continuing.

  - **Asynchronous Write**:
    - If the write message is longer than `WRITE_PACKET_SIZE` and `--SYNC` flag is not present, the client writes the dat synchronously. It does this by first writing the data to a temporary file (`tmp`).
    - `pthread_create()` is used to start a new thread (`handle_async_write`) that handles writing data to the SS in chunks.
    - The `handle_async_write` function reads from the temporary file and sends data in chunks of `WRITE_PACKET_SIZE`. It waits for acknowledgments (`rec_ack`) after each chunk and sends a `"STOP"` message to indicate the end of the transmission.

- **CREATE and DELETE**:
  - These commands are sent to the NM, which determines the appropriate SS and forwards the request.
  - The client receives the SS details and connects to execute the operation. Success or error messages from the SS are printed to the user.

- **COPY**:
  - The client sends the `COPY` command to the NM, which provides the SS details for the source and destination paths.
  - The client connects to both SSs (if necessary) and handles the data transfer as directed by the NM. Specific details on how data is transferred between servers are managed by the NM and SS.

- **TREE**:
  - The `TREE` command requests a directory listing from the SS.
  - The `handle_tree_command()` function sends the `TREE` command to the SS and prints the received directory structure line by line.
  - The client checks for an `"END_OF_TREE"` message to indicate the end of the listing.

- **INFO**:
  - The `INFO` command retrieves metadata (such as file size and permissions) from the SS.
  - The data is received and printed to the user.

- **STREAM**:
  - The client uses `popen()` to open a process that streams audio data using `mpv`, a command-line music player.
  - The client sends the `STREAM` command to the SS and writes the received audio data to `mpv` in real-time.

---

#### 4. **Data Transmission Functions**
- **send_data(int sock_fd, char *data, size_t data_size)**:
  - Sends data over the socket. If the `send()` operation fails, an error is printed, and the program exits.
- **receive_data(int sock_fd, char *buffer, size_t buffer_size)**:
  - Receives data from the socket, clearing the buffer first. If data reception fails, an error is printed, and the program exits.
  - The buffer is null-terminated to ensure safe string handling.

---

#### 5. **Threaded Operations**
- **Asynchronous Write**:
  - The `handle_async_write()` function runs in a separate thread, handling large data writes asynchronously.
  - The function opens a temporary file (`tmp`), reads data in chunks of `WRITE_PACKET_SIZE`, and sends each chunk to the SS. It waits for an acknowledgment before sending the next chunk.
  - Once all data is sent, a `"STOP"` message is transmitted to signal the end of the write operation.

---

#### 6. **Error Handling**
- **Error Codes**:
  - Custom error messages are defined in `error_codes.h` and used throughout the client to communicate issues (e.g., `ERROR009: Invalid address` or `ERROR008: Invalid response`).
  - Full list of errors:
  ```c
    // Success Code
    #define ERR_SUCCESS 0

    // General Errors
    #define ERR_INVALID_COMMAND          1
    #define ERR_STORAGE_SERVER_UNAVAILABLE 2
    #define ERR_NAMING_SERVER_UNAVAILABLE 3
    #define ERR_INVALID_COMMAND_FORMAT   4
    #define ERR_INVALID_PATH             5
    #define ERR_UNKNOWN_ERROR            6
    #define ERR_INVALID_ARGUMENTS        7
    #define ERR_UNKNOWN_MESSAGE          8
    #define ERR_CONNECTION_FAILED        9

    // File Errors
    #define ERR_FILE_NOT_FOUND           100
    #define ERR_PATH_ALREADY_EXISTS      101
    #define ERR_FILE_IN_USE              102
    #define ERR_FILE_CREATION_FAILED     103
    #define ERR_FILE_DELETION_FAILED     104
    #define ERR_FILE_READ_FAILED         105
    #define ERR_FILE_WRITE_FAILED        106
    #define ERR_FILE_COPY_FAILED         107

    // Directory Errors
    #define ERR_DIR_NOT_FOUND            200
    #define ERR_DIR_ALREADY_EXISTS       201
    #define ERR_DIR_CREATION_FAILED      202
    #define ERR_DIR_DELETION_FAILED      203

    // Permission Errors
    #define ERR_PERMISSION_DENIED        300

    // Other Errors
    #define ERR_PATH_NOT_ALLOWED         400

  ```

- **Connection Failures**:
  - If the client fails to connect to the NM or SS, descriptive error messages are printed, and the client exits.
- **Input Validation**:
  - Commands are validated before being sent to the server, and improper inputs are handled gracefully with error messages.

---

## Assumptions Made

- Any file must have a . extension and folders do not have a '.' in their name
- Assuming maximum cache size is 100, this can be changed by changing the `BUFFER_SIZE`
- Commands are of a maximum length of 1024 characters, this can be changed by changing the `MAX_LENGTH`
- A maximum of 100 storage servers can be present at any given moment, this can be changed by changing the `MAX_STORAGE_SERVERS`
- Each storage server can have a maximum of 1000 paths corresponding to it, this can be changed by changing the `MAX_PATH_ENTRIES`
- Write is done asynchronously by default if the number of characters is greater than 1024, this can be changed by changing the `WRITE_PACKET_SIZE` 