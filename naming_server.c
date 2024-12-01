#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>      
#include <stdarg.h>    
#include <pthread.h>    
#include <dirent.h>
#include <sys/stat.h>

#define PORT 0
#define MAX_LENGTH 1024

#define MAX_STORAGE_SERVERS 100
#define MAX_PATHS 100
#define MAX_PATH_ENTRIES 1000

typedef struct StorageServer {
    int id;

    char ip[INET_ADDRSTRLEN];
    int client_port;  // Port for client communication
    int ss_socket;    // Socket descriptor for NM-SS communication
    int nm_port;

    int num_paths;
    char paths[MAX_PATH_ENTRIES][MAX_LENGTH];

    bool running;

    time_t last_heartbeat;
    int beatcount;
} StorageServer;

#define MAX_CACHE_SIZE 100  // Fixed maximum cache size

typedef struct {
    char path[MAX_LENGTH];
    StorageServer* ss;
} CacheEntry;


#define MAX_SUB_DIR 100
#define MAX_DIR_NAME 256

typedef struct TrieNode {
    char name[MAX_DIR_NAME];
    struct TrieNode* children[MAX_SUB_DIR];
    int storage_server_id;
} TrieNode;

TrieNode* root;

// FUNCTION DEFINITIONS

void add_storage_server(StorageServer* ss);
void close_storage_server(StorageServer* ss);
void add_path(char* file_path, int storage_server_id);
StorageServer* get_ss_for_path(char* file_path);
void delete_paths_with_ss_id(TrieNode* node, int storage_server_id);
void remove_storage_server_paths(int storage_server_id);
void print_paths(TrieNode* node, char* buffer, int depth);
void log_message(const char *format, ...);
int create_socket();
void close_connection(int sock_fd, fd_set *master_set);
void setup_server_socket(int sock_fd, int port);
void print_ip_addresses();
void send_data(int sock_fd, char *data, size_t data_size);
void receive_data(int sock_fd, char *buffer, size_t buffer_size);
int cache_lookup(const char* path, StorageServer** ss);
void cache_add(const char* path, StorageServer* ss);
char* get_file_name(char *path);
bool copy_directory(char *src_path, char *dest_path, int client_sock_fd);
bool copy_file(char *src_path, char *dest_path, int client_sock_fd);
void process_client_request(int sock_fd, char *message);
void process_storage_server_message(int sock_fd, char *message, StorageServer **storage_server);
void *monitor_storage_servers(void *arg);
void* listener(void* args);


// STORAGE SERVER

StorageServer* storage_servers[MAX_PATH_ENTRIES];
int ss_count = 0;

void add_storage_server(StorageServer* ss) {
    for (int i = 0; i < ss->num_paths; i++) {
        char* pass = strdup(ss->paths[i]);
        add_path(pass, ss->id);

        printf("Added path: %s\n", ss->paths[i]);
    }

    ss_count++;

    printf("Added storage server %d with IP %s, client port %d with %d paths\n", ss->id, ss->ip, ss->client_port, ss->num_paths);
    log_message("Added storage server %d with IP %s, client port %d with %d paths", ss->id, ss->ip, ss->client_port, ss->num_paths);
    
    printf("Paths available now are:\n");
    char buffer[1024];
    bzero(buffer, sizeof(buffer));
    print_paths(root, buffer, 0);
}

void close_storage_server(StorageServer* ss) {
    storage_servers[ss->id]->running = false;
    remove_storage_server_paths(ss->id);
    ss_count--;

    printf("Storage server %d is no longer running\n", ss->id);
    log_message("Storage server %d is no longer running", ss->id);

    printf("Paths available now are:\n");
    char buffer[1024];
    bzero(buffer, sizeof(buffer));
    print_paths(root, buffer, 0);
}

int connect_to_ss(StorageServer* ss) {
    int ss_sock_fd = create_socket();

    // Set up the storage server address
    struct sockaddr_in ss_addr;
    memset(&ss_addr, 0, sizeof(ss_addr));
    ss_addr.sin_family = AF_INET;
    ss_addr.sin_port = htons(ss->nm_port);
    
    if (inet_pton(AF_INET, ss->ip, &ss_addr.sin_addr) <= 0) {
        perror("Invalid storage server address");
        return -1;
    }

    // Connect to the storage server
    if (connect(ss_sock_fd, (struct sockaddr *)&ss_addr, sizeof(ss_addr)) < 0) {
        perror("Connection to storage server failed");
        close(ss_sock_fd);
        return -1;
    }

    return ss_sock_fd;
}


// CACHE

CacheEntry cache[MAX_CACHE_SIZE];
int cache_size = 0;
int cache_start = 0;  // Points to the oldest entry


// TRIE


void add_path(char* file_path, int storage_server_id) {
    char* token = strtok(file_path, "/");
    TrieNode* current = root;

    while (token != NULL) {
        bool found = false;
        for (int i = 0; i < MAX_SUB_DIR; i++) {
            if (current->children[i] != NULL && strcmp(current->children[i]->name, token) == 0) {
                current = current->children[i];
                found = true;
                break;
            }
        }

        if (!found) {
            TrieNode* new_node = (TrieNode*) malloc(sizeof(TrieNode));
            strcpy(new_node->name, token);
            for (int i = 0; i < MAX_SUB_DIR; i++) {
                new_node->children[i] = NULL;
            }
            new_node->storage_server_id = -1; 

            for (int i = 0; i < MAX_SUB_DIR; i++) {
                if (current->children[i] == NULL) {
                    current->children[i] = new_node;
                    current = new_node;
                    break;
                }
            }
        }
        token = strtok(NULL, "/");
    }

    current->storage_server_id = storage_server_id;
}

StorageServer* get_ss_for_path(char* fp) {
    char* file_path = strdup(fp);
    char* token = strtok(file_path, "/");
    TrieNode* current = root;

    while (token != NULL) {
        bool found = false;
        for (int i = 0; i < MAX_SUB_DIR; i++) {
            if (current->children[i] != NULL && strcmp(current->children[i]->name, token) == 0) {
                current = current->children[i];
                found = true;
                break;
            }
        }
        
        token = strtok(NULL, "/");
    }

    if (current->storage_server_id == -1) return NULL;

    return storage_servers[current->storage_server_id];
}

void delete_paths_with_ss_id(TrieNode* node, int storage_server_id) {
    if (node == NULL) return;

    for (int i = 0; i < MAX_SUB_DIR; i++) {
        if (node->children[i] != NULL) {
            delete_paths_with_ss_id(node->children[i], storage_server_id);
            if (node->children[i]->storage_server_id == storage_server_id) {
                free(node->children[i]);
                node->children[i] = NULL;
            }
        }
    }
}

void remove_storage_server_paths(int storage_server_id) {
    TrieNode* current = root;
    delete_paths_with_ss_id(current, storage_server_id);
}

void print_paths(TrieNode* node, char* buffer, int depth) {
    if (!node) return;

    // Append the current node's name to the path buffer
    if (depth > 0) {
        strcat(buffer, "/");
    }
    strcat(buffer, node->name);

    // If this node marks the end of a storage server path, print the path
    if (node->storage_server_id != -1) {
        printf("%s (Storage Server ID: %d)\n", buffer, node->storage_server_id);
    }

    // Traverse all children
    for (int i = 0; i < MAX_SUB_DIR; i++) {
        if (node->children[i]) {
            // Save the current state of the buffer before recursion
            char temp[MAX_LENGTH];
            strcpy(temp, buffer);

            // Recurse to the child
            print_paths(node->children[i], buffer, depth + 1);

            // Restore the buffer
            strcpy(buffer, temp);
        }
    }

    // Remove the current node's name from the buffer for backtracking
    if (depth > 0) {
        char* last_slash = strrchr(buffer, '/');
        if (last_slash) {
            *last_slash = '\0';
        }
    } else {
        buffer[0] = '\0'; // Reset the buffer if at the root
    }
}


// Logs a message to log.txt with a timestamp

void log_message(const char *format, ...) {
    // Prepare the message
    va_list args;
    va_start(args, format);
    char log_buffer[MAX_LENGTH];
    vsnprintf(log_buffer, sizeof(log_buffer), format, args);
    va_end(args);

    // Open log.txt in append mode
    FILE *log_file = fopen("log.txt", "a");
    if (log_file == NULL) {
        perror("Could not open log.txt");
        return;
    }

    // Write the log message without timestamp
    fprintf(log_file, "%s\n", log_buffer);
    fclose(log_file);
}


// SERVER

int create_socket() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    return sock_fd;
}

void close_connection(int sock_fd, fd_set *master_set) {
    close(sock_fd);
    FD_CLR(sock_fd, master_set);
}

void setup_server_socket(int sock_fd, int port) {
    struct sockaddr_in server_addr;
    socklen_t addrlen = sizeof(server_addr);
    // Zero out the structure
    memset(&server_addr, 0, sizeof(server_addr));

    // Assign IP and PORT
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Accept connections from any IP
    server_addr.sin_port = htons(port);

    // Bind the socket
    if (bind(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (getsockname(sock_fd, (struct sockaddr *)&server_addr, &addrlen) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }
    int portnum = ntohs(server_addr.sin_port);
    printf("Port: %i\n", portnum);

    // Listen
    if (listen(sock_fd, SOMAXCONN) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }
}

void print_ip_addresses() {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[NI_MAXHOST];
    
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }
    
    printf("Server IP addresses:\n");
    // Walk through linked list of interfaces
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
    
        family = ifa->ifa_addr->sa_family;
    
        // Check for IPv4 addresses (AF_INET) and exclude loopback interface
        if (family == AF_INET && (ifa->ifa_flags & IFF_LOOPBACK) == 0) {
            // Get the IP address
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST) == 0) {
                printf("\tInterface : %s\n", ifa->ifa_name);
                printf("\t  Address : %s\n", host);
            }
        }
    }
    
    freeifaddrs(ifaddr);
}


// HELPERS

void send_data(int sock_fd, char *data, size_t data_size) {
    if (sock_fd == -1) {
        return;
    }
    if (send(sock_fd, data, data_size, 0) != data_size) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
}

void receive_data(int sock_fd, char *buffer, size_t buffer_size) {
    bzero(buffer, buffer_size);
    ssize_t bytes_received = recv(sock_fd, buffer, buffer_size, 0);
    if (bytes_received < 0) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }
    // Null-terminate if necessary
    buffer[bytes_received] = '\0';
}


// CACHE

int cache_lookup(const char* path, StorageServer** ss) {
    int index = -1;
    // Search the cache
    for (int i = 0; i < cache_size; i++) {
        int pos = (cache_start + i) % MAX_CACHE_SIZE;

        if (strcmp(path, cache[pos].path) == 0) {
            // Found matching entry
            index = pos;
            break;
        }
    }
    if (index != -1) {
        // Move entry to the most recently used position
        CacheEntry temp = cache[index];
        for (int i = index; i != (cache_start + cache_size - 1) % MAX_CACHE_SIZE; i = (i + 1) % MAX_CACHE_SIZE) {
            int next = (i + 1) % MAX_CACHE_SIZE;
            cache[i] = cache[next];
        }
        int end = (cache_start + cache_size - 1) % MAX_CACHE_SIZE;
        cache[end] = temp;
        *ss = cache[end].ss;
        // *ss = cache[index].ss;
        return 1;  // Cache hit
    }
    return 0;  // Cache miss
}

void cache_add(const char* path, StorageServer* ss) {
    if (cache_size < MAX_CACHE_SIZE) {
        // Add new entry at the end
        int pos = (cache_start + cache_size) % MAX_CACHE_SIZE;
        strcpy(cache[pos].path, path);
        cache[pos].ss = ss;
        cache_size++;
    } else {
        // Overwrite oldest entry
        cache_start = (cache_start + 1) % MAX_CACHE_SIZE;
        int pos = (cache_start + cache_size - 1) % MAX_CACHE_SIZE;
        strcpy(cache[pos].path, path);
        cache[pos].ss = ss;
    }
    printf("Added to cache: %s\n", path);
}


// COPYING

#define WRITE_PACKET_SIZE 32

// Helper function to get the file name from a given path
char* get_file_name(char *path) {
    char *file_name = strrchr(path, '/');
    return (file_name) ? file_name + 1 : path;
}

// Function to copy a file, ensuring the destination path includes the file name
bool copy_file(char *src_path, char *dest_path, int client_sock_fd) {
    // Send write confirmation to destination storage server
    char* extension = strrchr(dest_path, '.');

    StorageServer* dest_ss = get_ss_for_path(dest_path);
    if (dest_ss == NULL) {
        printf("ERR100: Destination path doesn't exist\n");
        send_data(client_sock_fd, "ERR100: Destination path doesn't exist\n", 31);
        return false;
    }

    int dest_ss_sock_fd = connect_to_ss(dest_ss);
    if (dest_ss_sock_fd == -1) {
        printf("Error connecting to storage server\n");
        return false;
    }

    char* message = (char*)malloc(MAX_LENGTH);
    snprintf(message, MAX_LENGTH, "WRITE %s", dest_path);   
    send_data(dest_ss_sock_fd, message, strlen(message));
    printf("Sent operation to destination SS: %s\n", message);

    StorageServer* src_ss = get_ss_for_path(src_path);
    if (src_ss == NULL) {
        printf("ERR100: Source path doesn't exist\n");
        send_data(client_sock_fd, "ERR100: Source path doesn't exist\n", 31);
        send_data(dest_ss_sock_fd, "exit", 4);
        return false;
    }
    
    int src_ss_sock_fd = connect_to_ss(src_ss);
    if (src_ss_sock_fd == -1) {
        printf("Error connecting to storage server\n");
        send_data(dest_ss_sock_fd, "exit", 4);
        return false;
    }

    snprintf(message, MAX_LENGTH, "READ %s", src_path);
    send_data(src_ss_sock_fd, message, strlen(message));
    printf("Sent operation to source SS: %s\n", message);
    
    printf("Starting reading.\n");

    // Keep receiving data until an acknowledgment is received
    char* temp_file = (char*)malloc(MAX_LENGTH);
    snprintf(temp_file, MAX_LENGTH, "tmp%s", extension);
    FILE *tmp_file = fopen(temp_file, "wb");
    while (true) {
        char buffer[MAX_LENGTH];
        receive_data(src_ss_sock_fd, buffer, MAX_LENGTH);
        if (strncmp(buffer, "ACK", 3) == 0) {
            break;
        }
        if (strncmp(buffer, "ERR", 3) == 0) {
            printf("Error reading file\n");
            send_data(client_sock_fd, buffer, strlen(buffer));
            send_data(dest_ss_sock_fd, "exit", 4);
            return false;
        }
        fprintf(tmp_file, "%s", buffer);
    }
    fclose(tmp_file);
    close(src_ss_sock_fd);

    printf("File read successfully.\n");

    send_data(dest_ss_sock_fd, "ASYNC", 5);
    printf("Sent ASYNC command to destination SS %d\n", dest_ss->id);

    char* buffer = (char*) malloc(MAX_LENGTH);

    receive_data(dest_ss_sock_fd, buffer, MAX_LENGTH);
    printf("Recieved ACK: %s\n", buffer);
    if (strstr(buffer, "async_ack") == NULL){
        printf("ERROR: Writing ASYNC data failed\n");
        return false;
    }

    char write_buffer[WRITE_PACKET_SIZE];
    char response_buffer[MAX_LENGTH];

    FILE *file = fopen(temp_file, "rb");
    if (file == NULL) {
        printf("Error opening file\n");
        return false;
    }

    int count = 0;
    size_t bytes_read = fread(write_buffer, 1, WRITE_PACKET_SIZE, file);
    while (bytes_read > 0) {
        write_buffer[bytes_read] = '\0'; // Ensure null termination for safe string handling

        // Send the chunk
        send_data(dest_ss_sock_fd, write_buffer, strlen(write_buffer));

        // Wait for acknowledgment
        receive_data(dest_ss_sock_fd, response_buffer, MAX_LENGTH);

        if (strncmp(response_buffer, "ERR", 3) == 0) {
            printf("Error writing to file\n");
            send_data(client_sock_fd, response_buffer, strlen(response_buffer));
            return false;
        }

        if(strcmp(response_buffer, "rec_ack")!=0){
            printf("Failed to send packet\n");
            continue;
        }
        

        bytes_read = fread(write_buffer, 1, WRITE_PACKET_SIZE, file);
    }

    while (true) {
        send_data(dest_ss_sock_fd, "STOP", 4);
        bzero(response_buffer, MAX_LENGTH);
        receive_data(dest_ss_sock_fd, response_buffer, MAX_LENGTH);
        if (strcmp(response_buffer, "stop_ack") == 0) break;
    }
    fclose(file);    

    printf("File copied successfully.\n");
    return true;
}

// Function to copy a directory recursively, ensuring proper path handling
bool copy_directory(char *src_path, char *dest_path, int client_sock_fd) {
    // Get SS for source path
    StorageServer* src_ss = get_ss_for_path(src_path);
    if (src_ss == NULL) {
        printf("ERR100: Source path doesn't exist\n");
        send_data(client_sock_fd, "ERR100: Source path doesn't exist\n", 31);
        return false;
    }

    // Connect to source storage server
    int src_ss_sock_fd = connect_to_ss(src_ss);
    if (src_ss_sock_fd == -1) {
        printf("Error connecting to storage server\n");
        return false;
    }

    // Get SS for destination path
    StorageServer* dest_ss = get_ss_for_path(dest_path);
    if (dest_ss == NULL) {
        printf("ERR100: Destination path doesn't exist\n");
        send_data(client_sock_fd, "ERR100: Destination path doesn't exist\n", 34);
        return false;
    }

    // Send TREE command to source storage server

    char command[MAX_LENGTH];
    char buffer[MAX_LENGTH];

    // Prepare and send the TREE command
    snprintf(command, MAX_LENGTH, "TREE %s", src_path);
    send_data(src_ss_sock_fd, command, strlen(command));
    usleep(1000000);

    char path[MAX_LENGTH];
    bzero(path, sizeof(path));
    path[0] = '/';

    int depth = 0;

    // Receive the directory tree from the server
    while (true) {
        send_data(src_ss_sock_fd, "NEXT", 4);
        ssize_t bytes_received = recv(src_ss_sock_fd, buffer, MAX_LENGTH - 1, 0);
        if (bytes_received <= 0) {
            perror("Receive error or connection closed");
            break;
        }
        buffer[bytes_received - 1] = '\0';

        // Check for "END_OF_TREE" message
        if (strncmp(buffer, "ACK", 3) == 0) {
            printf("Directory listing completed.\n");
            break;
        }

        int cur_depth = strstr(buffer, "|-- ") - buffer;
        while (cur_depth <= depth) {
            char* last_slash = strrchr(path, '/');
            if (last_slash) {
                *last_slash = '\0';
            }
            depth -= 4;
        }

        // Append the current directory to the path
        snprintf(path + strlen(path), MAX_LENGTH - strlen(path), "/%s", strstr(buffer, "|-- ") + 4);
        printf("%s\n", path);

        // Connect to destination storage server        

        // Send the COPY command to the destination storage server, if the file is a path
        char* filename = get_file_name(path);

        if (strstr(buffer, ".") == NULL) {
            printf("Creating directory: %s%s\n", dest_path, path);

            // Connect to the destination storage server
            int dest_ss_sock_fd = connect_to_ss(dest_ss);
            if (dest_ss_sock_fd == -1) {
                send_data(client_sock_fd, "ERR002: Invalid storage server address\n", 41);
                return false;
            }

            char* command = (char*)malloc(MAX_LENGTH);
            snprintf(command, MAX_LENGTH, "CREATE %s%s", dest_path, path);
            send_data(dest_ss_sock_fd, command, strlen(command));

            // Receive acknowledgment from the storage server
            char* ack_buffer = (char*)malloc(MAX_LENGTH);
            bzero(ack_buffer, MAX_LENGTH);
            receive_data(dest_ss_sock_fd, ack_buffer, MAX_LENGTH);

            if (strncmp(ack_buffer, "ACK", 3) == 0 || strncmp(ack_buffer, "ERR101", 6) == 0) {
                printf("Directory creation success.\n");
            } else {
                printf("Directory creation failed: %s\n", ack_buffer);
                send_data(client_sock_fd, ack_buffer, strlen(ack_buffer));
                close(dest_ss_sock_fd);
                return false;
            }

            close(dest_ss_sock_fd);
        } else {
            // Copy the file
            char f_src_path[MAX_LENGTH];
            char d_src_path[MAX_LENGTH];
            snprintf(f_src_path, MAX_LENGTH, "%s%s", src_path, path);
            snprintf(d_src_path, MAX_LENGTH, "%s%s", dest_path, path);

            printf("Copying file: %s to %s\n", f_src_path, d_src_path);

            copy_file(f_src_path, d_src_path, client_sock_fd);
        }

        depth = cur_depth;
    }
    
    return true;
}

bool backup(StorageServer* src, StorageServer* dest) {
    printf("Backing up storage server %d in SS %d\n", src->id, dest->id);
    log_message("Backing up storage server %d in SS %d and %d", src->id, dest->id);
    
    // if (dest == NULL || !dest->running) {
    //     printf("Destination storage server not available.\n");
    //     log_message("Destination storage server not available.");
    //     return false;
    // }

    // for (int i = 0; i < src->num_paths; i++) {
    //     char* path = src->paths[i];
    //     char* dest_path = (char*) malloc(MAX_LENGTH);
    //     snprintf(dest_path, MAX_LENGTH, "backup_%d/%s", src->id, path);

    //     copy_directory(path, dest_path, -1);
    // }

    return true;
}

// PROCESSING

void process_client_request(int sock_fd, char *message) {
    // Parse and process the client request

    printf("Processing client request: %s\n", message);

    // Log the client request

    log_message("Processing client request on socket %d: %s", sock_fd, message);


    // Parse the message

    char* operation = (char*) malloc(MAX_LENGTH);
    char* path = (char*) malloc(MAX_LENGTH);
    char* dest = (char*) malloc(MAX_LENGTH);
    char* message_dup = (char*) malloc(MAX_LENGTH);
    strcpy(message_dup, message);

    char *token = strtok(message, " ");
    if (token == NULL) {
        printf("Invalid client request.\n");
        send_data(sock_fd, "ERR001: Invalid request\n", 25);
        return;
    }
    strcpy(operation, token);

    printf("Operation: %s\n", operation);

    token = strtok(NULL, " ");
    if (token == NULL) {
        printf("Invalid client request: no path specified.\n");
        send_data(sock_fd, "ERR007: No path specified\n", 27);
        return;
    }
    strcpy(path, token);

    printf("Path: %s\n", path);

    if (strcmp(operation, "COPY") == 0) {
        token = strtok(NULL, " ");
        if (token == NULL) {
            printf("Invalid client request: no destination specified.\n");
            send_data(sock_fd, "ERR007: No destination specified\n", 34);
            return;
        }
        strcpy(dest, token);
    }

    // Check LRU cache for the path
    StorageServer *ss = NULL;

    char* lookup = strdup(path);
    char* last = strrchr(lookup, '/');
    if (last != NULL && strchr(last, '.') != NULL) {
        *last = '\0';
    }

    if (cache_lookup(lookup, &ss)) {
        printf("Cache hit for path: %s\n", path);
    } 
    if (ss == NULL) {
        printf("Cache miss for path: %s\n", path);
        
        ss = get_ss_for_path(lookup);
        if(ss == NULL) {
            printf("Path not found: %s\n", lookup);
            log_message("Path not found for request on socket %d: %s", sock_fd, lookup);
            send_data(sock_fd, "ERR100: Path not found\n", 24);
            if (strcmp(operation, "COPY") == 0) {
                send_data(sock_fd, "ERR107: Copy operation failed\n", 31);
                free(path);
                free(operation);
                free(dest);
            }
            return;
        }
        cache_add(lookup, ss);
        printf("Path: %s SS:%d\n", path, ss->id);
    }


    if (strcmp(operation, "READ") == 0 || strcmp(operation, "WRITE") == 0 || 
        strcmp(operation, "INFO") == 0 || strcmp(operation, "STREAM") == 0 || 
        strcmp(operation, "TREE") == 0) {
        
        // Send information to the client about the storage server
        printf("Client command.\n");
        char response[MAX_LENGTH];
        snprintf(response, sizeof(response), "IP: %s Port: %d", ss->ip, ss->client_port);
        send_data(sock_fd, response, strlen(response));
        printf("Response sent to client on socket %d: %s\n", sock_fd, response);
    }

     // Send the operation message to the storage server

    if (strcmp(operation, "CREATE") == 0 || strcmp(operation, "DELETE") == 0) {
        int ss_sock_fd = connect_to_ss(ss);

        if (ss_sock_fd == -1) {
            send_data(sock_fd, "ERR002: Invalid storage server address\n", 41);
            return;
        }
        // Send the operation message to the storage server
        send_data(ss_sock_fd, message_dup, strlen(message_dup));

        // Receive acknowledgment from the storage server
        char* ack_buffer = (char*)malloc(MAX_LENGTH);
        bzero(ack_buffer, MAX_LENGTH);
        receive_data(ss_sock_fd, ack_buffer, MAX_LENGTH);

        // Send acknowledgment back to the client
        send_data(sock_fd, ack_buffer, strlen(ack_buffer));
        close(ss_sock_fd);
    }


    else if (strcmp(operation, "COPY") == 0) {
        printf("Destination: %s\n", dest);
        // copy_directory(path, dest, sock_fd);
        // send_data(sock_fd, "ERR107: Copy operation failed\n", 31);

        char* filename = get_file_name(path);

        bool result;
        if (strstr(filename, ".") != NULL) {
            // Copy file
            printf("Copying file\n");
            result = copy_file(path, dest, sock_fd);
            
        } 
        else {
            // Copy directory
            result = copy_directory(path, dest, sock_fd);
        }

        if (result) {
            send_data(sock_fd, "ACK: COPY Successful\n", 23);
        } else {
            send_data(sock_fd, "ERR107: Copy operation failed\n", 31);
        }
    }


    // After sending response
    log_message("Response sent to client on socket %d", sock_fd);

    free(path);
    free(operation);
}

void process_storage_server_message(int sock_fd, char *message, StorageServer **storage_server) {
    // Parse and process the storage server message

    log_message("Processing storage server message on socket %d: %s", sock_fd, message);

    if (strncmp(message, "REGISTER", 8) == 0) { // Registration message
        char ip[INET_ADDRSTRLEN];
        int client_port;
        int nm_port;
        int id;

        char *token = strtok(message, " "); // "REGISTER"

        token = strtok(NULL, " "); // ID
        if (token == NULL) {
            printf("ERR007: Invalid registration message from storage server (no ID).\n");
            return;
        }
        id = atoi(token);

        token = strtok(NULL, " "); // IP
        if (token == NULL) {
            printf("ERR007: Invalid registration message from storage server (no IP).\n");
            return;
        }
        strcpy(ip, token);

        token = strtok(NULL, " "); // nm_port
        if (token == NULL) {
            printf("ERR007: Invalid registration message from storage server (no naming server port).\n");
            return;
        }
        nm_port = atoi(token);

        token = strtok(NULL, " "); // cl_port
        if (token == NULL) {
            printf("ERR007: Invalid registration message from storage server (no client port).\n");
            return;
        }
        client_port = atoi(token);


        if (storage_servers[id] != NULL) {
            printf("Storage server with that IP has already been initialised.\n");
            if (storage_servers[id]->running) {
                printf("Storage server is already running.\n");
                send_data(sock_fd, "BLOCKED", 7);
                return;
            }
            
            StorageServer *ss = storage_servers[id];
            printf("Attempting to restart storage server...\n");

            ss->client_port = client_port;
            ss->nm_port = nm_port;
            ss->ss_socket = sock_fd;
            ss->running = true;

            add_storage_server(ss);

            // Send confirmation
            send_data(sock_fd, "REGISTRATION_SUCCESSFUL", 23);
            *storage_server = ss;
            return;
        }
        

        token = strtok(NULL, " "); // path
        if (token == NULL) {
            printf("ERR007: Invalid registration message from storage server (no paths).\n");
            return;
        }
        char* paths = (char*)malloc(MAX_LENGTH);
        strcpy(paths, token);


        StorageServer *ss = (StorageServer*) malloc(sizeof(StorageServer));
        strcpy(ss->ip, ip);
        ss->id = id;
        ss->client_port = client_port;
        ss->ss_socket = sock_fd;
        ss->nm_port = nm_port;
        ss->running = true;

        int num_paths = 0;

        token = strtok(paths, ",");
        while(token != NULL) {
            strcpy(ss->paths[num_paths++], token);
            token = strtok(NULL, ",");
        }
        ss->num_paths = num_paths;

        storage_servers[id] = ss;

        add_storage_server(ss);

        // Send acknowledgment
        send_data(sock_fd, "REGISTRATION_SUCCESSFUL", 23);
        free(paths);

        *storage_server = ss;
    }

    else if (strncmp(message, "HEARTBEAT", 9) == 0) {
        int ss_id;
        sscanf(message, "HEARTBEAT %d", &ss_id);
        StorageServer *ss = storage_servers[ss_id];
        if (ss != NULL) {
            ss->last_heartbeat = time(NULL);
            ss->running = true;
            ss->beatcount++;
        }
    }
    else {
        // Other messages
        send_data(sock_fd, "ERR008: UNKNOWN_MESSAGE", 23);
    }
}


// HEARTBEAT 

#define HEARTBEATFREQ 10    // in seconds
#define BACKUPFREQ 30       // in seconds

void *monitor_storage_servers(void *arg) {
    printf("SS monitoring Initialized\n");

    while (true) {
        time_t now = time(NULL);
        for (int i = 0; i < MAX_STORAGE_SERVERS; i++) {
            StorageServer *ss = storage_servers[i];
            if (ss == NULL) continue;

            if (ss->running && difftime(now, ss->last_heartbeat) > 3 * HEARTBEATFREQ) {
                // Storage server has not sent a heartbeat in a while, mark as inactive
                close_storage_server(ss);
            }

            if (ss_count >= 3 && ss->running && (ss->beatcount * HEARTBEATFREQ) % BACKUPFREQ == 0) {
                // Backup the storage server    
                bool b1 = backup(ss, storage_servers[(ss->id + 1) % ss_count]);
                bool b2 = backup(ss, storage_servers[(ss->id + 2) % ss_count]);

                printf("SS %d backed up in %d servers.\n", ss->id, b1 + b2);
            }
        }
        sleep(HEARTBEATFREQ); 
        
    }
    return NULL;
}


// LISTENING

typedef struct {
    int sock_fd;
    struct sockaddr_in addr;
    char peer_ip[INET_ADDRSTRLEN];
    fd_set master_set;
    int type;
} ListenerArgs;

// Handler for a single connection

void* listener(void* args) {
    ListenerArgs *listener_args = (ListenerArgs*)args;
    int sock_fd = listener_args->sock_fd;
    char *peer_ip = listener_args->peer_ip;
    int peer_port = ntohs(listener_args->addr.sin_port);
    fd_set *master_set = &(listener_args->master_set);
    int type = listener_args->type;
    
    StorageServer *ss = NULL;

    printf("Listening to: \tSocket: %d\n\t\tIP: %s\n\t\tPort: %d\n", sock_fd, peer_ip, peer_port);

    while (true) {
        char buffer[MAX_LENGTH];
        memset(buffer, 0, sizeof(buffer));

        // Receive data

        ssize_t bytes_received = recv(sock_fd, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Socket %d hung up\n", sock_fd);
                log_message("Socket %d hung up", sock_fd);
            } else {
                perror("recv");
                log_message("Receive error on socket %d", sock_fd);
            }
            close_connection(sock_fd, master_set);

            // Storage server has lost connection
            if (ss) close_storage_server(ss);

            return NULL;
        }
        buffer[bytes_received] = '\0';

        // Log the received message

        log_message("Received message from %s:%d (socket %d): %s", peer_ip, peer_port, sock_fd, buffer);

        // Process the received message

        if (type == 1) {
            printf("Received from client (%d): %s\n", sock_fd, buffer);
            process_client_request(sock_fd, buffer);
        }
        else if (type == 2) {
            if (strstr(buffer, "HEARTBEAT") == NULL)
                printf("Received from storage server (%d): %s\n", sock_fd, buffer);
            process_storage_server_message(sock_fd, buffer, &ss);
            if (ss == NULL) return NULL;
        }
    }
    
    return NULL;
}


int main() {
    // Clear the log file at the start
    FILE *log_file = fopen("log.txt", "w");
    if (log_file == NULL) {
        perror("Could not open log.txt");
        exit(EXIT_FAILURE);
    }
    fclose(log_file);

    // Log server start with timestamp
    log_message("Naming server started");


    // Initialise Trie for filepaths
    root = (TrieNode*) malloc(sizeof(TrieNode));
    strcpy(root->name, "");
    root->storage_server_id = -1;


    int sock_fd = create_socket();
    setup_server_socket(sock_fd, PORT);
    print_ip_addresses();

    printf("Naming server is running and accepting connections...\n");

    fd_set master_set, read_fds;
    int fdmax;

    FD_ZERO(&master_set);
    FD_ZERO(&read_fds);

    // Add the listening socket to the master set
    FD_SET(sock_fd, &master_set);
    fdmax = sock_fd;
    pthread_t monitor_tid;
    pthread_create(&monitor_tid, NULL, monitor_storage_servers, NULL);

    while (true) {
        printf("Waiting for connections...\n");
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);

        int new_socket = accept(sock_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (new_socket < 0) {
            perror("Accepting new client failed.");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        int client_port = ntohs(client_addr.sin_port);


        // Log the new connection

        log_message("Accepted new connection from %s:%d (socket %d)", client_ip, client_port, new_socket);


        // Add the new socket to the master set

        FD_SET(new_socket, &master_set);
        if (new_socket > fdmax) {
            fdmax = new_socket;
        }


        // Receive the initial message to identify the connection type

        char buffer[MAX_LENGTH];
        memset(buffer, 0, sizeof(buffer));
        ssize_t bytes_received = recv(new_socket, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            perror("Receiving initial message failed.");
            close(new_socket);
            FD_CLR(new_socket, &master_set);
            continue;
        }   
        buffer[bytes_received] = '\0';


        // Identify the connection type & hand over to a seperate listener for that connection

        ListenerArgs* listener_args = (ListenerArgs*) malloc(sizeof(ListenerArgs));
        listener_args->sock_fd = new_socket;
        listener_args->addr = client_addr;
        strcpy(listener_args->peer_ip, client_ip);
        listener_args->master_set = master_set;

        if (strncmp(buffer, "STORAGE_SERVER", 14) == 0) {
            printf("Connected to a storage server\n");
            send_data(new_socket, "STORAGE_SERVER_ACK", 18);
            listener_args->type = 2;

            pthread_t storage_server_thread;
            pthread_create(&storage_server_thread, NULL, listener, (void*)listener_args);
        } 
        else if (strncmp(buffer, "CLIENT", 6) == 0) {
            printf("Connected to a client\n");
            send_data(new_socket, "CLIENT_ACK", 10);
            listener_args->type = 1;

            pthread_t client_thread;
            pthread_create(&client_thread, NULL, listener, (void*)listener_args);
        } 
        else {
            printf("Unknown connection type\n");
            close(new_socket);
            FD_CLR(new_socket, &master_set);
        }
    }

    close(sock_fd); // Close the socket when done
    return 0;
}

