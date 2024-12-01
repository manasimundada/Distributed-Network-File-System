#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/stat.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>

#include "error_codes.h"

#define BUFFER_SIZE 1024
#define MAX_PATHS 10
#define PORT 0
#define MAX_LENGTH 1024
#define HEARTBEATFREQ 10
#define WRITE_PACKET_SIZE 32


char accessible_paths[MAX_PATHS][MAX_LENGTH]; // List of accessible paths
int num_paths = 0;

int ns_socket;


// HELPERS

void send_data(int sock_fd, char *data, size_t data_size) {
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


// INITIALISATION

// Function to get the local IP address
void get_local_ip(char *ip_buffer) {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs failed");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;
        // Get the first non-loopback IPv4 address
        if (family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK)) {
            getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                        ip_buffer, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            break;
        }
    }
    freeifaddrs(ifaddr);
}

// Function to send registration details to NM
int sock;
void register_with_nm(char *nm_ip, int nm_port, int nm_conn_port, int client_port,int ss_id) {
    printf("REGISTRATION HAS BEGUN\n");
    struct sockaddr_in nm_addr;
    char buffer[BUFFER_SIZE];
    char local_ip[NI_MAXHOST];

    // Get local IP
    get_local_ip(local_ip);

    // Create socket
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    nm_addr.sin_family = AF_INET;
    nm_addr.sin_port = htons(nm_port);

    if (inet_pton(AF_INET, nm_ip, &nm_addr.sin_addr) <= 0) {
        perror("Invalid NM address");
        exit(EXIT_FAILURE);
    }

    // Connect to NM
    if (connect(sock, (struct sockaddr *)&nm_addr, sizeof(nm_addr)) < 0) {
        perror("Connection to NM failed");
        exit(EXIT_FAILURE);
    }
    send_data(sock, "STORAGE_SERVER", 14);
    receive_data(sock, buffer, 1024);
    printf("Naming Server: %s\n", buffer);  

    // Prepare registration details
    sprintf(buffer, "REGISTER %d %s %d %d ",ss_id, local_ip, nm_conn_port, client_port);
    for (int i = 0; i < num_paths; i++) {
        strcat(buffer, accessible_paths[i]);
        strcat(buffer, ",");
    }

    // Send registration details
    send_data(sock, buffer, strlen(buffer));

    // Receive acknowledgment
    receive_data(sock, buffer, BUFFER_SIZE);
    printf("NM Response: %s\n", buffer);

    if (strncmp(buffer, "REGISTRATION_SUCCESSFUL", 23) == 0) {
        printf("Registration successful\n");
    } else {
        printf("Registration failed\n");
        exit(0);
    }
}


// OPERATIONS

// Function to recursively list directories
int list_directory(const char *base_path, int depth, int client_socket) {
    DIR *dir;
    struct dirent *entry;

    // Open the directory
    dir = opendir(base_path);
    if (dir == NULL) {
        // Send error message to client
        char error_msg[BUFFER_SIZE];
        snprintf(error_msg, sizeof(error_msg), "ERR005: Cannot open directory: %s\n", strerror(errno));
        send(client_socket, error_msg, strlen(error_msg), 0);
        return -1;
    }

    while ((entry = readdir(dir)) != NULL) {
        char path[MAX_LENGTH];
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue; // Skip . and ..
        }

        // Construct the full path
        snprintf(path, sizeof(path), "%s/%s", base_path, entry->d_name);

        // Build the line with indentation
        char line[MAX_LENGTH];
        memset(line, 0, sizeof(line));
        for (int i = 0; i < depth; i++) {
            strcat(line, "    ");
        }
        strcat(line, "|-- ");
        strcat(line, entry->d_name);
        strcat(line, "\n");

        // Send the line to the client
        char buffer[BUFFER_SIZE];
        bzero(buffer, BUFFER_SIZE);
        receive_data(client_socket, buffer, BUFFER_SIZE);

        if (strcmp(buffer, "NEXT") != 0) break;
        
        send(client_socket, line, strlen(line), 0);

        // Check if entry is a directory
        struct stat statbuf;
        if (stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode)) {
            // Recursively list the directory
            list_directory(path, depth + 1, client_socket);
        }
    }
    closedir(dir);

    return 0;

    return 0;
}

typedef struct writer_arg{
    int sock_fd;
    char* filename;
}writer_arg;

void *handle_big_write(void* arg){
    char* file_name = ((writer_arg*)arg)->filename;
    int sock_fd = ((writer_arg*)arg)->sock_fd;
    printf("Starting async write to path %s\n", file_name);
    fflush(stdout);
    char write_buffer[WRITE_PACKET_SIZE];

    FILE* file = fopen(file_name, "ab");
    if (file == NULL) {
        perror("Error reopening file");
        return NULL;
    }

    while (true) {
        printf("Trying to recieve on socket %d\n", sock_fd);
        fflush(stdout);
        // Receive a packet
        receive_data(sock_fd, write_buffer, WRITE_PACKET_SIZE);
        printf("Received packet: %s\n", write_buffer);

        // Check if the packet contains "STOP"
        if (strncmp(write_buffer, "STOP", 4) == 0) {
            // Send "stop_ack" and break the loop
            send_data(sock_fd, "stop_ack", 8);
            printf("Received STOP, closing file.\n");
            break;
        }

        // Write the received packet to the file
        fwrite(write_buffer, 1, strlen(write_buffer), file);

        // Send acknowledgment for the received packet
        send_data(sock_fd, "rec_ack", 7);
    }

    fclose(file);
    return NULL;
}

// HANDLERS

typedef struct HandlerArgs {
    int sock_fd;
    char* command;
} HandlerArgs;

int unlink_callback(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int ret = remove(fpath);
    if (ret) perror(fpath);
    return ret;
}

int sanitize_path(const char *path) {
    // Allow only alphanumeric characters, '/', '_', '-', and '.'
    for (size_t i = 0; i < strlen(path); i++) {
        if (!(
            (path[i] >= 'a' && path[i] <= 'z') ||
            (path[i] >= 'A' && path[i] <= 'Z') ||
            (path[i] >= '0' && path[i] <= '9') ||
            path[i] == '/' || path[i] == '_' ||
            path[i] == '-' || path[i] == '.'
        )) {
            return 0; // Invalid character found
        }
    }
    return 1; // Path is safe
}

void* handler(void* args) {
    HandlerArgs *handler_args = (HandlerArgs*)args;
    int sock_fd = handler_args->sock_fd;
    char *command = handler_args->command;

    printf("Received command: %s\n", command);

    // Handle NM commands
    if (strncmp(command, "CREATE", 6) == 0) {
        char* path = (char*)malloc(MAX_LENGTH);
        sscanf(command + 7, "%s", path);

        int val = 0;
        struct stat path_stat;
        int stat_result = stat(path, &path_stat);

        if (stat_result == 0) {
            // Path already exists
            send_data(sock_fd, "ERR101: Path already exists\n", strlen("ERR101: Path already exists\n"));
        } else {
            if (errno == ENOENT) {
                // Path does not exist, determine action based on extension
                char* extension = strrchr(path, '.');

                if (extension != NULL && extension > strrchr(path, '/')) {
                    // File creation (has an extension after the last '/')
                    printf("Creating file: %s\n", path);
                    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0644);
                    if (fd == -1) {
                        perror("File creation failed");
                        send_data(sock_fd, "ERR103: File creation failed\n", strlen("ERR103: File creation failed\n"));
                    } else {
                        close(fd);
                        send_data(sock_fd, "ACK: CREATE_FILE successful\n", strlen("ACK: CREATE_FILE successful\n"));
                    }
                } else {
                    // Directory creation (no valid file extension)
                    printf("Creating directory: %s\n", path);
                    if (mkdir(path, 0755) == -1) {
                        perror("Directory creation failed");
                        send_data(sock_fd, "ERR202: Directory creation failed\n", strlen("ERR202: Directory creation failed\n"));
                    } else {
                        send_data(sock_fd, "ACK: CREATE directory successful\n", strlen("ACK: CREATE directory successful\n"));
                    }
                }
            } else {
                perror("Stat failed");
                send_data(sock_fd, "ERR100: Path not found\n", strlen("ERR100: Path not found\n"));
            }
        }

        free(path);
    }
    
    else if (strncmp(command, "DELETE", 6) == 0) {
        // Delete file or directory
        char path[MAX_LENGTH];
        sscanf(command + 7, "%s", path);
        // printf("Deleting file or directory: %s\n", path);
        struct stat path_stat;
        if (stat(path, &path_stat) == -1) {
            perror("Stat failed");
            send_data(sock_fd, "ERR100: Path not found\n", strlen("ERR100: Path not found\n"));
        } else {
            if (S_ISDIR(path_stat.st_mode)) {
                if (!sanitize_path(path)) {
                    send_data(sock_fd, "ERR104: Invalid characters in path\n", strlen("ERR104: Invalid characters in path\n"));
                    return NULL;
                }

                // Use nftw to delete directory recursively
                if (nftw(path, unlink_callback, 64, FTW_DEPTH | FTW_PHYS) == -1) {
                    perror("nftw failed");
                    send_data(sock_fd, "ERR104: Deletion failed\n", strlen("ERR104: Deletion failed\n"));
                } else {
                    send_data(sock_fd, "ACK: Deletion successful\n", strlen("ACK: Deletion successful\n"));
                }
            } else {
                // It's a file; use remove()
                if (remove(path) == -1) {
                    perror("Deletion failed");
                    send_data(sock_fd, "ERR104: Deletion failed\n", strlen("ERR104: Deletion failed\n"));
                } else {
                    send_data(sock_fd, "ACK: Deletion successful\n", strlen("ACK: Deletion successful\n"));
                }
            }
        }
    } 
    

    // Handle client requests
    if (strncmp(command, "READ", 4) == 0) {
        // Send file content until EOF
        char path[MAX_LENGTH];
        sscanf(command + 5, "%s", path);
        
        printf("Reading file: %s\n", path);
        FILE *fp = fopen(path, "rb");
        if (fp) {
            char file_buffer[BUFFER_SIZE];
            size_t bytes_read;

            while ((bytes_read = fread(file_buffer, 1, BUFFER_SIZE, fp)) > 0) {
                if (send(sock_fd, file_buffer, bytes_read, 0) != bytes_read) {
                    perror("Send error");
                    break;
                }
            }
            fclose(fp);
            usleep(500);
            // Send packet to indicate end of transmission
            send_data(sock_fd, "ACK: READ successful\n", strlen("ACK: READ successful\n"));
        } else {
            perror("File open error");
            send_data(sock_fd, "ERR100: Cannot open file\n", strlen("ERR100: Cannot open file\n"));
        }
    } 
    
    else if (strncmp(command, "WRITE", 5) == 0) {
        // Receive data from client and write to file until "STOP" is received  
        char* path = (char*)malloc(MAX_LENGTH);
        char* file_buffer = (char*)malloc(MAX_LENGTH);
        char write_buffer[WRITE_PACKET_SIZE];
        sscanf(command + 6, "%s", path);

        printf("Writing to file: %s\n", path);
        FILE *fp = fopen(path, "wb");
        if(!fp) {
            perror("File open error");
            send_data(sock_fd, "ERR106: Cannot open file for writing\n", strlen("ERR106: Cannot open file for writing\n"));
            free(path);
            free(file_buffer);
            return NULL;
        }
        
        receive_data(sock_fd, file_buffer, BUFFER_SIZE);
        printf("recieved (on socket %d) write type: %s on\n", sock_fd, file_buffer);
        if (strstr(file_buffer, "exit")) {
            close(sock_fd);
            free(path);
            free(file_buffer);
            return NULL;
        } 

        if(strstr(file_buffer, "ASYNC")){
            fclose(fp);
            send_data(sock_fd, "async_ack", 9);
            pthread_t writer_thread;
            writer_arg *arg = (writer_arg*)malloc(sizeof(writer_arg));
            arg->sock_fd = sock_fd;
            arg->filename = strdup(path);
            pthread_create(&writer_thread, NULL, handle_big_write, (void*)arg);
            pthread_join(writer_thread, NULL);
        } else if(strstr(file_buffer, "SYNC_SMOL")){
            send_data(sock_fd, "sync_smol_ack", 13);
            receive_data(sock_fd, write_buffer, WRITE_PACKET_SIZE);
            fwrite(write_buffer, 1, strlen(write_buffer), fp);
            send_data(sock_fd, "Write Completed\n", 16);
        } else if(strstr(file_buffer, "SYNC_BIG")){
            send_data(sock_fd, "sync_big_ack", 12);
            writer_arg *arg = (writer_arg*)malloc(sizeof(writer_arg));
            arg->sock_fd = sock_fd;
            arg->filename = path;
            handle_big_write((void *)arg);
        }

        fclose(fp);
        // Send acknowledgement to client
        send_data(sock_fd, "ACK: WRITE successful\n", strlen("ACK: WRITE successful\n"));
        
        free(path);
        free(file_buffer);
    } 
    
    else if (strncmp(command, "INFO", 4) == 0) {
        // Get size and permissions
        char path[MAX_LENGTH];
        struct stat st;
        sscanf(command + 5, "%s", path);
        if (stat(path, &st) == 0) {
            sprintf(command, "Size: %lld, Permissions: %o\n", st.st_size, st.st_mode & 0777);
            send(sock_fd, command, strlen(command), 0);
        } else {
            perror("Stat failed");
            send_data(sock_fd, "ERR100: Path not found\n", strlen("ERR100: Path not found\n"));
        }
    } 
    
    else if (strncmp(command, "STREAM", 6) == 0) {
        // Stream audio file
        char path[MAX_LENGTH];
        sscanf(command + 7, "%s", path);
        FILE *fp = fopen(path, "rb");
        if (fp) {
            while (!feof(fp)) {
                int bytes_read = fread(command, 1, BUFFER_SIZE, fp);
                send(sock_fd, command, bytes_read, 0);
            }
            fclose(fp);
        } else {
            perror("File open error");
            send_data(sock_fd, "ERR100: Cannot open file for streaming\n", strlen("ERR100: Cannot open file for streaming\n"));
        }
    } 
    
    else if (strncmp(command, "TREE", 4) == 0) {
        // Handle TREE command
        char path[MAX_LENGTH];
        sscanf(command + 5, "%s", path);

        // Start listing the directory
        int retval = list_directory(path, 0, sock_fd);

        // Send "END_OF_TREE" to indicate completion
        if(retval != -1) send_data(sock_fd, "ACK: TREE successful\n", strlen("ACK: TREE successful\n"));
    }

    close(sock_fd);
    free(handler_args);
    return NULL;
}

void* listener(void* args) {
    printf("LISTENING HAS BEGUN\n");
    int server_fd = *((int *)args);
    int new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);
    char buffer[BUFFER_SIZE];

    while (true) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0) {
            perror("Accept failed");
            continue;
        }

        bzero(buffer, BUFFER_SIZE);
        receive_data(new_socket, buffer, BUFFER_SIZE);

        pthread_t handle_thread;
        HandlerArgs *handler_args = (HandlerArgs *)malloc(sizeof(HandlerArgs));
        handler_args->sock_fd = new_socket;
        handler_args->command = strdup(buffer);

        if (pthread_create(&handle_thread, NULL, handler, (void *)handler_args) != 0) {
            perror("Failed to create thread");
            free(handler_args);
        }
        // pthread_detach(handle_thread);
    }
}

int server_id;  // Variable to store the server ID
void *heartbeat_thread(void *arg) {
    printf("INITIALIZING HEARTBEAT\n");
    while (1) {
        char heartbeat_msg[MAX_LENGTH];
        snprintf(heartbeat_msg, sizeof(heartbeat_msg), "HEARTBEAT %d", server_id);
        send_data(sock, heartbeat_msg, strlen(heartbeat_msg));
        sleep(HEARTBEATFREQ);  // Send heartbeat every 5 seconds
    }
    return NULL;
}

void *nm_listener(void *arg) {
    char buffer[BUFFER_SIZE];
    while (1) {
        ssize_t bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Naming Server connection closed.\n");
            } else {
                perror("recv");
            }
            close(sock);
            exit(0);
        }
        buffer[bytes_received] = '\0';
        printf("Received from Naming Server: %s\n", buffer);

        // Handle any messages or commands from the naming server here
        // For now, it's just printing the received messages
    }
    return NULL;
}

int main(int argc, char *argv[]) {
    int ns_fd, cli_fd;
    struct sockaddr_in nm_conn_addr, client_conn_addr;
    pthread_t nm_thread, client_thread;
    int nm_conn_port = 0, client_port = 0;
    int opt;
    char *nm_ip = NULL;
    int nm_port = 0;

    if (argc < 6) {
        printf("Usage: %s <ID> -n <NM IP> -p <NM Port> [accessible paths...]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    server_id = atoi(argv[1]);
    optind = 2;
    // Parse command-line arguments
    while ((opt = getopt(argc, argv, "n:p:")) != -1) {
        switch (opt) {
            case 'n':
                nm_ip = optarg;
                break;
            case 'p':
                nm_port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "Usage: %s <ID> -n <NM IP> -p <NM Port> [accessible paths...]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Store accessible paths
    for (int i = optind; i < argc && num_paths < MAX_PATHS; i++) {
        strcpy(accessible_paths[num_paths++], argv[i]);
    }

    // Create socket for NM communication (to receive NM commands)
    if ((ns_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    nm_conn_addr.sin_family = AF_INET;
    nm_conn_addr.sin_addr.s_addr = INADDR_ANY;
    nm_conn_addr.sin_port = htons(PORT); // Let OS assign a port

    if (bind(ns_fd, (struct sockaddr *)&nm_conn_addr, sizeof(nm_conn_addr)) < 0) {
        perror("NM bind failed");
        exit(EXIT_FAILURE);
    }

    // Get the assigned port
    socklen_t addrlen = sizeof(nm_conn_addr);
    if (getsockname(ns_fd, (struct sockaddr *)&nm_conn_addr, &addrlen) == -1) {
        perror("getsockname failed");
        exit(EXIT_FAILURE);
    }
    nm_conn_port = ntohs(nm_conn_addr.sin_port);

    if (listen(ns_fd, 5) < 0) {
        perror("NM listen failed");
        exit(EXIT_FAILURE);
    }

    // Create socket for client communication
    if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Client socket failed");
        exit(EXIT_FAILURE);
    }

    client_conn_addr.sin_family = AF_INET;
    client_conn_addr.sin_addr.s_addr = INADDR_ANY;
    client_conn_addr.sin_port = htons(0); // Let OS assign a port

    if (bind(cli_fd, (struct sockaddr *)&client_conn_addr, sizeof(client_conn_addr)) < 0) {
        perror("Client bind failed");
        exit(EXIT_FAILURE);
    }

    // Get the assigned port
    addrlen = sizeof(client_conn_addr);
    if (getsockname(cli_fd, (struct sockaddr *)&client_conn_addr, &addrlen) == -1) {
        perror("getsockname failed");
        exit(EXIT_FAILURE);
    }
    client_port = ntohs(client_conn_addr.sin_port);

    if (listen(cli_fd, 5) < 0) {
        perror("Client listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Storage Server ID %d listening on port %d\n", server_id, nm_port);
    // Register with NM
    register_with_nm(nm_ip, nm_port, nm_conn_port, client_port, server_id);
    printf("REGISTERED WITH NAMING SERVER\n");

    pthread_create(&nm_thread, NULL, listener, &ns_fd);
    printf("CREATED NAMING SERVER THREAD\n");
    pthread_create(&client_thread, NULL, listener, &cli_fd);
    printf("CREATED CLIENT THREAD\n");

    // Start heartbeat thread
    pthread_t heartbeat_tid;
    pthread_create(&heartbeat_tid, NULL, heartbeat_thread, NULL);
    printf("CREATED HEARTBEAT THREAD\n");

    // Start naming server listener thread
    pthread_t nm_listener_thread;
    pthread_create(&nm_listener_thread, NULL, nm_listener, NULL);
    printf("CREATED NAMING SERVER LISTENER THREAD\n");

    pthread_join(nm_thread, NULL);
    printf("EXITED NAMING SERVER THREAD\n");
    pthread_join(client_thread, NULL);
    printf("EXITED CLIENT THREAD\n");

    return 0;
}