#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include "error_codes.h"

#define BUFFER_SIZE 1024
#define MAX_LENGTH 1024
#define WRITE_PACKET_SIZE 32

char* nm_IP;
int nm_PORT;

char* ss_IP;
int ss_PORT;

int create_socket() {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    return sock_fd;
}

void connect_to_server(int sock_fd, char *ip, int port) {
    struct sockaddr_in server_addr;

    // Zero out the structure
    memset(&server_addr, 0, sizeof(server_addr));

    // Assign IP and PORT
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    // Convert IPv4 and IPv6 addresses from text to binary
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        printf("\nERROR009: Invalid address/ Address not supported \n");
        exit(EXIT_FAILURE);
    }

    // Connect to the server
    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        printf("\nERROR009: Connection Failed\n");
        exit(EXIT_FAILURE);
    }
}

void send_data(int sock_fd, char *data, size_t data_size) {
    if (send(sock_fd, data, data_size, 0) != data_size) {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }
}

int receive_data(int sock_fd, char *buffer, size_t buffer_size) {
    bzero(buffer, buffer_size);
    ssize_t bytes_received = recv(sock_fd, buffer, buffer_size, 0);
    if (bytes_received < 0) {
        perror("Receive failed");
        exit(EXIT_FAILURE);
    }
    // Null-terminate if necessary
    buffer[bytes_received] = '\0';
    return bytes_received;
}

void handle_tree_command(int socket_fd, char *path) {
    char command[MAX_LENGTH];
    char buffer[BUFFER_SIZE];

    // Prepare and send the TREE command
    snprintf(command, MAX_LENGTH, "TREE %s", path);
    send_data(socket_fd, command, strlen(command));

    // Receive the directory tree from the server
    while (1) {
        ssize_t bytes_received = recv(socket_fd, buffer, BUFFER_SIZE - 1, 0);
        if (bytes_received <= 0) {
            // perror("Receive error or connection closed");
            break;
        }
        buffer[bytes_received] = '\0';

        // Check for "END_OF_TREE" message
        if (strcmp(buffer, "END_OF_TREE") == 0) {
            printf("Directory listing completed.\n");
            break;
        }

        // Print the received data
        printf("%s", buffer);
    }
}

typedef struct writer_arg{
    int sock_fd;
}writer_arg;

void* handle_big_write(void* arg){
    int ss_sock_fd = ((writer_arg*)arg)->sock_fd;
    char write_buffer[WRITE_PACKET_SIZE];
    char response_buffer[BUFFER_SIZE];
    FILE *file = fopen("tmp", "r");
    if (file == NULL) {
        perror("Error opening file");
        return NULL;
    }
    int count=0;
    size_t bytes_read = fread(write_buffer, 1, WRITE_PACKET_SIZE, file);
    while (bytes_read > 0) {
        write_buffer[bytes_read] = '\0'; // Ensure null termination for safe string handling

        // Send the chunk
        send_data(ss_sock_fd, write_buffer, strlen(write_buffer));

        // Wait for acknowledgment
        receive_data(ss_sock_fd, response_buffer, BUFFER_SIZE);
        if(strcmp(response_buffer, "rec_ack")!=0){
            printf("Failed to send packet\n");
            continue;
        }

        bytes_read = fread(write_buffer, 1, WRITE_PACKET_SIZE, file);
        // printf("run %d\n", count++);
    }

    while(1){
        send_data(ss_sock_fd, "STOP", 4);
        receive_data(ss_sock_fd, response_buffer, BUFFER_SIZE);
        if(strcmp(response_buffer, "stop_ack")==0) break;
    }
    fclose(file);

    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <Server IP> <Port>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    nm_IP = argv[1];
    nm_PORT = atoi(argv[2]);

    int nm_sock_fd = create_socket();
    connect_to_server(nm_sock_fd, nm_IP, nm_PORT);

    char* operation = (char*)malloc(1024);
    char* buffer = (char*)malloc(1024);
    
    // Initial Message to confirm if connection is either client or storage server
    send_data(nm_sock_fd, "CLIENT", 6);
    receive_data(nm_sock_fd, buffer, 1024);
    printf("Naming Server: %s\n", buffer);

    while (1) {

        printf("Enter operation: ");
        fgets(operation, 1024, stdin);
        operation[strcspn(operation, "\n")] = 0;
        if(strncmp(operation, "EXIT", 4) == 0) {
            send_data(nm_sock_fd, operation, strlen(operation));
            break;
        }
        
        send_data(nm_sock_fd, operation, strlen(operation));

        bzero(buffer, 1024);
        if (strncmp(operation, "COPY", 4) == 0) {            
            while (strstr(buffer, "ACK") == NULL && strstr(buffer, "ERR107") == NULL) {
                receive_data(nm_sock_fd, buffer, 1024);
                printf("NM Response: %s\n", buffer);
                if (strcmp(buffer, "") == 0) {
                    printf("ERROR: No response from Naming Server\n");
                    break;
                }
            }
            continue;
        }

        receive_data(nm_sock_fd, buffer, 1024);
        printf("NM Response: %s\n", buffer);


        if (strncmp(buffer, "IP:", 3) == 0) {

            // Parse IP and port from NM response
            char ss_ip[INET_ADDRSTRLEN];
            int ss_port;
            sscanf(buffer, "IP: %s Port: %d", ss_ip, &ss_port);

            // Connect to SS
            int ss_sock_fd = create_socket();
            connect_to_server(ss_sock_fd, ss_ip, ss_port);

            send_data(ss_sock_fd, operation, strlen(operation));
            // printf("Operation sent to SS: %s\n", operation);
            
            if(strncmp(operation, "STREAM", 6) == 0) {
                FILE *mpv_fp = popen("mpv --no-video -", "w");
                if (mpv_fp == NULL) {
                    perror("Failed to open mpv");
                    close(ss_sock_fd);
                    continue;
                }

                // Receive data from SS and write to mpv
                char ss_buffer[1024];
                while (1) {
                    ssize_t bytes_received = recv(ss_sock_fd, ss_buffer, sizeof(ss_buffer), 0);
                    if (bytes_received < 0) {
                        perror("Receive failed");
                        break;
                    } else if (bytes_received == 0) {
                        // Connection closed by server
                        break;
                    }

                    // Write data to mpv
                    size_t bytes_written = fwrite(ss_buffer, 1, bytes_received, mpv_fp);
                    if (bytes_written < bytes_received) {
                        perror("Write to mpv failed");
                        break;
                    }
                }

                // Close mpv process
                pclose(mpv_fp);
            }

            else if(strncmp(operation, "READ", 4) == 0) {
                printf("\nFile Content:\n");
                while (1) {
                    ssize_t bytes_received = recv(ss_sock_fd, buffer, 1024 - 1, 0);
                    if(bytes_received < 0) {
                        perror("Receive failed");
                        break;
                    }
                    else if(bytes_received == 0) {
                        // Connection closed by server
                        break;
                    }
                    buffer[bytes_received] = '\0'; // Null-terminate the received data
                    // Check if an error message is received
                    if(strncmp(buffer, "ACK:", 4) == 0) {
                        printf("\nEnd of File\n\n");
                        break;
                    }
                    if(strncmp(buffer, "ERR", 3) == 0) {
                        printf("%s\n", buffer);
                        break;
                    }
                    printf("%s", buffer); // Print the received data to the terminal
                }
            }

            else if(strncmp(operation, "INFO", 4) == 0) {
                receive_data(ss_sock_fd, buffer, 1024);
                printf("File Info: %s\n", buffer);
            }

            else if(strncmp(operation, "WRITE", 5) == 0) {
                int is_sync = (strstr(operation, "--SYNC") != NULL);
                char write_buffer[WRITE_PACKET_SIZE];
                printf("Enter data to write: ");
                fflush(stdout);
                // printf("cp1\n");
                memset(write_buffer, 0, WRITE_PACKET_SIZE);
                fgets(write_buffer, WRITE_PACKET_SIZE, stdin);
                size_t bytes_read = fread(write_buffer, 1, WRITE_PACKET_SIZE, stdin);
                // write_buffer[strcspn(write_buffer, EOF)] = 0;
                if (bytes_read == 0) {
                    if (feof(stdin)) {
                        clearerr(stdin); // Reset stdin for future reads
                        printf("\nEOF detected. Exiting write operation.\n");
                        continue;
                    } else {
                        perror("Error reading from stdin");
                        clearerr(stdin);
                        continue;
                    }
                }

                if (bytes_read == 1 && write_buffer[0] == '\n') {
                    printf("Blank input detected. Please enter data to write.\n");
                    continue;
                }

                if(strlen(write_buffer)<WRITE_PACKET_SIZE){
                    send_data(ss_sock_fd, "SYNC_SMOL", 10);
                    receive_data(ss_sock_fd, buffer, 1024);
                    // printf("received ack: %s\n", buffer);
                    if(strstr(buffer, "sync_smol_ack")==NULL){
                        printf("ERROR: Writing SYNC data failed\n");
                        continue;
                    }
                    send_data(ss_sock_fd, write_buffer, strlen(write_buffer));
                    receive_data(ss_sock_fd, buffer, 1024);
                    printf("SS Response: %s\n", buffer);
                } else {
                    FILE *file = fopen("tmp", "w");
                    if (file == NULL) {
                        perror("Error opening file");
                        return EXIT_FAILURE;
                    }
                    fwrite(write_buffer, 1, bytes_read, file);
                    while ((bytes_read = fread(write_buffer, 1, WRITE_PACKET_SIZE, stdin)) > 0) {
                        fwrite(write_buffer, 1, bytes_read, file);
                    }
                    fclose(file);
                    // printf("async cp1\n");
                    writer_arg *arg = (writer_arg*)malloc(sizeof(writer_arg));
                    arg->sock_fd = ss_sock_fd;

                    if(is_sync) {
                        send_data(ss_sock_fd, "SYNC_BIG", 9);
                        receive_data(ss_sock_fd, buffer, 1024);
                        // printf("ack received: %s\n", buffer);
                        if(strstr(buffer, "sync_big_ack")==NULL){
                            printf("ERROR: Writing SYNC data failed\n");
                            continue;
                        }
                        handle_big_write((void *)arg);
                    } else {
                        send_data(ss_sock_fd, "ASYNC", 6);
                        receive_data(ss_sock_fd, buffer, 1024);
                        printf("received ack: %s\n", buffer);
                        if(strstr(buffer, "async_ack")==NULL){
                            printf("ERROR: Writing ASYNC data failed\n");
                            continue;
                        }
                        pthread_t writer_thread;
                        pthread_create(&writer_thread, NULL, handle_big_write, (void*)arg);
                    }
                }
                 int ch;
                while ((ch = getchar()) != '\n' && ch != EOF);

                // Reset stdin state for the next iteration
                clearerr(stdin);
            }

            else if (strncmp(operation, "TREE", 4) == 0) {
                // Send operation to Naming Server
                send_data(nm_sock_fd, operation, strlen(operation));

                // Receive response from NM (IP and Port of SS)
                char *buffer = (char *)malloc(BUFFER_SIZE);
                ssize_t bytes_received = receive_data(nm_sock_fd, buffer, BUFFER_SIZE);
                if (bytes_received <= 0) {
                    // perror("No response from Naming Server");
                    free(buffer);
                    continue;
                }
                buffer[bytes_received] = '\0';

                // Parse the IP and Port
                char ss_ip[INET_ADDRSTRLEN];
                int ss_port;
                if (sscanf(buffer, "IP: %s Port: %d", ss_ip, &ss_port) != 2) {
                    printf("ERROR008: Invalid response from Naming Server - %s\n", buffer);
                    free(buffer);
                    continue;
                }
                free(buffer);

                printf("Connecting to Storage Server at %s:%d\n", ss_ip, ss_port);

                // Connect to the Storage Server
                int ss_sock_fd = create_socket();
                connect_to_server(ss_sock_fd, ss_ip, ss_port);

                // Extract the path from the operation
                char path[MAX_LENGTH];
                if (sscanf(operation + 5, "%s", path) != 1) {
                    printf("Usage: TREE <path>\n");
                    close(ss_sock_fd);
                    continue;
                }

                // Call the handle_tree_command function
                handle_tree_command(ss_sock_fd, path);

                // Close the SS connection
                close(ss_sock_fd);
            }

            else printf("ERROR001: Invalid operation\n");

            // Close SS connection
            close(ss_sock_fd);
        }
    }

    close(nm_sock_fd);
}