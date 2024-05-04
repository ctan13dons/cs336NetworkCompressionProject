#include "compdetect_server.h"

#define SERVER_PORT 7777
#define THRESHOLD 100

void clean_exit(int signal) {
    printf("Received signal %d. Exiting...\n", signal);
    exit(EXIT_SUCCESS); 
}

void preprobe() {
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Define server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // Bind the socket to the IP and port
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 1) < 0) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Accept a client connection
    int client_socket = accept(server_socket, NULL, NULL);
    if (client_socket < 0) {
        perror("accept");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Open file for writing the received JSON data
    FILE *file = fopen("config.json", "w");
    if (!file) {
        perror("Error opening file");
        close(client_socket);
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Receive the file contents and write to file
    char buffer[1024];
    ssize_t bytes_received;
    
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer), 0)) > 0) {
        // Null-terminate and print the received data
        buffer[bytes_received] = '\0';
        printf("Received config file, size: %zd bytes\n", bytes_received);

        // Write the received data to the file
        size_t bytes_written = fwrite(buffer, 1, bytes_received, file);
        if ((ssize_t)bytes_written != bytes_received) {
            perror("fwrite");
            fclose(file);
            close(client_socket);
            close(server_socket);
            exit(EXIT_FAILURE);
        }
    }
    fclose(file);
    close(client_socket);
    close(server_socket);
}

void postprobe(char *server_ip, int post_server_port, char *findings) {
    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set SO_REUSEADDR option
    int reuse_addr = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEPORT, &reuse_addr, sizeof(reuse_addr)) < 0) {
        perror("setsockopt");
        close(server_socket);
        exit(EXIT_FAILURE);      
    }

    // Define server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(post_server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Bind the socket to the IP and port
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_socket, 1) < 0) {
        perror("listen");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Accept the client connection
    int client_socket = accept(server_socket, NULL, NULL);
    if (client_socket < 0) {
        perror("accept");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Send findings to the client
    ssize_t bytes_sent = send(client_socket, findings, strlen(findings), 0);
    if (bytes_sent < 0) {
        perror("send");
        close(client_socket);
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    printf("Findings sent to client\n");

    close(client_socket);
    close(server_socket);
}

void probe(char *server_ip, int udp_dest_port, int inter_measurement_time, int udp_payload_size, int num_udp_packets, char *message) {
    // Create UDP socket
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("Probe UDP Socket Creation Failed");
        exit(EXIT_FAILURE);
    }

    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    server_addr.sin_port = htons(udp_dest_port);

    // Bind socket to port
    if(bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        perror("UDP Bind Fail");
        exit(EXIT_FAILURE);
    }

    // Buffer for receiving UDP packets
    int buffer[udp_payload_size + 2];
    int packet_id;

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    clock_t start_time_low, end_time_low, start_time_high, end_time_high;

    // Measure low entropy time
    printf("Receiving low entropy packets...\n");
    start_time_low = clock();
    for (int i = 0; i <= num_udp_packets; i++) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 3; // Timeout duration in secs
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (ready == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        } else if (ready == 0) {
            printf("Timeout occurred\n");
            break;
        }

        recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
		packet_id = ntohs(*(uint16_t *)buffer); // Retrive packet id
    }
    end_time_low = clock();
    double low_entropy_time = (((double)end_time_low - (double)start_time_low)) / ((double)CLOCKS_PER_SEC * 1000.0);

    // Sleep for shorter time to stay ready for client
    printf("Sleeping for %f sec...\n", (inter_measurement_time - low_entropy_time));
    sleep(inter_measurement_time - low_entropy_time);

    // Measure high entropy time
    printf("Receiving high entropy packets...\n");
    start_time_high = clock();
    for (int i = 0; i <= num_udp_packets; i++) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout;
        timeout.tv_sec = 3; // Timeout duration in secs
        timeout.tv_usec = 0;

        int ready = select(sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (ready == -1) {
            perror("select");
            exit(EXIT_FAILURE);
        } else if (ready == 0) {
            printf("Timeout occurred\n");
            break;
        }

        recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
		packet_id = ntohs(*(uint16_t *)buffer); // Retrive packet id
    }
    end_time_high = clock();
    double high_entropy_time = (((double)end_time_high - (double)start_time_high)) / ((double)CLOCKS_PER_SEC * 1000.0);

    // Check if compression is detected based on the difference in times
    if ((high_entropy_time - low_entropy_time) > THRESHOLD) {
        strcpy(message, "COMPRESSION DETECTED");
    } else {
        strcpy(message, "NO COMPRESSION DETECTED");
    }

    close(sockfd);
}

int main() {
	signal(SIGTERM, clean_exit);
	signal(SIGINT, clean_exit);
	
    preprobe();

    // Open the config file
    FILE *config_file = fopen("config.json", "r");
    if (!config_file) {
        perror("Error opening config file");
        exit(EXIT_FAILURE);
    }

    // Read lines from the config file
    char line[256];
    char server_ip[256] = "";
    
    int udp_source_port = 0;
    int udp_dest_port = 0;
    
    int pre_server_port = 0;
    int post_server_port = 0;
    
    int udp_payload_size = 0;
    int num_udp_packets = 0;

    int inter_measurement_time = 0;
    
    while (fgets(line, sizeof(line), config_file)) {
        // Parse each line and extract the necessary parameters
    	if (strstr(line, "Server IP:")) {
        	sscanf(line, "Server IP: %s", server_ip);
        } else if (strstr(line, "Source Port for UDP:")) {
        	sscanf(line, "Source Port for UDP: %d", &udp_source_port);
        } else if (strstr(line, "Destination Port for UDP:")) {
            sscanf(line, "Destination Port for UDP: %d", &udp_dest_port);
        } else if (strstr(line, "Preprobing TCP Port:")) {
            sscanf(line, "Preprobing TCP Port: %d", &pre_server_port);
        } else if (strstr(line, "Postprobing TCP Port:")) {
            sscanf(line, "Postprobing TCP Port: %d", &post_server_port);
        } else if (strstr(line, "UDP Payload Size:")) {
 	    	sscanf(line, "UDP Payload Size: %d", &udp_payload_size);
        } else if (strstr(line, "Inter-Measurement Time:")) {
            sscanf(line, "Inter-Measurement Time: %d", &inter_measurement_time);
        } else if (strstr(line, "Number of UDP Packets:")) {
            sscanf(line, "Number of UDP Packets: %d", &num_udp_packets);
        }
    }
    fclose(config_file);

    char findings[256];

    probe(server_ip, udp_dest_port, inter_measurement_time,udp_payload_size, num_udp_packets, findings);

    postprobe(server_ip, post_server_port, findings);

    return 0;
}
