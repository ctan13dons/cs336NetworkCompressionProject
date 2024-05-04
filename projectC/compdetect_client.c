#include "compdetect_client.h"

void fill_high_entropy_data(char *data, int len) {
    FILE *f = fopen("/dev/urandom", "r");
    if (f == NULL) {
        perror("Error opening /dev/urandom");
        exit(EXIT_FAILURE);
    }
    for (int i = 0; i < len; i++) {
        data[i] = getc(f);
    }
    fclose(f);
}

void fill_low_entropy_data(char *data, int len) {
    for (int i = 0; i < len; i++) {
        data[i] = '0';
    }
}

void preprobe(const char *server_ip, int server_port, const char *json_data) {
    // Create socket and connect to the server
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Send the JSON data to the server
    ssize_t bytes_sent = send(sock_fd, json_data, strlen(json_data), 0);
    if (bytes_sent < 0) {
        perror("send");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    printf("JSON data sent successfully\n");

    close(sock_fd);
}

void postprobe(const char *server_ip, int server_port) {
    sleep(2); 

    // Connect to the server
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }

    // Receive findings message from the server
    char findings[256];
    ssize_t bytes_recv = recv(sock_fd, findings, sizeof(findings) - 1, 0);
    if (bytes_recv < 0) {
        perror("recv");
        close(sock_fd);
        exit(EXIT_FAILURE);
    }
    findings[bytes_recv] = '\0';
    printf("Findings from server: %s\n", findings);

    close(sock_fd);
}

void probe(const char *server_ip, int server_port, int client_port, int num_udp_packets, int udp_payload_size, int inter_measurement_time) {
    sleep(2);

    // Create UDP socket
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Define client and server addresses
    struct sockaddr_in client_addr, server_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = htons(client_port);
    client_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // Bind udp socket to client address
    if (bind(udp_socket, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
        perror("bind");
        close(udp_socket);
        exit(EXIT_FAILURE);
    }

    char payload[num_udp_packets + 2]; // +2 for ip and udp header info

    //Set don't fragment bit
   	int DF = IP_PMTUDISC_DO;
    if (setsockopt(udp_socket, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0) {
        perror("Failed to set DF flag");
        exit(EXIT_FAILURE);
    }

   // Send low entropy UDP packets
    fill_low_entropy_data(payload, udp_payload_size + 2);

    printf("Sending Low Entropy Data...\n");
    for (int i = 0; i <= num_udp_packets; i++) {
    	sleep(0.1);
    	*(uint16_t *)payload = htons(i); // Set packet id
        sendto(udp_socket, payload, udp_payload_size + 2, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }
    printf("Low Entropy Sent!\n");

    // Wait for Inter-Measurement Time
    printf("Sleeping for %d...\n", inter_measurement_time);
    sleep(inter_measurement_time);

    // Send high entropy UDP packets
    fill_high_entropy_data(payload, udp_payload_size + 2);

    printf("Sending High Entropy Data...\n");
    for (int i = 0; i <= num_udp_packets; i++) {
    	sleep(0.1);
        *(uint16_t *)payload = htons(i); // Set packet id
        sendto(udp_socket, payload, udp_payload_size + 2, 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }
    printf("High Entropy Sent!\n");

    close(udp_socket);
}

int main() {
    // Read the config file
    FILE *config_file = fopen("config.json", "r");
    if (!config_file) {
        perror("Error opening config file");
        return EXIT_FAILURE;
    }

    char server_ip[256] = "";
    int pre_server_port = 0;
    int post_server_port = 0;
    int udp_source_port = 0;
    int udp_dest_port = 0;
    int inter_measurement_time = 0;
    int udp_payload_size = 0;
    int num_udp_packets = 0;
    
    char json_data[1024];

    char line[256];

    while (fgets(line, sizeof(line), config_file)) {
        if (strstr(line, "Server IP:")) {
            sscanf(line, "Server IP: %s", server_ip);
        } 
        else if (strstr(line, "Preprobing TCP Port:")) {
            sscanf(line, "Preprobing TCP Port: %d", &pre_server_port);
        }
        else if (strstr(line, "Postprobing TCP Port:")) {
            sscanf(line, "Postprobing TCP Port: %d", &post_server_port);
        }
        else if (strstr(line, "Inter-Measurement Time:")) {
            sscanf(line, "Inter-Measurement Time: %d", &inter_measurement_time);
        }
        else if (strstr(line, "Source Port for UDP:")) {
            sscanf(line, "Source Port for UDP: %d", &udp_source_port);
        }
        else if (strstr(line, "Destination Port for UDP:")) {
            sscanf(line, "Destination Port for UDP: %d", &udp_dest_port);
        }
        else if (strstr(line, "UDP Payload Size:")) {
            sscanf(line, "UDP Payload Size: %d", &udp_payload_size);
        }
        else if (strstr(line, "Number of UDP Packets:")) {
            sscanf(line, "Number of UDP Packets: %d", &num_udp_packets);
        }
    }
    fclose(config_file);

    // Read the JSON data from the file
    FILE *json_file = fopen("config.json", "r");
    if (!json_file) {
        perror("Error opening JSON file");
        return EXIT_FAILURE;
    }
    
    size_t json_data_len = fread(json_data, 1, sizeof(json_data) - 1, json_file);
    fclose(json_file);
    json_data[json_data_len] = '\0';

    // Run the program
    preprobe(server_ip, pre_server_port, json_data);
    probe(server_ip, udp_dest_port, udp_source_port, num_udp_packets, udp_payload_size, inter_measurement_time);
    postprobe(server_ip, post_server_port);

    return 0;
}
