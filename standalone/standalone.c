#include "standalone.h"

#define THRESHOLD 100
#define BUFFER_SIZE 1024
#define PACKET_LEN 4096

struct config {
    char server_ip_address[16];
    
    int udp_source_port;
    int udp_destination_port;
    
    int tcp_head_syn_port;
    int tcp_tail_syn_port;
    
    int tcp_pre_probing_phase_port;
    int tcp_post_probing_phase_port;

    int udp_payload_size;
    int number_of_udp_packets;
    int ttl_for_udp_packets;
    
    int inter_measurement_time;
};

void clean_exit(int signal){
	printf("Received signal %d. Exiting...\n", signal);
	exit(EXIT_SUCCESS);
}

void read_config_file(const char *filename, struct config *config) {
    FILE *config_file = fopen(filename, "r");
    if (!config_file) {
        perror("Error opening config file");
        exit(EXIT_FAILURE);
    }

    char line[256];
    while (fgets(line, sizeof(line), config_file)) {
        if (strstr(line, "Server IP:")) {
            sscanf(line, "Server IP: %s", config->server_ip_address);
        } 
        else if (strstr(line, "Source Port for UDP:")) {
            sscanf(line, "Source Port for UDP: %d", &config->udp_source_port);
        }
        else if (strstr(line, "Destination Port for UDP:")) {
            sscanf(line, "Destination Port for UDP: %d", &config->udp_destination_port);
        }
        else if (strstr(line, "Preprobing TCP Port:")) {
            sscanf(line, "Preprobing TCP Port: %d", &config->tcp_pre_probing_phase_port);
        }
        else if (strstr(line, "Postprobing TCP Port:")) {
            sscanf(line, "Postprobing TCP Port: %d", &config->tcp_post_probing_phase_port);
        }
        else if (strstr(line, "UDP Payload Size:")) {
            sscanf(line, "UDP Payload Size: %d", &config->udp_payload_size);
        }
        else if (strstr(line, "Inter-Measurement Time:")) {
            sscanf(line, "Inter-Measurement Time: %d", &config->inter_measurement_time);
        }
        else if (strstr(line, "Number of UDP Packets:")) {
            sscanf(line, "Number of UDP Packets: %d", &config->number_of_udp_packets);
        }
        else if (strstr(line, "Destination Port for TCP Head SYN:")) {
            sscanf(line, "Destination Port for TCP Head SYN: %d", &config->tcp_head_syn_port);
        }
        else if (strstr(line, "Destination Port for TCP Tail SYN:")) {
            sscanf(line, "Destination Port for TCP Tail SYN: %d", &config->tcp_tail_syn_port);
        }
        else if (strstr(line, "TTL for UDP Packets:")) {
            sscanf(line, "TTL for UDP Packets: %d", &config->ttl_for_udp_packets);
        }
    }
    fclose(config_file);
}

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

char* get_local_ip(const char* interface_name) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char *host = NULL;

	// Gets the linked list containing all the network interfaces
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

	// Loops through to find the right interface
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
        	continue;
        }

        family = ifa->ifa_addr->sa_family;

        if (strcmp(ifa->ifa_name, interface_name) == 0) {
            if (family == AF_INET) {
            	// Get ip from the addr struct
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0) {
                    fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
                    exit(EXIT_FAILURE);
                }
                host = strdup(inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr));
                break;
            }
        }
    }

    freeifaddrs(ifaddr);
    return host;
}

unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    unsigned long checksum_value = 0;
    unsigned short *ptr;
    int tcplen = ntohs(iph->tot_len) - iph->ihl * 4;

	int mask = 0xFFFF;

    // Calculate pseudo-header checksum
    checksum_value += (iph->saddr >> 16) & mask;
    checksum_value += iph->saddr & mask;
    checksum_value += (iph->daddr >> 16) & mask;
    checksum_value += iph->daddr & mask;
    checksum_value += htons(IPPROTO_TCP);
    checksum_value += htons(tcplen);

    // Iterate through header to calculate checksum
    ptr = (unsigned short *)tcph;
    int i;

    for (i = tcplen; i > 1; i -= 2) {
        checksum_value += *ptr++;
    }
    
    if (i == 1) {
        checksum_value += *((unsigned char *)ptr);
    }

    // Convert 32 bit sum to 16 bits
    while (checksum_value >> 16)
        checksum_value = (checksum_value & mask) + (checksum_value >> 16);

	// Return in one's complement
    return (unsigned short)(~checksum_value);
}

unsigned short ip_checksum(struct iphdr *iph) {
    unsigned long checksum_value = 0;
    unsigned short *ptr;

    // IP header checksum
    ptr = (unsigned short *)iph;
    for (int i = iph->ihl * 2; i > 0; i--){
        checksum_value += *ptr++;
    }
    
    // Convert 32 bit sum to 16 bits
    while (checksum_value >> 16)
        checksum_value = (checksum_value & 0xFFFF) + (checksum_value >> 16);

	// Return in one's complement
    return (unsigned short)(~checksum_value);
}

void send_udp_packets_low(int udp_sock, struct config *config) {
	// Set up server and client addresses
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->udp_destination_port);
    server_addr.sin_addr.s_addr = inet_addr(config->server_ip_address);

    struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	client_addr.sin_port = htons(config->udp_source_port);

	int reuseaddr = 1;
	if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}

	if (bind(udp_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

    // Set don't fragment bit in IP header
    int DF = IP_PMTUDISC_DO;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0) {
        perror("Failed to set DF");
        exit(EXIT_FAILURE);
    }

	// Set ttl value in IP header
    int ttl = config->ttl_for_udp_packets;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    	perror("Failed to set TTL");
     	exit(EXIT_FAILURE);
    }

    // Set up payload
	char payload[config->udp_payload_size];
	fill_low_entropy_data(payload, config->udp_payload_size + 2);
	
    //Send low entropy UDP packets
    printf("Sending Low Entropy UDP packets...\n");
    for (int i = 0; i < config->number_of_udp_packets; i++) {
    	sleep(0.1);
        *(uint16_t*)payload = htons(i); // Set packet id
        sendto(udp_sock, payload, (config->udp_payload_size), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }
    printf("Low entropy UDP packets sent\n");
}

void send_udp_packets_high(int udp_sock, struct config *config) {
	// Set up server and client addresses
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(config->udp_destination_port);
    server_addr.sin_addr.s_addr = inet_addr(config->server_ip_address);

    struct sockaddr_in client_addr;
	memset(&client_addr, 0, sizeof(client_addr));
	client_addr.sin_family = AF_INET;
	client_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	client_addr.sin_port = htons(config->udp_source_port);

	int reuseaddr = 1;
	if (setsockopt(udp_sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(reuseaddr)) < 0) {
		perror("Invalid address");
		exit(EXIT_FAILURE);
	}

	if (bind(udp_sock, (struct sockaddr *)&client_addr, sizeof(client_addr)) < 0) {
		perror("Bind failed");
		exit(EXIT_FAILURE);
	}

    // Set the df flag in IP header
    int DF = IP_PMTUDISC_DO;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_MTU_DISCOVER, &DF, sizeof(DF)) < 0) {
        perror("Failed to set DF");
        exit(EXIT_FAILURE);
    }

	// Set the ttl in IP header
    int ttl = config->ttl_for_udp_packets;
    if (setsockopt(udp_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
    	perror("Failed to set TTL");
     	exit(EXIT_FAILURE);
    }

	// Set up payload
    char payload[config->udp_payload_size];
    fill_high_entropy_data(payload, config->udp_payload_size + 2);

    //Send high entropy UDP packets
    printf("Sending High Entropy UDP Packets...\n");
    for (int i = 0; i < config->number_of_udp_packets; i++) {
    	sleep(0.1);
        *(uint16_t*)payload = htons(i);
        sendto(udp_sock, payload, (config->udp_payload_size), 0, (struct sockaddr *)&server_addr, sizeof(server_addr));
    }
    printf("High entropy UDP packets sent\n");
}

void *send_packets(void *arg) {
    struct config *config = (struct config *)arg;

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Fill IP and TCP header for the SYN head packet
    struct sockaddr_in dest_addr;
    char packet[PACKET_LEN];
    struct iphdr *ip_header = (struct iphdr *)packet;
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct iphdr));
    
    ip_header->ihl = 5;
    ip_header->version = 4;
    ip_header->tos = 0;
    ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    ip_header->id = 0;
    ip_header->frag_off = 0;
    ip_header->ttl = 255;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->check = 0;
    ip_header->saddr = inet_addr(get_local_ip("enp0s8")); 
    ip_header->daddr = inet_addr(config->server_ip_address);
    
    tcp_header->source = htons(config->tcp_pre_probing_phase_port);
    tcp_header->dest = htons(config->tcp_head_syn_port);
    tcp_header->seq = 0;
    tcp_header->ack_seq = 0;
    tcp_header->doff = 5;
    tcp_header->fin = 0;
    tcp_header->syn = 1;
    tcp_header->rst = 0;
    tcp_header->psh = 0;
    tcp_header->ack = 0;
    tcp_header->urg = 0;
    tcp_header->window = htons(5840);
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;

    // Calculate TCP checksum
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Fill dest addr struct
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    // Send SYN head packet for low entropy
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Set up UDP socket
    int udp_sock_low = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock_low < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }

    // Send UDP packets
    sleep(1); 
    send_udp_packets_low(udp_sock_low, config);

    // Fill in TCP header for SYN tail packet
    tcp_header->source = htons(config->tcp_pre_probing_phase_port);
    tcp_header->dest = htons(config->tcp_tail_syn_port);

    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Send SYN tail packet for low entropy
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    close(udp_sock_low);

	sleep(config->inter_measurement_time);

	// Fill in TCP header for SYN tail packet
    tcp_header->source = htons(config->tcp_post_probing_phase_port);
    tcp_header->dest = htons(config->tcp_head_syn_port);

    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Send SYN head packet
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    // Set up UDP socket
    int udp_sock_high = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_sock_high < 0) {
        perror("UDP socket creation error");
        exit(EXIT_FAILURE);
    }
	// Send UDP packets
  	sleep(1); 
   	send_udp_packets_high(udp_sock_high, config);

	// Fill in TCP header for SYN tail packet
    tcp_header->source = htons(config->tcp_post_probing_phase_port);
    tcp_header->dest = htons(config->tcp_tail_syn_port);

    tcp_header->check = 0;
    tcp_header->check = tcp_checksum(ip_header, tcp_header);

    // Send SYN tail packet
    if (sendto(sockfd, packet, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("sendto");
        exit(EXIT_FAILURE);
    }

    close(sockfd);
    close(udp_sock_high);

    return NULL;
}

void *receive_rst_packets() {
	clock_t start_time_low, start_time_high, end_time_low, end_time_high;
    double low_entropy_time, high_entropy_time;
    
    int recvsock;
    if ((recvsock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Set timeout for receiving RST packets
    struct timeval timeout;
    timeout.tv_sec = 20;
    timeout.tv_usec = 0;
    if (setsockopt(recvsock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout)) < 0) {
    	perror("setsockopt failed");
    	exit(EXIT_FAILURE);
    }

    // Recv RST for head packet for low entropy train
    char recv_buffer[PACKET_LEN];
    int recv_len;
    
    for (;;) {
        recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);

        if (recv_len < 0) {
            printf("Failed to detect due to insufficient information\n");
            exit(EXIT_FAILURE);
        }
        
        struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
        struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));

        if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
        	start_time_low = clock();
            printf("Low entropy train: RST for Head packet received.\n");
            break;
        }
    }
    
    if (recv_len < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }
    
    // Recv RST for tail packet for low entropy train
    for (;;) {
		recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);
		
		if (recv_len < 0) {
           printf("Failed to detect due to insufficient information\n");
           exit(EXIT_FAILURE);
       }
       
		struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
		struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));

		if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
			end_time_low = clock();
			printf("Low entropy train: RST for Tail packet received.\n");
			break;
		}
	}
	
	if (recv_len < 0) {
		perror("recvfrom");
		exit(EXIT_FAILURE);
	}

	// Calculate time between head and tail
	low_entropy_time = ((((double)end_time_low) - ((double)start_time_low)) / ((double)CLOCKS_PER_SEC)) * 1000;
	printf("Low Entropy Time: %f\n", low_entropy_time);
	
	printf("Sleeping for inter measurement time\n");
	
    // Recv RST for head packet for high entropy train
    for (;;) {
        recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);

        if (recv_len < 0) {
            printf("Failed to detect due to insufficient information\n");
            exit(EXIT_FAILURE);
        }
        
        struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
        struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));

        if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
        	start_time_high = clock();
            printf("High entropy train: RST for Head packet received.\n");
            break;
        }
    }
    
    if (recv_len < 0) {
        perror("recvfrom");
        exit(EXIT_FAILURE);
    }
    
    // Recv RST for tail packet for high entropy train
    for (;;) {
		recv_len = recvfrom(recvsock, recv_buffer, PACKET_LEN, 0, NULL, NULL);

		if (recv_len < 0) {
            // Failed to receive RST packet within timeout
            printf("Failed to detect due to insufficient information\n");
            exit(EXIT_FAILURE);
        }
        
		struct iphdr *recv_ip_header = (struct iphdr *)recv_buffer;
		struct tcphdr *recv_tcp_header = (struct tcphdr *)(recv_buffer + sizeof(struct iphdr));

		if (recv_ip_header->protocol == IPPROTO_TCP && recv_tcp_header->rst) {
			end_time_high = clock();
			printf("High entropy train: RST for Tail packet received.\n");
			break;
		}
	}
	
	if (recv_len < 0) {
		perror("recvfrom");
		exit(EXIT_FAILURE);
	}

	// Calculate time between head and tail
	high_entropy_time = ((((double)end_time_high) - ((double)start_time_high)) / ((double)CLOCKS_PER_SEC)) * 1000;
    printf("High Entropy Time: %f\n", high_entropy_time);

    // Calculate for compression
    if ((high_entropy_time - low_entropy_time) > THRESHOLD) {
        printf("Compression detected!\n");
    } else {
        printf("No compression detected!\n");
    }

    close(recvsock);
    
    return NULL;
}

int main() {
	// Set signals to handle abrupt exits
	signal(SIGTERM, clean_exit);
	signal(SIGINT, clean_exit);

	pthread_t send_thread, receive_thread;

	// Read config file into struct
    struct config config;
	read_config_file("config.json", &config);

    // Create send_packets thread
    if (pthread_create(&send_thread, NULL, send_packets, &config) != 0) {
        perror("pthread_create for send_packets");
        exit(EXIT_FAILURE);
    }

    // Create receive_rst_packets thread
    if (pthread_create(&receive_thread, NULL, receive_rst_packets, NULL) != 0) {
        perror("pthread_create for receive_rst_packets");
        exit(EXIT_FAILURE);
    }

    pthread_join(send_thread, NULL);
    pthread_join(receive_thread, NULL);
	
    return 0;
}
