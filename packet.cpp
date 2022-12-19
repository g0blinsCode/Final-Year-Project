#include <chrono>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/if_packet.h>
#include <signal.h>
#include <net/if.h>
#include <iostream>

#define MAX_CONNECTION_ATTEMPTS 1000
#define RATE_LIMITING_THRESHOLD 100
#define RATE_LIMITING_WINDOW 60

#define IPTABLES_PATH "/sbin/iptables"



/*  **************************** Rate Limiting Attack Start ***************************************************/
int block_connection(char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol) {
  char command[256];
  snprintf(command, 256, "%s -A INPUT -s %s -d %s --sport %d --dport %d -p %s -j DROP",
           IPTABLES_PATH, src_ip, dst_ip, src_port, dst_port, protocol);
  return system(command);
}

typedef struct connection_attempt {
  char src_ip[16];
  char dst_ip[16];
  int src_port;
  int dst_port;
  time_t timestamp;
} connection_attempt;

connection_attempt connection_attempts[MAX_CONNECTION_ATTEMPTS];
int num_connection_attempts = 0;

void add_connection_attempt(char *src_ip, char *dst_ip, int src_port, int dst_port) {
  // Add a new connection attempt to the data structure
  strncpy(connection_attempts[num_connection_attempts].src_ip, src_ip, 16);
  strncpy(connection_attempts[num_connection_attempts].dst_ip, dst_ip, 16);
  connection_attempts[num_connection_attempts].src_port = src_port;
  connection_attempts[num_connection_attempts].dst_port = dst_port;
  connection_attempts[num_connection_attempts].timestamp = time(NULL);
  num_connection_attempts++;
}

int check_rate_limiting(char *src_ip, char *dst_ip, int src_port, int dst_port) {
  // Check the rate limiting for a given connection attempt
  int num_attempts = 0;
  time_t current_time = time(NULL);
  for (int i = 0; i < num_connection_attempts; i++) {
    // Check if the connection attempt matches the source and destination IP and port
    if (strncmp(connection_attempts[i].src_ip, src_ip, 16) == 0 &&
        strncmp(connection_attempts[i].dst_ip, dst_ip, 16) == 0 &&
        connection_attempts[i].src_port == src_port &&
        connection_attempts[i].dst_port == dst_port) {
      // Check if the connection attempt is within the rate limiting window
      if (current_time - connection_attempts[i].timestamp < RATE_LIMITING_WINDOW) {
        num_attempts++;
      }
    }
  }
  if (num_attempts > RATE_LIMITING_THRESHOLD) {

        block_connection(src_ip, dst_ip, 80, 80, "TCP");

       return 0;
  }
}

/* **************************************** Rate Limiting Attack ENding *****************************************************/

/********************* CSRF Detection ***********************************/
void CSRF_Detector(char *payload)
{
    // Check for the presence of a unique CSRF token in the payload
    if (strstr(payload, "csrf_token=") == NULL)
    {
        printf("WARNING: Possible CSRF attack detected!and payload is == %s ",payload,"\n");
        // exit(0);
    }
}
/* ****************** CSRF Detection Ending *******************************/ 
void XSS_Detector(char *payload)
{
    // Check for the presence of XSS payloads in the packet payload

    /*
        HTML encoding: "&lt;script&gt;"
    URL encoding: "%3Cscript%3E"
    Base64 encoding: "PHNjcmlwdD4="
    Hex encoding: "3c7363726970743e"
    ASCII encoding: "\x3c\x73\x63\x72\x69\x70\x74\x3e"*/

    if (strstr(payload, "<script>") != NULL || strstr(payload, "</script>") != NULL ||
        strstr(payload, "&lt;script&gt;") != NULL || strstr(payload, "&lt;/script&gt;") != NULL ||
        strstr(payload, "%3Cscript%3E") != NULL || strstr(payload, "%3C/script%3E") != NULL ||
        strstr(payload, "&lt;script&gt;") ||
        strstr(payload, "PHNjcmlwdD4=") != NULL || strstr(payload, "PHNjcmlwdD4K") != NULL ||
        strstr(payload, "3c7363726970743e") != NULL || strstr(payload, "3c2f7363726970743e") != NULL ||
        strstr(payload, "\x3c\x73\x63\x72\x69\x70\x74\x3e") != NULL ||
        strstr(payload, "\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e") != NULL)
    {
        printf("WARNING: XSS payload detected! and payload is == %s",payload,"\n");
        exit(0);
    }
}

/********************************* No of packet for displaying struct here *********************************************/
typedef struct
{
    int tcp_count;
    int udp_count;
    int http_count;
    int https_count;
    int icmp_count;
} packet_counts;

/********************************* No of packet for displaying struct ending *********************************************/

//******************************** Printing Function Starting********************************************//
int printPackets(packet_counts count)
{

    printf("\n no of Tcp packets are == %d", count.tcp_count);
    printf("\n no of UDP packets are == %d", count.udp_count);
    printf("\n no of HTTP packets are == %d", count.http_count);
    printf("\n no of HTTPS packets are == %d", count.https_count);
    printf("\n no of ICMP packets are == %d", count.icmp_count);
    // alarm(60);
    sleep(5);
    // exit(0); // here
}

//******************************** Printing Function Ending ********************************************//

/********************************* Payload of packet struct here *********************************************/
void show_payload(char *payload, int length)
{
    // Save the payload to a temporary file
    FILE *fp = fopen("/tmp/payload.bin", "w");
    fwrite(payload, 1, length, fp);
    fclose(fp);

    // Use the hexdump utility to convert the payload to a human-readable format
    system("hexdump -C /tmp/payload.bin");

    XSS_Detector(payload);
    CSRF_Detector(payload);
}

/********************************* Payload of packet struct here *********************************************/

//**************************** DRIVER FUNCTION *******************************************************//

int main(int argc, char *argv[])
{

    // Check the number of command-line arguments
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(1);
    }

    packet_counts packetCounter = {.tcp_count = 0, .udp_count = 0, .http_count = 0, .https_count = 0 , .icmp_count = 0}; // for counting packets

    // Open a raw socket
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)
    {
        perror("socket");
        exit(1);
    }

    // Set up the link-layer address structure
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(argv[1]);

    // Bind the socket to the specified interface
    if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == -1)
    {
        perror("bind");
        exit(1);
    }
    
    static double elapsedTime;

          // get the current time
    auto start = std::chrono::steady_clock::now();

    while (1)
    {

// measure the elapsed time
  auto end = std::chrono::steady_clock::now();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

  printf( "Elapsed time is == %d " , elapsed.count() );

        // if the elapsed time is greater than or equal to 100 seconds
        if (elapsed.count() >= 40000.0) // Summary after every 1 minute
        {
            // call the function
            printPackets(packetCounter);

            // reset the start time to the current time
           start = std::chrono::steady_clock::now();
        }
        // Read a packet from the network
        char buf[2048];
        int bytes_read = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
        if (bytes_read == -1)
        {
            perror("recvfrom");
            exit(1);
        }

        // Print some basic information about the packet
        printf("Packet: %d bytes\n", bytes_read);
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]);
        printf("Ethertype: %02x%02x\n", buf[12], buf[13]);

        // Check the ethertype to determine the type of the packet
        uint16_t ethertype = (buf[12] << 8) | buf[13];
        if (ethertype == 0x0800)
        {
            // IPv4 packet
            printf("IPv 4 packet\n");

            // Parse the IP header
            struct ip *ip_hdr = (struct ip *)(buf + 14);
            printf("Source IP: %s\n", inet_ntoa(ip_hdr->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_hdr->ip_dst));
            printf("IP protocol: %d\n", ip_hdr->ip_p);

            /************************************ Logic for ICMP Packets ************************************/
            if (ip_hdr->ip_p == IPPROTO_ICMPV6)
            {
                // ICMPv6 packet
                printf("ICMPv6 packet\n");
                // Parse the ICMPv6 header
                struct icmp6_hdr *icmp6_hdr = (struct icmp6_hdr *)(buf + 14 + (ip_hdr->ip_hl << 2));
                // Access the type and code fields
                printf("ICMPv6 type: %d\n", icmp6_hdr->icmp6_type);
                printf("ICMPv6 code: %d\n", icmp6_hdr->icmp6_code);
                // Print the checksum field
                printf("ICMPv6 checksum: 0x%04x\n", ntohs(icmp6_hdr->icmp6_cksum));
                // Print the identifier field
                printf("ICMPv6 identifier: %d\n", ntohs(icmp6_hdr->icmp6_id));

                // Calculate the length of the icmp payload
                int icmp_payload_length = bytes_read - (14 + (ip_hdr->ip_hl << 2) + sizeof(struct icmp6_hdr));
                // Display the ICMPv6 payload
                show_payload(buf + 14 + (ip_hdr->ip_hl << 2) + sizeof(struct icmp6_hdr), icmp_payload_length);

                packetCounter.icmp_count++;

                
            }

            //*************** LOGIC FOR HTTP AND HTTPS PACKETS *************************************//
            if (ip_hdr->ip_p == IPPROTO_TCP)
            {
                // TCP packet
                // Parse the TCP header
                struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + 14 + (ip_hdr->ip_hl << 2));
                int src_port = ntohs(tcp_hdr->source);
                int dst_port = ntohs(tcp_hdr->dest);
                // Check if the packet is an HTTP or HTTPS packet
                if (src_port == 80 || dst_port == 80)
                {
                    printf("HTTP packet\n");
                    packetCounter.http_count++;
                }
                else if (src_port == 443 || dst_port == 443)
                {
                    printf("HTTPS packet\n");
                    packetCounter.https_count++;
                }


            check_rate_limiting(inet_ntoa(ip_hdr->ip_src) ,inet_ntoa(ip_hdr->ip_dst) , src_port , dst_port);


            }
            /************************************* ENDING OF HTTPS PACKETS ********************************************8*/

            // Check the protocol to determine the type of the payload
            if (ip_hdr->ip_p == 6)
            {
                // TCP packet
                printf("TCP packet\n");

                // Parse the TCP header
                struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + 14 + (ip_hdr->ip_hl * 4));

                printf("Source port: %d\n", ntohs(tcp_hdr->source));
                printf("Destination port: %d\n", ntohs(tcp_hdr->dest));

                // Calculate the length of the TCP payload
                int tcp_payload_length = bytes_read - (14 + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4));

                // Show the payload
                show_payload(buf + 14 + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4), tcp_payload_length);

                packetCounter.tcp_count++;
            }

            else if (ip_hdr->ip_p == 17)
            {
                // UDP packet
                printf("UDP packet\n");

                // Parse the UDP header
                struct udphdr *udp_hdr = (struct udphdr *)(buf + 14 + (ip_hdr->ip_hl * 4));

                // Calculate the length of the UDP payload
                int udp_payload_length = ntohs(udp_hdr->len) - sizeof(struct udphdr);
                printf("Source port: %d\n", ntohs(udp_hdr->source));
                printf("Destination port: %d\n", ntohs(udp_hdr->dest));

                show_payload(buf + 14 + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr), udp_payload_length);
                packetCounter.udp_count++;


            check_rate_limiting(inet_ntoa(ip_hdr->ip_src) ,inet_ntoa(ip_hdr->ip_dst) , ntohs(udp_hdr->source) , ntohs(udp_hdr->dest));

            }
        }
        else if (ethertype == 0x86dd)
        {
            // IPv6 packet
            printf("IPv6 packet\n");
        }
        else
        {
            // Unknown packet
            printf("Unknown packet\n");
        }

        // Print a separator between packets
        printf("\n");
    }

    return 0;
}