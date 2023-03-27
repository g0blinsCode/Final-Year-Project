#include "csrf_detector.h"
#include "headers.h"
#include "xss_detector.h"
#include "rate_limiting.h"
#include "malicious_file_execution.h"
#include "clickjacking.h"
#include "sql_detector.h"
#include "remote_code_execution.h"
#include "ssrf.h"
vector <string> rce_payloads;
vector <string> xss_payloads;
vector <string> ssrf_payloads;

/********************************* No of packet for displaying struct here *********************************************/
typedef struct
{
    int tcp_count;
    int udp_count;
    int http_count;
    int https_count;
    int icmp_count;
    int unknow_count;
    int ipv6_count;
} packet_counts;

/********************************* No of packet for displaying struct ending *********************************************/

//******************************** Printing Function Starting********************************************//
void printPackets(packet_counts count)
{

    printf("\n no of Tcp packets are == %d", count.tcp_count);
    printf("\n no of UDP packets are == %d", count.udp_count);
    printf("\n no of HTTP packets are == %d", count.http_count);
    printf("\n no of HTTPS packets are == %d", count.https_count);
    printf("\n no of ICMP packets are == %d", count.icmp_count);
    printf("\n no of IPV6 packets are == %d", count.ipv6_count);
    printf("\n no of Unknown packets are == %d", count.unknow_count);


    // alarm(60);
    // sleep(1);
    // exit(0); // here
}

//******************************** Printing Function Ending ********************************************//

/********************************* Payload of packet struct here *********************************************/

void show_payload(char *payload, int length , vector<string> sql_payloads , vector<string> rce_payloads, vector<string> xss_payloads , char* source_ip , char *destination_ip)
{
    // Save the payload to a temporary file
    // printf("Testing\n");

    FILE *fp = fopen("/tmp/payload.bin", "w");
    fwrite(payload, 1, length, fp);
    fclose(fp);

    // Use the hexdump utility to convert the payload to a human-readable format
    system("hexdump -C /tmp/payload.bin");

    XSS_Detector(payload , source_ip , destination_ip);
    // CSRF_Detector(payload);
    // Malicious_File_Execution_Detector(payload);
    // Clickjacking_Detector(payload);
    // SQL_Detector(payload);
    // RCE_Detector(payload);
}

/********************************* Payload of packet struct here *********************************************/

//**************************** DRIVER FUNCTION *******************************************************//

int main(int argc, char *argv[])
{
    printf("\nMain Here");

    // Check the number of command-line arguments
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <Network Interface>. \n", argv[0]);
        exit(1);
    }
    //  Declaring packet counts variable for packetCounter
    packet_counts packetCounter = {.tcp_count = 0, .udp_count = 0, .http_count = 0, .https_count = 0, .icmp_count = 0 , .unknow_count=0, .ipv6_count=0 }; // for counting packets

    // Open a raw socket
    //PF => Packet oriented Communication , raw for network layer , eth => ethhernet interface
    int sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd == -1)
    {
        perror("socket");
        exit(1);
    }

    vector<string> sql_payloads;
     ifstream file("sql.txt");
    string line;
    while (getline(file, line)) {
    sql_payloads.push_back(line);
  }
  file.close();
    line=" ";
  file.open("ssrf.txt");
    while (getline(file, line)) {
    ssrf_payloads.push_back(line);
  }
  file.close();

    file.open("rce.txt");
    line.clear();
    while (getline(file, line)) {
    rce_payloads.push_back(line);
  }
  file.close();
    
    //Testing
    file.open("xss_payload.txt");
    line.clear();
    while (getline(file, line)) {
  }
  file.close();
  
    //Testing
  
  file.open("xss_payload.txt");
    line.clear();
    while (getline(file, line)) {
    xss_payloads.push_back(line);
  }
  file.close();


    file.open("xss_payload.txt");
    line.clear();
    while (getline(file, line)) {
    xss_payloads.push_back(line);
  }
  file.close();


  // Sort the payloads
  sort(sql_payloads.begin(), sql_payloads.end());
   sort(rce_payloads.begin() , rce_payloads.end());
   sort(ssrf_payloads.begin() , ssrf_payloads.end());
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
        // cout<<"\nHello123456";
        // measure the elapsed time
        auto end = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        printf("Elapsed time is == %d ", elapsed.count());

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
        //Here
        // Call the show_payload function
        struct iphdr *ip = (struct iphdr *)buf;
        

        // show_payload(buf + 14, bytes_read - 14, sql_payloads, rce_payloads, xss_payloads);
        cout<<"\n Check the ethertype to determine the type of the packet\n";
        // cout<<"(buf[12] << 8) | buf[13] :::"<<((buf[12] << 8) | buf[13]);
        uint16_t ethertype = (buf[12] << 8) | buf[13];
        if (ethertype == 0x0800) //IPv4 packets (0x0800)
        {
            // IPv4 packet
            printf("IPv 4 packet\n");

            // Parse the IP header
            struct ip *ip_hdr = (struct ip *)(buf + 14);
            source_ip = inet_ntoa(ip_hdr->ip_src);
            printf("Source IP: %s\n", source_ip);
            destination_ip = inet_ntoa(ip_hdr->ip_dst);
            printf("Destination IP: %s\n", destination_ip);
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
                show_payload(buf + 14 + (ip_hdr->ip_hl << 2) + sizeof(struct icmp6_hdr), icmp_payload_length , sql_payloads , rce_payloads , xss_payloads , source_ip , destination_ip);

                packetCounter.icmp_count++;
            }

            //*************** LOGIC FOR HTTP AND HTTPS PACKETS *************************************//
            if (ip_hdr->ip_p == IPPROTO_TCP)
            {
                // TCP packet
                // Parse the TCP header
                struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + 14 + (ip_hdr->ip_hl << 2));
                int src_port = ntohs(tcp_hdr->source);
                source_port = src_port;
                int dst_port = ntohs(tcp_hdr->dest);
                destination_port = dst_port;

                   // Calculate the length of the TCP payload
                int tcp_payload_length = bytes_read - (14 + (ip_hdr->ip_hl << 2) + (tcp_hdr->th_off << 2));
    
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
                show_payload(buf + 14 + (ip_hdr->ip_hl << 2) + (tcp_hdr->doff << 2), tcp_payload_length, sql_payloads, rce_payloads, xss_payloads, source_ip , destination_ip);

                // check_rate_limiting(inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst), src_port, dst_port);

            }
            /************************************* ENDING OF HTTPS PACKETS ********************************************8*/

            // Check the protocol to determine the type of the payload
            if (ip_hdr->ip_p == 6)//TCP (6), UDP (17), ICMP (1)
            {
                // TCP packet
                printf("TCP packet\n");

                // Parse the TCP header
                struct tcphdr *tcp_hdr = (struct tcphdr *)(buf + 14 + (ip_hdr->ip_hl * 4));

                source_port = ntohs(tcp_hdr->source);
                destination_port = ntohs(tcp_hdr->dest);
                printf("Source port: %d\n", source_port);
                printf("Destination port: %d\n", destination_port);

                // Calculate the length of the TCP payload
                int tcp_payload_length = bytes_read - (14 + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4));

                // Show the payload
                show_payload(buf + 14 + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4), tcp_payload_length , sql_payloads , rce_payloads , xss_payloads, source_ip , destination_ip);

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

                source_port = ntohs(udp_hdr->source);
                destination_port = ntohs(udp_hdr->dest);
                printf("Source port: %d\n", source_port);
                printf("Destination port: %d\n", destination_port);

                show_payload(buf + 14 + (ip_hdr->ip_hl * 4) + sizeof(struct udphdr), udp_payload_length, sql_payloads , rce_payloads , xss_payloads, source_ip , destination_ip);
                packetCounter.udp_count++;

                // check_rate_limiting(inet_ntoa(ip_hdr->ip_src), inet_ntoa(ip_hdr->ip_dst), ntohs(udp_hdr->source), ntohs(udp_hdr->dest));
            }
        }//clossing of IPv4 logic/IF
        else if (ethertype == 0x86dd)
        {
            // IPv6 packet
            // cout<<"\nHello1";
            printf("IPv6 packet\n");
            // Parse the IPv6 header
            struct ip6_hdr *ip6_hdr = (struct ip6_hdr *)(buf + 14);
            // Access the payload length field
            int payload_length = ntohs(ip6_hdr->ip6_plen);
            // Display the payload
            packetCounter.ipv6_count++;
            show_payload(buf + 14 + sizeof(struct ip6_hdr), payload_length, sql_payloads, rce_payloads, xss_payloads, source_ip , destination_ip);
        }
        else
        {
                // Unknown packet
                printf("Unknown packet\n");
                packetCounter.unknow_count++;
        }

        // Print a separator between packets
        printf("\n");

        // FILE *fp = fopen("ips.txt", "a");

        // fprintf(fp, "Source IP: %s\nDestination IP: %s\nSource Port: %d\nDestination Port: %d\n", source_ip, destination_ip, source_port, destination_port);

        // Close the file
        // fclose(fp);
    }///closing of while

    return 0;
}