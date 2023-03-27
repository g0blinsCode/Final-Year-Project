#include "csrf_detector.h"
#include "headers.h"
#include "xss_detector.h"

//******************************** Printing Function Starting********************************************//
int printPackets(packet_counts count)
{

    printf("\n no of Tcp packets are == %d", count.tcp_count);
    printf("\n no of UDP packets are == %d", count.udp_count);
    printf("\n no of HTTP packets are == %d", count.http_count);
    printf("\n no of HTTPS packets are == %d", count.https_count);
    printf("\n no of ICMP packets are == %d", count.icmp_count);
    // alarm(60);
    // sleep(1);
    // exit(0); // here
}