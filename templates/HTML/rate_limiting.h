#include "csrf_detector.h"
#include "headers.h"
#include "xss_detector.h"


#define MAX_CONNECTION_ATTEMPTS 1000
#define RATE_LIMITING_THRESHOLD 100
#define RATE_LIMITING_WINDOW 60

#define IPTABLES_PATH "/sbin/iptables"

char *source_ip, *destination_ip;
int source_port, destination_port;

/*  **************************** Rate Limiting Attack Start ***************************************************/
int block_connection(char *src_ip, char *dst_ip, int src_port, int dst_port, char *protocol)
{
    char command[256];
    snprintf(command, 256, "%s -A INPUT -s %s -d %s --sport %d --dport %d -p %s -j DROP",
             IPTABLES_PATH, src_ip, dst_ip, src_port, dst_port, protocol);
    return system(command);
}

typedef struct connection_attempt
{
    char src_ip[16];
    char dst_ip[16];
    int src_port;
    int dst_port;
    time_t timestamp;
} connection_attempt;

connection_attempt connection_attempts[MAX_CONNECTION_ATTEMPTS];
int num_connection_attempts = 0;

void add_connection_attempt(char *src_ip, char *dst_ip, int src_port, int dst_port)
{
    // Add a new connection attempt to the data structure
    strncpy(connection_attempts[num_connection_attempts].src_ip, src_ip, 16);
    strncpy(connection_attempts[num_connection_attempts].dst_ip, dst_ip, 16);
    connection_attempts[num_connection_attempts].src_port = src_port;
    connection_attempts[num_connection_attempts].dst_port = dst_port;
    connection_attempts[num_connection_attempts].timestamp = time(NULL);
    num_connection_attempts++;
}

int check_rate_limiting(char *src_ip, char *dst_ip, int src_port, int dst_port)
{
    // Check the rate limiting for a given connection attempt
    int num_attempts = 0;
    time_t current_time = time(NULL);
    for (int i = 0; i < num_connection_attempts; i++)
    {
        // Check if the connection attempt matches the source and destination IP and port
        if (strncmp(connection_attempts[i].src_ip, src_ip, 16) == 0 &&
            strncmp(connection_attempts[i].dst_ip, dst_ip, 16) == 0 &&
            connection_attempts[i].src_port == src_port &&
            connection_attempts[i].dst_port == dst_port)
        {
            // Check if the connection attempt is within the rate limiting window
            if (current_time - connection_attempts[i].timestamp < RATE_LIMITING_WINDOW)
            {
                num_attempts++;
            }
        }
    }
    if (num_attempts > RATE_LIMITING_THRESHOLD)
    {

        block_connection(src_ip, dst_ip, 80, 80, "TCP");

        return 0;
    }
}

/* **************************************** Rate Limiting Attack ENding *****************************************************/
