#ifndef __FILLPACKET__H_
#define __FILLPACKET__H_

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

typedef char u8;
typedef unsigned short u16;

#define DEFAULT_SEND_COUNT 4
#define DEFAULT_TIMEOUT 1500

extern pid_t pid;
extern u16 icmp_req;

typedef struct
{
	struct ip ip_hdr;
	struct icmp icmp_hdr;
} myicmp ;

void 
fill_iphdr ( struct ip *ip_hdr, const char* dst_ip,char *sourceIP ,int totalLen);

void
fill_icmphdr (struct icmp *icmp_hdr,char *strData);

unsigned short
fill_cksum(struct icmp *icmp_packet);
 
#endif
 