#include "fill_packet.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>

#define	IP_DF 0x4000		//不分段flag

extern pid_t pid;
extern u16 icmp_req;

//填充 IP封包的header
void 
fill_iphdr ( struct ip *ip_hdr , const char* dst_ip ,char *sourceIP ,int totalLen)
{
	ip_hdr->ip_v = 4 ;		//版本為 IPv4
	ip_hdr->ip_hl = 5;		//header長度 	
	ip_hdr->ip_tos = 0;		//服務類型
	ip_hdr->ip_len = totalLen;  //IP 封包的總長度
	ip_hdr->ip_id = 0;	//識別碼
	ip_hdr->ip_off = htons(IP_DF); //不分段flag
	ip_hdr->ip_ttl = 1;		//TTL		
	ip_hdr->ip_p = IPPROTO_ICMP;			// ICMP
	
	inet_aton(dst_ip, &(ip_hdr->ip_dst));	//將字串格式的目的 IP 位址轉換為二進制形式
	inet_aton(sourceIP, &(ip_hdr->ip_src));	//將字串格式的來源 IP 位址轉換為二進制形式
}

//填充 ICMP封包的header
void
fill_icmphdr (struct icmp *icmp_hdr,char *strData)
{	
	
	icmp_hdr->icmp_type = ICMP_ECHO;	//封包類型為 ICMP 回應
	icmp_hdr->icmp_code = 0;	//ICMP code
	icmp_hdr->icmp_cksum = 0;	//checksum
	icmp_hdr->icmp_id = htons(pid); //process ID
	icmp_hdr->icmp_seq = htons(icmp_req);	//seq
	sprintf(icmp_hdr->icmp_data,"%s",strData);	//資料複製到 icmp_data
	icmp_hdr->icmp_cksum =fill_cksum(icmp_hdr);	//checksum
}

//計算 ICMP 封包的checksum,計算校驗和時，通常將資料分割成 16 位元的部分，再將這些部分加總起來
unsigned short
fill_cksum(struct icmp *icmp_packet)
{
	unsigned long sum = 0;  
    unsigned short *buffer = (unsigned short*) icmp_packet; //buffer 將 icmp_packet 視為一系列 16 位元數值的陣列
    int len = sizeof(struct icmp); // ICMP 封包結構的大小(位元組)
	while(len > 1){ 
    	sum += *buffer;
    	buffer++; //移動到下一個 16 位元(2 個位元組)
        len -= 2; //剩餘位元組減少 2
    }

    if(len == 1){       //最後一個位元組的校驗和計算
      	sum += *(unsigned char *)buffer; 
    }
    
    sum = (sum & 0xffff) + (sum >> 16); //確保校驗和值在 16 位元的範圍內

    return ~sum; //和的反相與接收端進行校驗
}