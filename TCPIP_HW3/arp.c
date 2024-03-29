#include "arp.h"

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <linux/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>



//You can fill the following functions or add other functions if needed. If not, you needn't write anything in them.  
void set_hard_type(struct ether_arp *packet, unsigned short int type)
{
	packet->ea_hdr.ar_hrd = type; //設定 ARP 封包的硬體類型欄位（Hardware Type）的值
}
void set_prot_type(struct ether_arp *packet, unsigned short int type)
{
	packet->ea_hdr.ar_pro = type; //設定 ARP 封包的協定類型欄位（Protocol Type）的值
}
void set_hard_size(struct ether_arp *packet, unsigned char size)
{
	packet->ea_hdr.ar_hln = size; //設定 ARP 封包的硬體位址長度欄位（Hardware Address Length）的值
}
void set_prot_size(struct ether_arp *packet, unsigned char size)
{
	packet->ea_hdr.ar_pln = size; //設定 ARP 封包的協定位址長度欄位（Protocol Address Length）的值
}
void set_op_code(struct ether_arp *packet, short int code)
{
	packet->ea_hdr.ar_op = code; //設定 ARP 封包的操作碼欄位（Operation Code）的值
}
void set_sender_hardware_addr(struct ether_arp *packet, unsigned char* address)
{

}
void set_sender_protocol_addr(struct ether_arp *packet, char *address)
{
	
}
void set_target_hardware_addr(struct ether_arp *packet, char *address)
{
	
}
void set_target_protocol_addr(struct ether_arp *packet, char *address)
{
	
}

char* get_target_protocol_addr(struct ether_arp *packet)
{
	struct in_addr targetaddr;
	memcpy(&targetaddr,packet->arp_tpa,4);   //複製arp封包的目標ip位址到targetaddr
	return inet_ntoa(targetaddr);
}
char* get_sender_protocol_addr(struct ether_arp *packet)
{
	struct in_addr sendaddr;
	memcpy(&sendaddr,packet->arp_spa,4); //複製arp封包的發送端ip位址到sendaddr
	return inet_ntoa(sendaddr);
}
char* get_sender_hardware_addr(struct ether_arp *packet)
{
	struct ether_addr send_mac;
	char Sendmac[32];
	memcpy(&send_mac,packet->arp_sha,6); //複製arp封包的發送端mac位址到send_mac
	return ether_ntoa_r(&send_mac,Sendmac);
}
char* get_target_hardware_addr(struct ether_arp *packet)
{
	// if you use malloc, remember to free it.
}
