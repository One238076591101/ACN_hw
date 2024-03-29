#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <time.h>
#include <net/if.h>

#include "fill_packet.h"
#include "pcap.h"

#define MASK_SIZE 20
#define IP_SIZE 20

pid_t pid;
u16 icmp_req = 1;
struct timeval stop,start;

void print_usage()
{
	printf("Please enter the following command.\n");
	printf("sudo ./ipscanner –i [Network Interface Name] -t [timeout(ms)]\n");
}

int main(int argc, char* argv[])
{
	int sockfd;
	int on = 1;
	
	int sockfd_send;
	int sockfd_recv;
	
	pid = getpid();
	struct sockaddr_in dst;

	
	struct in_addr myip,mymask;
	struct ifreq req_local; 
	char device_name[100];
	
	myicmp packet,packet_recv;
	int timeout = DEFAULT_TIMEOUT;



	strcpy(device_name,argv[2]);   
	timeout = atoi(argv[4]);
	strcpy(req_local.ifr_name,device_name);
	
	//檢查程式是否以 root 權限運行
	if(geteuid() != 0){
			printf("%s\n","ERROR: You must be root to use this tool!");
			exit(1);
	}
	//建立socket將封包傳送到網路介面
	if((sockfd_send = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
			perror("open send socket error");
			exit(1);
	}
	//獲取網路介面的IP地址
    if(ioctl(sockfd_send, SIOCGIFADDR, &req_local) < 0) {
        perror("ioctl SIOCGIFADDR error");
        myip.s_addr = 0;
    }
    else {
        memcpy(&dst,&req_local.ifr_addr,sizeof(dst));
        myip = dst.sin_addr;
    }

	 //獲取網路介面的network mask
	if( ioctl(sockfd_send,SIOCGIFNETMASK, &req_local)== -1){
		perror("SIOCGIFADDR ERROR");
		exit(1);
		mymask.s_addr = 0;
	}
	else{
		memcpy(&dst,&req_local.ifr_addr,sizeof(dst));
        mymask = dst.sin_addr;
	}
	
	//將 mask從二進制轉換為字串格式，並將它們分割成數值做處理
	char str_Mask[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &mymask, str_Mask, INET_ADDRSTRLEN);
	char maskStr[MASK_SIZE];
	unsigned char	Target_Mask[MASK_SIZE]; 
	memcpy(maskStr, str_Mask, MASK_SIZE);
	char *Mask_token;
	int MASK_Num;
	Mask_token = strtok(maskStr, ".");
	int i=0;
	//將 mask的四個部分轉換為整數形式並儲存在 Target_Mask 陣列中
	while( Mask_token != NULL) 
	{
		MASK_Num = atoi(Mask_token);
		Target_Mask[i] = MASK_Num;
		i++;
		Mask_token = strtok(NULL,".");
	}
	
	//將 IP 地址從二進制轉換為字串格式，並將它們分割成數值做處理
	char str_IP[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &myip, str_IP, INET_ADDRSTRLEN);
	char ipStr[IP_SIZE];
	unsigned char 	Target_IP[IP_SIZE]; 
	memcpy(ipStr, str_IP, IP_SIZE);
	char *IP_token;
	int IP_Num;
	IP_token = strtok(ipStr, ".");
	int j=0;
	//將 IP 地址的四個部分轉換為整數形式並儲存在 Target_IP 陣列中
	while( IP_token != NULL) 
	{
		IP_Num = atoi(IP_token);
		Target_IP[j] = IP_Num; 
		j++;
		IP_token = strtok(NULL,".");
	}
	
	//透過等長子網段劃分，得知特定子網段中哪些IP地址是可用的，作為搜尋的範圍
	int ableIP,netSeg,startMask,endMask; //設可用的 IP 數量,子網段的數量,起始地址,結束地址
	
	if(Target_Mask[2] == 255){ //Target_Mask=255.255.255.x
		
		ableIP = 256 - Target_Mask[3];
		netSeg = 256 / ableIP;


		if(netSeg == 1){ 	//沒有分子網段, Target_Mask=255.255.255.0
			startMask =0+1;
			endMask = 255-1;
		}
		else if(netSeg == 2){ //等分成2個子網段,Target_Mask=255.255.255.128
			if( Target_IP[3]<128){
				startMask =0+1;
				endMask = 128-1;
			}
			else{
				startMask =128;
				endMask = 255-1;
			}
		}
		else if(netSeg == 4){ //等分成4個子網段, Target_Mask=255.255.255.192
			if(Target_IP[3]<64){
				startMask =0+1;
				endMask = 63-1;
			}
			else if(Target_IP[3]>63 && Target_IP[3]<128){
				startMask =64+1;
				endMask = 127-1;
			}
			else if(Target_IP[3]>127 && Target_IP[3]<192){
				startMask =128+1;
				endMask = 191-1;
			}
			else if(Target_IP[3]>191 && Target_IP[3]<256){
				startMask =191+1;
				endMask = 255-1;
			}
		}
		else if(netSeg == 8){ //等分成8個子網段, Target_Mask=255.255.255.224
			if(Target_IP[3]<32){
				startMask =0+1;
				endMask = 31-1;
			}
			else if(Target_IP[3]>31 && Target_IP[3]<64){
				startMask =32+1;
				endMask = 63-1;
			}
			else if(Target_IP[3]>63 && Target_IP[3]<96){
				startMask =64+1;
				endMask = 95-1;
			}
			else if(Target_IP[3]>95 && Target_IP[3]<128){
				startMask =96+1;
				endMask = 127-1;
			}
			else if(Target_IP[3]>127 && Target_IP[3]<160){
				startMask =128+1;
				endMask = 159-1;
			}
			else if(Target_IP[3]>159 && Target_IP[3]<192){
				startMask =160+1;
				endMask = 191-1;
			}
			else if(Target_IP[3]>191 && Target_IP[3]<224){
				startMask =192+1;
				endMask = 223-1;
			}
			else if(Target_IP[3]>223 && Target_IP[3]<256){
				startMask =224+1;
				endMask = 255-1;
			}
		}
	}

	if(argc == 5){
		if(!strcmp(argv[0],"./ipscanner") && !strcmp(argv[1],"-i") && !strcmp(argv[3],"-t"))
		{	
			

			for(int i=startMask;i<=endMask;i++){
				if(i==Target_IP[3]) //當到自己的ip時則跳過
				{
					continue;
				}
				char testIP[IP_SIZE]; //建立testIP ，測試不同的 IP 位址
				sprintf(testIP,"%d.%d.%d.%d",Target_IP[0],Target_IP[1],Target_IP[2],i); //testIP 為格式化後的 IP 位址，其中 i 在迴圈中變化，生成不同的測試 IP 位址
				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0) //建立socket發送封包
				{
					perror("socket");
					exit(1);
				}
				if(setsockopt( sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) //設置 socket 選項（IP_HDRINCL）自定義 IP header
				{
					perror("setsockopt");
					exit(1);
				}

				char data[20] = "M123040005"; //設定發送的data(我的學號)
				dst.sin_family = AF_INET; // struct sockaddr_in 結構中所包含的位址是 IPv4 位址
				dst.sin_addr.s_addr = inet_addr(testIP); //設定目的IP 位址
				
				printf("Ping %s (data size = %ld, id = 0x%x, seq = %d, timeout = %d ms)\n", testIP, sizeof(data),pid,icmp_req,timeout);

				//填充 ICMP 和 IP封包的header
				fill_icmphdr(&packet.icmp_hdr,data);
				fill_iphdr(&packet.ip_hdr, testIP,str_IP,sizeof(packet));
				
				unsigned long timeUsec;
				unsigned long timeSec;
				gettimeofday(&start, NULL); //獲取當前的timestamp
				if(sendto(sockfd, &packet, sizeof(packet), 0, &dst, sizeof(dst)) < 0) //使用 sendto 函數發送封包
				{
					perror("sendto");
					exit(1);
				}

				if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_ICMP)) < 0) //建立接收 ICMP reply的 socket
				{
					perror("socket");
					exit(1);
				}

				bzero(&dst,sizeof(dst)); //dst結構體初始化
				
				while(1){
					//接收封包時出現錯誤
			    		if(recvfrom(sockfd, &packet, sizeof(packet), 0,  NULL, NULL) < 0){ 
				            printf("Destination Unreachable\n\n");
				            break;
						}
						gettimeofday(&stop, NULL);
						timeSec = stop.tv_sec-start.tv_sec;
						timeUsec =(stop.tv_usec-start.tv_usec);
						//接收封包為 ICMP 的類型
						if(ntohs(packet.icmp_hdr.icmp_type) == ICMP_ECHOREPLY )
			        	{
			            	printf("Reply from : %s , time : %ld.%04ld ms\n\n",testIP,timeSec,timeUsec);
			            	break;
			        	}	
			        	else {
					    printf("Destination Unreachable\n\n");
				            break;
						}
				}
				icmp_req++;
				
			}
		}
		else{
				print_usage();
				exit(1);
		}
	}
	else{
		print_usage();
		exit(1);
	}

	return 0;
}

