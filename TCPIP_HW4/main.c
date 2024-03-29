#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/time.h>
#define MAX_HOPS 30
#define PACKET_SIZE 64
#define TIMEOUT 3

//參考指令(-help)
void usage() {
    printf("Usage: prog <hop-distance> <destination>\n");
}

int main(int argc, char *argv[]) {

    if(geteuid() != 0){
        printf("%s\n","ERROR: You must be root to use this tool!"); //檢查程式是否以root權限執行(sudo)
        exit(1);
    }


	if(!strcmp(argv[0],"./ers") ) 
	{

        if (!strcmp(argv[1],"-help") ) {
            usage();  
            return 1;
        }
        else if(!strcmp(argv[1],"prog") )
		{
            int hop_distance = atoi(argv[2]);  //hop數量
            char* destination = argv[3];  //目標IP位址

            //將目標主機的 IP 位址從文字格式（例如"140.117.11.1"）轉換為二進制格式，以便後續Socket將 ICMP 封包傳送到目標主機
            struct sockaddr_in target;
            if (inet_pton(AF_INET, destination, &target.sin_addr) != 1) {
                perror("Invalid destination IP address");
                return 1;
            }
            //建立Socket，以便後續的操作可以傳送和接收 ICMP 封包
            int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
            if (sockfd < 0) {
                perror("Socket creation failed");
                return 1;
            }
            //設定Socket的接收逾時時間，以便在接收封包時能夠控制等待的時間
            struct timeval timeout;
            timeout.tv_sec = TIMEOUT;
            timeout.tv_usec = 0;
            if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout)) < 0) {
                perror("Error setting socket options");
                return 1;
            }
            //ERS用於追蹤封包在網路中的路徑，每個TTL值發送3個封包並等待回應
            for (int ttl = 1; ttl <= hop_distance; ttl++) {
                setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)); //確保後續發送的 ICMP 封包具有正確的TTL值，模擬封包經過不同數量的路由器跳數

                struct sockaddr_in recv_addr; //儲存接收封包的來源ip位址
                socklen_t recv_addr_len = sizeof(recv_addr); 
                char packet[PACKET_SIZE]; //儲存 ICMP 封包的內容
                struct ip* ip_hdr = (struct ip*)packet; //ip_hdr 指向 packet ，填充 IP header 的字段

                int seq = 0;//追蹤 ICMP 封包的序號
                bzero(packet, PACKET_SIZE); //packet内容初始化

                ip_hdr->ip_dst = target.sin_addr; //將目標主機的 IP 位址複製到 ICMP 封包的 IP header中的目標 IP 位址欄位中，以告知封包傳送到哪個目標主機

                printf("Traceroute to %s (%s), %d hops max\n", destination, inet_ntoa(target.sin_addr), hop_distance);

                for (int i = 0; i < 3; i++) { //每個TTL值發送3個封包並等待回應
                    seq++; //增加 ICMP 封包的序號

                    //發送封包到指定的目標位址
                    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr*)&target, sizeof(target)) < 0) {
                        perror("Error sending packet");
                        return 1;
                    }

                    //接收 ICMP 封包
                    if (recvfrom(sockfd, packet, sizeof(packet), 0, (struct sockaddr*)&recv_addr, &recv_addr_len) < 0) {
                        printf("%d  * * *\n", ttl); //如果在接收逾時時間內沒有收到回應，則會輸出 "* * *"
                    } else {
                        printf("%d  %s\n", ttl, inet_ntoa(recv_addr.sin_addr)); //如果接收到回應，將解析回應並列印目前 TTL 值和路由器的 IP 位址
                    }
                }
            }
            close(sockfd);
        }
        else if(argc != 4)
        {
            printf("%s\n","Input command error."); //指令輸出錯誤
            exit(1);
        }
    }  
    return 0;
}