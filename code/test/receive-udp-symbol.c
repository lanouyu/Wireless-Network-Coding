#include "../src/cRaptorQ.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <pthread.h>
#include <unistd.h>

/******* for libpcap *******/
#include <pcap.h>  
#include <time.h>    
#include <stdio.h>  
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

/************libnet*********/
#include <string.h>
#include <errno.h>
#include <libnet.h>
#include <sys/types.h>

#define PORT 6666
#define MAXLINE 4096
// #define MAXSYMBOL 100

/***********************callback function get packet**********************/
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr, 
                    const u_char *packet)
{
    //char * buff = userless;
    u_char *data;

   // data = (u_char*)(packet+356+sizeof(struct ether_header)+sizeof(struct iphdr)
    //                                +sizeof(struct udphdr));//得到数据包里内容，不过一般为乱码。
    //printf("packet:%s\nether_header:%d\niphdr:%d\nudphdr:%d\n", 
    //	packet,sizeof(struct ether_header), sizeof(struct iphdr), sizeof(struct udphdr));
    u_int L = (pkthdr->len - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr))/2;
    data = (u_char*)(packet+L+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct udphdr));
    //printf ("the content of packets is \n%x\n",data);
    //printf("l:%x\npkthdr->len:%x\n",L, pkthdr->len );

    for (int i = 0; i < L; ++i)
    {
      userless[i] = data[i];
      //printf("%02x\n", userless[i]);
    }
}
  
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
  int * id = (int *)arg;  
    
  printf("id: %d\n", ++(*id));  
  printf("Packet length: %d\n", pkthdr->len);  
  printf("Number of bytes: %d\n", pkthdr->caplen);  
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
    
  int i;
  u_int L = pkthdr->len - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr);  
  for(i=0; i<L; ++i)  
  {  
    printf(" %02x", packet[i]);  
    if( (i + 1) % 16 == 0 )  
    {  
      printf("\n");  
    }  
  }  
    
  printf("\n\n");  
}  

int send_info() {
	/***********libnet**********************************************/

    libnet_t *handle; /* Libnet句柄 */
    int packet_size; /* 构造的数据包大小 */
    char *device = "ens33"; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    char *src_ip_str = "192.168.1.144"; /* 源IP地址字符串 */
    char *dst_ip_str = "192.168.1.255"; /* 目的IP地址字符串 */
    //char *dst_ip_str = "192.168.0.133";
    u_char src_mac[6] = {0x00, 0x0c, 0x29, 0x2b, 0xaa, 0xd2}; /* 源MAC */
    //u_char dst_mac[6] = {0x00, 0x0c, 0x29, 0xbf, 0xad, 0x3f}; /* 目的MAC */
    u_char dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    libnet_ptag_t eth_tag, ip_tag, udp_tag; /* 各层build函数返回值 */
    u_short proto = IPPROTO_UDP; /* 传输层协议 */
    u_char payload[50] = {0}; /* 承载数据的数组，初值为空 */
    u_long payload_s = 0; /* 承载数据的长度，初值为0 */
    memcpy(payload, "END", sizeof(uint32_t));

    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);
    
    /* 初始化Libnet */
    if ( (handle = libnet_init(LIBNET_LINK, device, error)) == NULL ) {
        printf("libnet_init failure\n");
        return (-1);
    };


    /* send */
    udp_tag = libnet_build_udp(
                               30330, /* 源端口 */
                               30331, /* 目的端口 */
                               LIBNET_UDP_H + payload_s, /* 长度 */
                               0, /* 校验和,0为libnet自动计算 */
                               payload, /* 负载内容 */
                               payload_s, /* 负载内容长度 */
                               handle, /* libnet句柄 */
                               0 /* 新建包 */
                               );
    if (udp_tag == -1) {
        printf("libnet_build_tcp failure\n");
        return (-3);
    };

 
    /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
    ip_tag = libnet_build_ipv4(
                               LIBNET_IPV4_H + LIBNET_UDP_H + payload_s, /* IP协议块的总长,*/
                               0, /* tos */
                               (u_short) libnet_get_prand(LIBNET_PRu16), /* id,随机产生0~65535 */
                               0, /* frag 片偏移 */
                               (u_int8_t)libnet_get_prand(LIBNET_PR8), /* ttl,随机产生0~255 */
                               proto, /* 上层协议 */
                               0, /* 校验和，此时为0，表示由Libnet自动计算 */
                               src_ip, /* 源IP地址,网络序 */
                               dst_ip, /* 目标IP地址,网络序 */
                               //NULL, /* 负载内容或为NULL */
                               //0, /* 负载内容的大小*/
				payload,
				payload_s,
                               handle, /* Libnet句柄 */
                               0 /* 协议块标记可修改或创建,0表示构造一个新的*/
                               );
    if (ip_tag == -1) {
        printf("libnet_build_ipv4 failure\n");
        return (-4);
    };

     /* 构造一个以太网协议块,只能用于LIBNET_LINK */
    eth_tag = libnet_build_ethernet(
                                    dst_mac, /* 以太网目的地址 */
                                    src_mac, /* 以太网源地址 */
                                    ETHERTYPE_IP, /* 以太网上层协议类型，此时为IP类型 */
                                    NULL, /* 负载，这里为空 */ 
                                    0, /* 负载大小 */
                                    handle, /* Libnet句柄 */
                                    0 /* 协议块标记，0表示构造一个新的 */ 
                                    );
    if (eth_tag == -1) {
        printf("libnet_build_ethernet failure\n");
        return (-5);
    };

 	for (uint32_t i = 0; i < 100; ++i) 
    	packet_size = libnet_write(handle); /* 发送已经构造的数据包*/

    if (packet_size == -1) {
        printf("write error:%s\n", libnet_geterror(handle));
    }
    else { 
        printf("wrote %d byte UDP packet\n",packet_size);
    }

    libnet_destroy(handle); /* 释放句柄 */  
}

//======================================================================================
int main(void) {

	FILE * fp;
	fp = fopen("log_symbol.txt","wb");
	/********************** socket****************************/
  	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  	//u_char buff[MAXLINE];  
    
  	/* get a device */  
  	devStr = pcap_lookupdev(errBuf);  
  	//devStr = "ens33";
    
  	if(devStr)  
  	{  
    	printf("success: device: %s\n", devStr);  
  	}  
  	else  
  	{  
    	printf("error: %s\n", errBuf);  
    	exit(1);  
  	}  
    
  	/* open a device, wait until a packet arrives */  
  	pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
    
  	if(!device)  
  	{  
    	printf("error: pcap_open_live(): %s\n", errBuf);  
    	exit(1);  
  	}

  	/* construct a filter */
  	struct bpf_program filter; 
  	//pcap_compile(device, &filter, "udp", 1, 0); 
  	pcap_compile(device, &filter, "src host 192.168.1.144", 1, 0); 
  	//pcap_compile(device, &filter, "src host 192.168.211.128", 1, 0);
  	pcap_setfilter(device, &filter);
  	clock_t begin, end;
  	double duration;
  	u_char buff[MAXLINE];

  	// parameters for decode
  	const uint16_t subsymbol = 8;
	const uint16_t symbol_size = 64;
	float drop_prob = 20.0;
	uint8_t overhead = 4;
	struct pair
	{
		uint32_t id;
		uint64_t *symbol;
	};
	

	pthread_t tid;
	int err;
	void *tret;

	for (uint32_t times = 0; times < 500; ++times) {
		struct pair *encoded;
		uint32_t next_encoded = 0;
		uint32_t oti_scheme = 0;
		uint64_t oti_common = 0;
		//begin = clock();

		// receive oti
		while (oti_common == 0) { 
			pcap_loop(device, 1, my_callback, (u_char *)buff);
			//printf("receive %s\n", (u_char *)buff);
			if (buff[0] == 'O' && buff[1] == 'T' && buff[2] == 'I') {
				begin = clock();
				uint32_t a = sizeof(uint32_t);
				memcpy(&oti_common, buff + a, sizeof(oti_common));
				printf("recv oti_common from client: %x\n", oti_common);
				memcpy(&oti_scheme, buff+a+sizeof(oti_common), sizeof(oti_scheme));
				printf("recv oti_scheme from client: %x\n", oti_scheme);
			}
		}

		//oti_common = 0xffffffffffffffff;
		//oti_scheme = 0xffffffff;

		// calculate number of symbols
		uint64_t F = oti_common >> 24; // transfer length
		uint64_t T = (oti_common << 48) >> 48; // symbol size
		uint64_t K = (F / T) + 1; // symbol number
		uint32_t MAXSYMBOL = K + 10; // need receive K_1 packet, 10 can change
		printf("shijinzhi\nF:%d\nT:%d\nK:%d\nMAXSYMBOL:%d\n", F,T,K,MAXSYMBOL);
		encoded = (struct pair*) malloc(sizeof(struct pair)* (MAXSYMBOL));
		for (uint32_t i = 0; i < MAXSYMBOL; ++i)
			encoded[i].symbol = NULL;

		// initialize decoder
		struct RaptorQ_ptr *dec = RaptorQ_Dec(DEC_32, oti_common, oti_scheme);
		if (dec == NULL) {
			fprintf(stderr, "Could not initialize decoder!\n");
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			return 0;
		}

		// receive packet
		while (next_encoded < MAXSYMBOL) {
			pcap_loop(device, 1, my_callback, (u_char *)buff);
			if (!(buff[0] == 'P' && buff[1] == 'A' && buff[2] == 'C')) continue;
			//printf("receive %s\n", (u_char *)buff);
			uint32_t a = sizeof(uint32_t);
			while (!(buff[a] == 'E' && buff[a+1]== 'N' && buff[a+2]=='D')) {
				memcpy(&encoded[next_encoded].id, buff + a, sizeof(uint32_t));
				a = a + sizeof(uint32_t);
				encoded[next_encoded].symbol = (uint32_t*) malloc(symbol_size);
				memcpy(encoded[next_encoded].symbol, buff + a, 
						symbol_size);
				a = a + symbol_size;
				printf("recv encoded[%x]:\tid: %x;\tsymbol: %x\n", next_encoded, 
				encoded[next_encoded].id, *encoded[next_encoded].symbol);
				
				++next_encoded;
			}
		}
		printf("receive all data!\n");

		// decode
		for (uint32_t i = 0; i < next_encoded; ++i) {
			uint64_t *data = encoded[i].symbol;
			uint32_t data_size = RaptorQ_symbol_size (dec) / sizeof(uint32_t);
			printf("encoded[%x]=%x\tdata_size: %x\n", i,*data, data_size);
			if (!RaptorQ_add_symbol_id (dec, (void **)&data, data_size,
										encoded[i].id)) {
				fprintf(stderr, "Error: couldn't add the symbol to the decoder\n");
				/*for (uint32_t k = 0; k < next_encoded; ++k)
					free (encoded[k].symbol);
				free (encoded);
				RaptorQ_free (&dec);
				return 0;*/
			}
		}
		uint64_t decoded_size = ceil (RaptorQ_bytes (dec) / sizeof(uint32_t));
		uint32_t *received = (uint32_t *) malloc (decoded_size * sizeof(uint64_t));

		for (uint32_t *shit = received; shit != received + decoded_size; ++ shit);
		uint64_t *rec = received;
		uint64_t written = RaptorQ_decode (dec, (void **)&rec, decoded_size);
		
		printf("written: %x\ndecoded_size: %x\n", written, decoded_size);
		
		if (written != decoded_size) {
			fprintf(stderr, "Couldn't decode");
			free(received);
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			RaptorQ_free(&dec);
			return 0;
		} else {
			printf("Decoded: %i\n", decoded_size);
		}

		for (uint32_t i = 0; i < decoded_size; ++i) {
			printf("decoded[%x]:%x\n", i, received[i]);
		}
		/*
		err=pthread_create(&tid,NULL,send_info,NULL);//创建线程
		if(err!=0) {
		    printf("pthread_create error:%s\n",strerror(err));
			exit(-1);
		}
		*/

		decoded_size *= symbol_size / 8;
		// calculate the speed
		end = clock();
		duration=(double)(end - begin) / CLOCKS_PER_SEC;
		printf("%.0f KB/s\n",decoded_size / duration / 1000);
		fprintf(fp, "%.0f \n",decoded_size / duration / 1000);

		RaptorQ_free(&dec);
		for (uint32_t k = 0; k < next_encoded; ++k)
		free (encoded[k].symbol);
		free (encoded);
		/*
		err=pthread_join(tid,&tret);//阻塞等待线程id为tid1的线程，直到该线程退出
		if(err!=0)
		{
			printf("can not join with thread1:%s\n",strerror(err));
			exit(-1);
		}
		*/

	}

  	pcap_close(device); 
  	fclose(fp);

  	return 0;
	
}

