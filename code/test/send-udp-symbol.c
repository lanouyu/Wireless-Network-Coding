#include "../src/cRaptorQ.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <unistd.h>

/************libnet*********/
#include <string.h>
#include <errno.h>
#include <libnet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

#define PORT 6666
#define MAXLINE 4096
#define MAXSYMBOL 100
bool flag = false;

/***********************callback function get packet**********************/
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr, 
                    const u_char *packet)
{
    //char * buff = userless;
    u_char *data;

   // data = (u_char*)(packet+356+sizeof(struct ether_header)+sizeof(struct iphdr)
    //                                +sizeof(struct udphdr));//得到数据包里内容，不过一般为乱码。
    printf("packet:%s\nether_header:%d\niphdr:%d\nudphdr:%d\n", 
    	packet,sizeof(struct ether_header), sizeof(struct iphdr), sizeof(struct udphdr));
    u_int L = (pkthdr->len - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr))/2;
    data = (u_char*)(packet+L+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct udphdr));
    //printf ("the content of packets is \n%x\n",data);
    printf("l:%x\npkthdr->len:%x\n",L, pkthdr->len );

    for (int i = 0; i < L; ++i)
    {
      userless[i] = data[i];
      //printf("%02x\n", userless[i]);
    }
}

void libnetsend(u_char *data, u_long payload_s)
{
	/***********libnet**********************************************/
    libnet_t *handle; /* Libnet句柄 */
    int packet_size; /* 构造的数据包大小 */
    char *device = "ens33"; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    char *src_ip_str = "192.168.1.144"; /* 源IP地址字符串 */
    char *dst_ip_str = "192.168.255.255"; /* 目的IP地址字符串 */
    //char *dst_ip_str = "192.168.0.133";
    //u_char src_mac[6] = {0x00, 0x0c, 0x29, 0x2b, 0xaa, 0xd2}; /* 源MAC */
    u_char src_mac[6] = {0x00, 0x0c, 0x29, 0x2b, 0xaa, 0xd2}; /* 目的MAC */
    u_char dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    libnet_ptag_t eth_tag, ip_tag, udp_tag; /* 各层build函数返回值 */
    u_short proto = IPPROTO_UDP; /* 传输层协议 */

    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

        	if ( (handle = libnet_init(LIBNET_LINK, device, error)) == NULL ) {
        	printf("libnet_init failure\n");
        	return (-1);
    	};

	u_char payload[500] = {0}; /* 承载数据的数组，初值为空 */
    memcpy(payload,data,payload_s);
    //u_long payload_s = 0; /* 承载数据的长度，初值为0 */
	//payload_s = encode(mysize, (u_char *)payload); /* 计算负载内容的长度 */
	//printf("payload:%x\npayload_s %x\n\n",payload, payload_s );

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
	 
	    packet_size = libnet_write(handle); /* 发送已经构造的数据包*/

	    if (packet_size == -1) {
	        printf("write error:%s\n", libnet_geterror(handle));
	    }
	    else { 
	        //printf("wrote %d byte UDP packet\n",packet_size);
	    }
	    libnet_destroy(handle); /* 释放句柄 */  
}

int recv_info() {
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
  	for (uint32_t i = 0; i < 500; ++i) {
	  	pcap_loop(device, 1, my_callback, (u_char *)buff);
	  	printf("receive:%s\n", buff);
	  	if (buff[0]=='E'&&buff[1]=='N'&&buff[2]=='D') {
	  		flag = true;
	  		sleep(1);
	  	}
	}
	pcap_close(device);
}

int main() 
{
	u_char payload[500] = {0};
	uint32_t payload_size = 500;
	uint32_t mysize = 50;
	float drop_prob = 10.0;
	uint8_t overhead = 4;
	const uint16_t subsymbol = 8;
	const uint16_t symbol_size = 64;
	pthread_t tid;
	int err;
	void *tret;
	err=pthread_create(&tid,NULL,recv_info,NULL);//创建线程
	if(err!=0) {
	    printf("pthread_create error:%s\n",strerror(err));
		exit(-1);
	}
	while (1) {
		/*****creat data*******************************************/
		uint32_t *myvec;
		srand((uint32_t)time(NULL));
		myvec = (uint32_t*) malloc(mysize * sizeof(uint32_t));
		for (uint32_t i = 0; i < mysize; ++i) {
			myvec[i] = (uint32_t)rand();
			printf("myvec[%x]: %x\n", i, myvec[i]);
		}
		struct pair {
			uint32_t id;
			uint64_t *symbol;
		};

		/******encode*********************************************/
		struct RaptorQ_ptr *enc = RaptorQ_Enc(ENC_32, myvec, mysize,
			subsymbol, symbol_size, 500);
					/* RaptorQ_ptr* RaptorQ_Enc (const RaptorQ_type type,
												void *data,
												const uint64_t size,
												const uint16_t min_subsymbol_size,
												const uint16_t symbol_size,
												const size_t max_memory);
					*/
		if (enc == NULL) {
			fprintf(stderr, "Initialize encoder error!\n");
			free (myvec);
			return -1;
		}

		RaptorQ_precompute(enc, 2, true);
			/* start background precomputation while we get the source symbols.
				void RAPTORQ_API RaptorQ_precompute (struct RaptorQ_ptr *enc,
															const uint8_t threads,
															const bool background);
			*/

		// create and initial encoded pair array
		uint32_t symbols_tot = 0;
		uint32_t blocks = RaptorQ_blocks(enc);
		for (uint8_t b = 0; b < blocks; ++b) {
			uint16_t sym = RaptorQ_symbols(enc, b);
			symbols_tot += (sym + overhead);
		}
		printf("symbols_tot: %x\n",symbols_tot);

		struct pair *encoded;
		uint32_t next_encoded = 0;
		encoded = (struct pair*) malloc(sizeof(struct pair)* symbols_tot);
		for (uint32_t i = 0; i < symbols_tot; ++i)
			encoded[i].symbol = NULL;

		// get oti information
		uint32_t oti_scheme = RaptorQ_OTI_Scheme(enc);
		uint64_t oti_common = RaptorQ_OTI_Common(enc);
	/******************************Send Oti************************************/
		uint32_t a = 0;
		memcpy(payload, "OTI", sizeof(uint32_t));
		a=a+sizeof(uint32_t);
		printf("send oti_common: %x\n", oti_common);
		memcpy(payload+a, &oti_common, sizeof(oti_common));
		a = a + sizeof(oti_common);
		printf("send oti_scheme: %x\n", oti_scheme);
		memcpy(payload + a, &oti_scheme, sizeof(oti_scheme));
		a = a + sizeof(oti_scheme);
		printf("%x\n", a);

		for (int i = 0; i < 10; ++i)
		{
			libnetsend(payload,a);
		}

		a=0;

		for (uint8_t b = 0; b < blocks; ++b) {
			uint32_t sym = RaptorQ_symbols(enc, b);
			int32_t repair = overhead;

			// get source symbol
			for (uint32_t source = 0; source < sym; ++source) {
				encoded[0].id = RaptorQ_id(source, b);
				uint32_t data_size = symbol_size / sizeof(uint32_t);
				encoded[0].symbol = (uint32_t*) malloc(symbol_size);
				uint32_t *data = encoded[0].symbol;
				uint64_t written = RaptorQ_encode(enc, (void**)&data, data_size,
					source, (uint8_t)b);
				if (written != data_size) {
					fprintf(stderr, "Source symbol error!\n");
					free(myvec);
					for (uint32_t k = 0; k <= next_encoded; ++k)
						free(encoded[k].symbol);
					free(encoded);
					RaptorQ_free(&enc);
					return -1;
				}
				//--------------send----------------//
				//for (uint32_t i )
				memcpy(payload, "PAC", sizeof(uint32_t));
				a=sizeof(uint32_t);
				//printf("send encoded[%x]: id: %x;\tsymbol: %x\n", next_encoded, 
				//	encoded[0].id, *encoded[0].symbol);		
				memcpy(payload + a , &encoded[0].id, sizeof(uint32_t));
				a = a + sizeof(uint32_t);
				//printf("%x\n", a);
				memcpy(payload + a, encoded[0].symbol, symbol_size);
				//printf("payload[%x]: id: %x;\tsymbol: %x\n", a, payload[a-sizeof(uint32_t)], payload[a]);
				a = a + symbol_size;
				memcpy(payload + a, "END", sizeof(uint32_t));
				a = a + sizeof(uint32_t);
				//printf("%x\n", a);
				libnetsend(payload,a);
				
				++next_encoded;
			}

			// get repair symbol
			uint32_t sym_rep;
			//printf("RaptorQ_max_repair_d:%d\n", RaptorQ_max_repair(enc, b));
			for (sym_rep = sym; sym_rep < RaptorQ_max_repair(enc, b);++sym_rep) 
			{
				float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
				encoded[0].id = RaptorQ_id(sym_rep, b);
				uint32_t data_size = symbol_size / sizeof(uint32_t);
				encoded[0].symbol = (uint32_t*) malloc(symbol_size);
				uint32_t *data = encoded[0].symbol;
				uint64_t written = RaptorQ_encode(enc, (void**)&data, data_size,
					sym_rep, (uint8_t)b);
				if (written != data_size) {
					fprintf(stderr, "Source symbol error!\n");
					free(myvec);
					for (uint32_t k = 0; k <= next_encoded; ++k)
						free(encoded[k].symbol);
					free(encoded);
					RaptorQ_free(&enc);
					return -1;
				}

				//--------------send----------------//
				//u_char payload[500] = {0};
				memcpy(payload, "PAC", sizeof(uint32_t));
				a=sizeof(uint32_t);
				//printf("send encoded[%x]: id: %x;\tsymbol: %x\n", next_encoded, 
				//	encoded[0].id, *encoded[0].symbol);		
				memcpy(payload + a , &encoded[0].id, sizeof(uint32_t));
				a = a + sizeof(uint32_t);
				//printf("%x\n", a);
				memcpy(payload + a, encoded[0].symbol, symbol_size);
				//printf("payload[%x]: id: %x;\tsymbol: %x\n", a, payload[a-sizeof(uint32_t)], payload[a]);
				a = a + symbol_size;
				memcpy(payload + a, "END", sizeof(uint32_t));
				a = a + sizeof(uint32_t);
				//printf("%x\n", a);
				libnetsend(payload,a);

				++next_encoded;
				if (flag) {
					flag = false;
					break;
				}
			}
			if (sym_rep == RaptorQ_max_repair(enc, b)) {
				fprintf(stderr, "lost too much symbol error!\n");
				free(myvec);
				for (uint32_t k = 0; k <= next_encoded; ++k)
					free(encoded[k].symbol);
				free(encoded);
				RaptorQ_free(&enc);
					return -1;
			}
		}
		RaptorQ_free(&enc);
		free(myvec);
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
	}

	return 0;
}

