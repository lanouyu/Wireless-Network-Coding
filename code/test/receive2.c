#include "../src/cRaptorQ.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include <string.h>

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

/***********************callback function get packet**********************/
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr, 
                    const u_char *packet)
{
    //char * buff = userless;
    u_char *data;

    data = (u_char*)(packet+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct udphdr) + 356);//得到数据包里内容，不过一般为乱码。
    u_int L = pkthdr->len - 356 - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr);
    //printf ("the content of packets is \n%x\n",data);
    printf("%x\n",L );

    for (int i = 0; i < L; ++i)
    {
      userless[i] = data[i];
      printf("%02x\n", userless[i]);
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
  u_int L = pkthdr->len - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct tcphdr);  
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
//======================================================================================
int main(void) {
	const uint16_t subsymbol = 8;
	const uint16_t symbol_size = 16;
	uint32_t mysize = 50;
	float drop_prob = 20.0;
	uint8_t overhead = 4;

	/********************** socket****************************/
  	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  	u_char buff[MAXLINE];  
    
  	/* open a device, wait until a packet arrives */  
  	pcap_t * device;  
  	/* construct a filter */
  	struct bpf_program filter; 


  	pid_t fpid; //fpid表示fork函数返回的值  
  	int count=0;  
  	fpid=fork();

  	if (fpid < 0)   
    	printf("error in fork!");   
    else if (fpid == 0) {  
      	//printf("i am the child process, my process id is %d\n",getpid());   
      	//printf("我是爹的儿子\n");//对某些人来说中文看着更直白。  
      	//count++; 
      	//printf("1统计结果是: %d\n",count);

        /* get a device */  
      	//devStr = pcap_lookupdev(errBuf);  
      	devStr = "ens33";
    
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
      	device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
    
      	if(!device)  
      	{  
        	printf("error: pcap_open_live(): %s\n", errBuf);  
        	exit(1);  
      	}

      	pcap_compile(device, &filter, "src host 192.168.1.143", 1, 0);
      	pcap_setfilter(device, &filter);

        /* wait loop forever */  
 		pcap_loop(device, 1, my_callback, (u_char *)buff);
    }
    else {
      	//printf("\n i am the parent process, my process id is %d\n",getpid());   
      	//printf("我是孩子他爹\n");  
      	//count++; 
      	//printf("2统计结果是: %d\n",count);
        /* get a device */  
      	//devStr = pcap_lookupdev(errBuf);  
      	devStr = "ens38";
    
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
     	device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
    
      	if(!device)  
      	{  
        	printf("error: pcap_open_live(): %s\n", errBuf);  
        	exit(1);  
      	}      
      	pcap_compile(device, &filter, "src host 192.168.0.132", 1, 0);
      	pcap_setfilter(device, &filter);  
   	  	pcap_loop(device, 1, my_callback, (u_char *)buff);
    }
  	pcap_close(device); 

	/*******************receive****************************/
	struct pair
	{
		uint32_t id;
		uint32_t *symbol;
	};
	struct pair *encoded;
	uint32_t next_encoded = 0;
	uint32_t oti_scheme = 0;
	uint64_t oti_common = 0;

	//n = recv(connfd, &oti_common, sizeof(oti_common), 0);
	//buff[n] = '\0';
	uint32_t a = 0;
	memcpy(&oti_common, buff, sizeof(oti_common));
	printf("recv oti_common from client: %x\n", oti_common);

	//recv(connfd, &oti_scheme, sizeof(oti_scheme), 0);
	//n = recv(connfd, &oti_scheme, sizeof(oti_scheme), 0);
	//buff[n] = '\0';
	memcpy(&oti_scheme, buff+sizeof(oti_common), sizeof(oti_scheme));
	printf("recv oti_scheme from client: %x\n", oti_scheme);

	a = sizeof(oti_scheme) + sizeof(oti_common);

	encoded = (struct pair*) malloc(sizeof(struct pair)* MAXSYMBOL);
	for (uint32_t i = 0; i < MAXSYMBOL; ++i)
		encoded[i].symbol = NULL;

	//n = recv(connfd, buff, sizeof(uint32_t)+symbol_size, 0);
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
		//n = recv(connfd, buff, sizeof(uint32_t)+symbol_size, 0);
	}

	printf("receive all data!\n");

	/******************decode******************************/
	struct RaptorQ_ptr *dec = RaptorQ_Dec(DEC_32, oti_common, oti_scheme);
	if (dec == NULL) {
		fprintf(stderr, "Could not initialize decoder!\n");
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
		return -1;
	}

	for (size_t i = 0; i < next_encoded; ++i) {
		uint32_t *data = encoded[i].symbol;
		uint32_t data_size = RaptorQ_symbol_size (dec) / sizeof(uint32_t);
		printf("encoded[%x]=%x\tdata_size: %x\n", i,*data, data_size);
		if (!RaptorQ_add_symbol_id (dec, (void **)&data, data_size,
									encoded[i].id)) {
			fprintf(stderr, "Error: couldn't add the symbol to the decoder\n");
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			RaptorQ_free (&dec);
			return -1;
		}
	}

	uint64_t decoded_size = ceil (RaptorQ_bytes (dec) / sizeof(uint32_t));
	uint32_t *received = (uint32_t *) malloc (decoded_size * sizeof(uint32_t));

	for (uint32_t *shit = received; shit != received + decoded_size; ++ shit);
	uint32_t *rec = received;
	uint64_t written = RaptorQ_decode (dec, (void **)&rec, decoded_size);
	
	printf("written: %x\ndecoded_size: %x\nmysize: %x\n",
		written, decoded_size, mysize);

	if ((written != decoded_size) || (decoded_size != mysize)) {
		fprintf(stderr, "Couldn't decode: %i - %lu\n", mysize, written);
		free(received);
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
		RaptorQ_free(&dec);
		return false;
	} else {
		printf("Decoded: %i\n", mysize);
	}

	for (uint16_t i = 0; i < mysize; ++i) {
		printf("received[%x]: %x\n", i, received[i]);
	}

	RaptorQ_free(&dec);
	for (uint32_t k = 0; k < next_encoded; ++k)
		free (encoded[k].symbol);
	free (encoded);
	return 0;
}