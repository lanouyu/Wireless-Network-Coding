#include <pcap.h>
#include "../src/cRaptorQ.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/************socket*********/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 6666
#define MAXLINE 4096
#define MAXSYMBOL 100

void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)
{
  int * id = (int *)arg;

  printf("id: %d\n", ++(*id));
  printf("Packet length: %d\n", pkthdr->len);
  printf("Number of bytes: %d\n", pkthdr->caplen);
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec)); 
  
  int i;
  for(i=0; i<pkthdr->len; ++i)
  {
    printf(" %02x", packet[i]);
    if( (i + 1) % 16 == 0 )
    {
      printf("\n");
    }
  }
  printf("\n ");
  /*
  for(i=42; i<pkthdr->len; ++i)
  {
    printf("%c", packet[i]);
  }
	*/
  printf("\n\n");
}

int main()
{
  char errBuf[PCAP_ERRBUF_SIZE], * devStr;
  
  /* get a device */
  devStr = pcap_lookupdev(errBuf);
  
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
  pcap_compile(device, &filter, "udp", 1, 0);
  pcap_setfilter(device, &filter);
 
  /* wait loop forever */
  int id = 0;
  pcap_loop(device, -1, getPacket, (u_char*)&id);
  
  pcap_close(device);

  return 0;
}

