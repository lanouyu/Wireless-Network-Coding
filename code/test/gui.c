#include <stdlib.h>
#include <gtk/gtk.h>
#include <pthread.h>
#include <stdio.h>

GtkWidget *label1;
GtkWidget *label2;
GtkTextBuffer *buffer1;
int flag;

#include "../src/cRaptorQ.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

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

    data = (u_char*)(packet+356+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct udphdr));//得到数据包里内容，不过一般为乱码。
    u_int L = pkthdr->len -356- sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr);
    //printf ("the content of packets is \n%x\n",data);
    printf("%x\n",L );

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

uint64_t decode(uint32_t mysize, u_char *buff) {
  /*******************receive****************************/
  const uint16_t subsymbol = 8;
  const uint16_t symbol_size = 16;
  float drop_prob = 20.0;
  uint8_t overhead = 4;
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
    return 0;
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
      return 0;
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
    return 0;
  } else {
    printf("Decoded: %i\n", mysize);
  }
  /*
  for (uint16_t i = 0; i < mysize; ++i) {
    printf("received[%x]: %x\n", i, received[i]);
  }
  */
  RaptorQ_free(&dec);
  for (uint32_t k = 0; k < next_encoded; ++k)
    free (encoded[k].symbol);
  free (encoded);
  return decoded_size;
}


void thread() {
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
    

    int count = 0;
    while (flag) {
      count += 1;
      begin = clock();
      uint64_t decoded_size = 0;
      u_char buff[MAXLINE];  
      pcap_loop(device, 1, my_callback, (u_char *)buff);
      printf("receive %s\n", (u_char *)buff);
      decoded_size = decode(50, (u_char *)buff);
      end = clock();
      duration=(double)(end - begin) / CLOCKS_PER_SEC;
      char speed[10];
      sprintf(speed, "%.0f KB/s", decoded_size / duration / 1000);
      printf("%.0f KB/s\n", speed);
      if (count % 1 == 0) {
        gtk_label_set_markup(GTK_LABEL (label2), speed);
        gtk_text_buffer_set_text (buffer1, speed, -1);
      }
    }

    pcap_close(device); 
}

static void func_start (GtkWidget *wid, GtkWidget *win)
{
  pthread_t id;
  int ret;
  flag = TRUE;
  ret = pthread_create(&id,NULL,(void *) thread,NULL);
  if (ret != 0) {
    printf("Create pthread failed!\n");
  }
}

void a() {
  gtk_label_set_text(GTK_LABEL (label1), "dac");
}

static void func_stop (GtkWidget *wid, GtkWidget *win)
{
  flag = FALSE;
}

int main (int argc, char *argv[])
{
  GtkWidget *button = NULL;
  GtkWidget *win = NULL;
  GtkWidget *vbox = NULL;

  /* Initialize GTK+ *///初始化GTK+ 的代码，这三行代码不要动就可以，自己的代码在下面写
  g_log_set_handler ("Gtk", G_LOG_LEVEL_WARNING, (GLogFunc) gtk_false, NULL);
  gtk_init (&argc, &argv);
  g_log_set_handler ("Gtk", G_LOG_LEVEL_WARNING, g_log_default_handler, NULL);

  /* Create the main window */
  win = gtk_window_new (GTK_WINDOW_TOPLEVEL);//new出来一个主窗口
  gtk_container_set_border_width (GTK_CONTAINER (win), 8);//设置窗口边缘的大小
  gtk_window_set_title (GTK_WINDOW (win), "RaptorQ_receive");//设置窗口标题
  gtk_window_set_position (GTK_WINDOW (win), GTK_WIN_POS_CENTER);//设置窗口位置
  gtk_widget_realize (win);//实现上述窗口
  g_signal_connect (win, "destroy", gtk_main_quit, NULL);//窗口信号连接，点击关闭按钮是会关闭窗口。

  /* Create a vertical box with buttons */
  vbox = gtk_vbox_new (TRUE, 6);//创建一个Vbox容器
  gtk_container_add (GTK_CONTAINER (win), vbox);//将创建的容器添加到上述创建的主窗口中

  button = gtk_button_new_from_stock ("Start");//创建一个按钮
  g_signal_connect (G_OBJECT (button), "clicked", G_CALLBACK (func_start), (gpointer) win);//设置按钮的回调函数，看到callback大家都应该懂这个是回调函数的。
  gtk_box_pack_start (GTK_BOX (vbox), button, TRUE, TRUE, 0);//将创建的按钮添加到上述的vbox中
//下面创建关闭按钮，并将关闭按钮的回调函数设置为系统的推出函数gtk_main_quit。
  button = gtk_button_new_from_stock ("Stop");
  g_signal_connect (button, "clicked", G_CALLBACK (func_stop), (gpointer) win);
  gtk_box_pack_start (GTK_BOX (vbox), button, TRUE, TRUE, 0);

  label1 = gtk_text_view_new();
  buffer1 = gtk_text_view_get_buffer(GTK_TEXT_VIEW (label1));
  gtk_box_pack_start (GTK_BOX (vbox), label1, FALSE, FALSE, 15);
  label2 = gtk_label_new("0KB/s");
  gtk_box_pack_start (GTK_BOX (vbox), label2, FALSE, FALSE, 15);
  

  /* Enter the main loop */
  gtk_widget_show_all (win);//显示上述的创建的界面
  gtk_main ();//开始整个主循环。
  return 0;
}