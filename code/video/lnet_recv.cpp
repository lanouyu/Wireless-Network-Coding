/*
 * Copyright (c) 2015, Luca Fulchir<luker@fenrirproject.org>, All rights reserved.
 *
 * This file is part of "libRaptorQ".
 *
 * libRaptorQ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation, either version 3
 * of the License, or (at your option) any later version.
 *
 * libRaptorQ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * and a copy of the GNU Lesser General Public License
 * along with libRaptorQ.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <fstream>
#include <iostream>
#include <random>
#include "../src/RaptorQ.hpp"
#include <vector>
#include <time.h>
#include <opencv2/opencv.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/videoio.hpp>
 /************socket*********/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pcap.h>  
#include <stdio.h>  
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <libnet.h>

using namespace std;
using namespace cv;

#define PORT 233
#define MAXNUM 9999

// Demonstration of how to use the C++ interface
// it's pretty simple, we generate some input,
// then encode, drop some packets (source and repair)
// and finally decode everything.

/***********************callback function get packet**********************/
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr, 
                    const u_char *packet)
{
    u_char *data;
    u_int L = (pkthdr->len - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr))/2;
    data = (u_char*)(packet+L+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct udphdr));
    memcpy(userless, data, L*sizeof(u_char));
}

uint8_t wrapper(u_char * payload, u_long payload_s){
	libnet_t *handle; /* Libnet句柄 */
	char *device = "ens33"; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    char *src_ip_str = "192.168.141.143"; /* 源IP地址字符串 */
    char *dst_ip_str = "192.168.255.255"; /* 目的IP地址字符串 */
    u_char src_mac[6] = {0x00, 0x0c, 0x29, 0x4b, 0x99, 0xe6}; /* 源MAC */
    u_char dst_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}; /* 目的MAC */
    u_long dst_ip, src_ip; /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE]; /* 出错信息 */
    libnet_ptag_t eth_tag, ip_tag, udp_tag; /* 各层build函数返回值 */
    u_short proto = IPPROTO_UDP; /* 传输层协议 */
    int packet_size; /* 构造的数据包大小 */
    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

    /* 初始化Libnet */
    if ( (handle = libnet_init(LIBNET_LINK, device, error)) == NULL ) {
    	printf("libnet_init failure\n");
        return (-1);
    };

    /* 构造UDP协议块 */
	udp_tag = libnet_build_udp(30330, 30331, LIBNET_UDP_H + payload_s, 0, payload, payload_s, handle, 0);
    if (udp_tag == -1) {
        printf("libnet_build_tcp failure\n");
        return (-3);
    };

    /* 构造IP协议块，返回值是新生成的IP协议快的一个标记 */
    ip_tag = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + payload_s, 0, 
    							(u_short) libnet_get_prand(LIBNET_PRu16), 0, 
    							(u_int8_t)libnet_get_prand(LIBNET_PR8), proto,  0, 
    							src_ip, dst_ip, payload, payload_s, handle, 0);
    if (ip_tag == -1) {
        printf("libnet_build_ipv4 failure\n");
        return (-4);
    };

 	/* 构造一个以太网协议块,只能用于LIBNET_LINK */
    eth_tag = libnet_build_ethernet(dst_mac, src_mac, ETHERTYPE_IP, NULL, 0, handle, 0);
    if (eth_tag == -1) {
        printf("libnet_build_ethernet failure\n");
        return (-5);
    };
 
 	/* 发送已经构造的数据包*/
    packet_size = libnet_write(handle); 
    if (packet_size == -1) {
        printf("write error:%s\n", libnet_geterror(handle));
        cout << payload_s<<endl;
    }
    else { 
        printf("wrote %d byte UDP packet\n",packet_size);
    }

    /* 释放句柄 */ 
    libnet_destroy(handle);  
}

// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (pcap_t * device, const uint32_t mysize);

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (pcap_t * device, const uint32_t mysize)
{
	u_char *buff;
	buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));
	int recvlen;
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */

	uint32_t oti_scheme;
	uint64_t oti_common;
	uint64_t obj_num;
	cout << "Wait for oti..." << endl;
	pcap_loop(device, 1, my_callback, (u_char *)buff);
	while (!(buff[0]=='O'&&buff[1]=='T'&&buff[2]=='I'))
		pcap_loop(device, 1, my_callback, (u_char *)buff);

	u_long pointer = sizeof(uint32_t);
	memcpy(&obj_num, buff+pointer, sizeof(obj_num));
	pointer += sizeof(obj_num);
	memcpy(&oti_scheme, buff+pointer, sizeof(oti_scheme));
	pointer += sizeof(oti_scheme);
	memcpy(&oti_common, buff+pointer, sizeof(oti_common));
	cout << "oti_scheme" << oti_scheme << endl;
	cout << "oti_common" << oti_common << endl;


	uint64_t F = oti_common >> 24; // transfer length
	uint64_t T = (oti_common << 48) >> 48; // symbol size
	uint64_t K = (F / T) + 1; // symbol number
	cout << "F: "<<F<< " T: "<<T<< " K: "<<K<<endl;
	typedef out_enc_align	in_dec_align;
	size_t aligned_symbol_size = static_cast<size_t> (
		std::ceil(static_cast<float> (T) / sizeof(out_enc_align)));
	uint32_t pac_size=aligned_symbol_size*sizeof(out_enc_align)+sizeof(uint32_t);
	
	// let's decode it
	RaptorQ::Decoder<typename std::vector<in_dec_align>::iterator,
							typename std::vector<out_dec_align>::iterator>
												dec (oti_common, oti_scheme);
	std::vector<out_dec_align> received;
	size_t out_size = static_cast<size_t> (
				std::ceil(static_cast<float>(mysize) / sizeof(out_dec_align)));
	received.reserve (out_size);
	// make sure that there's enough place in "received" to get the
	// whole decoded data.
	for (uint32_t i = 0; i < out_size; ++i)
		received.push_back (static_cast<out_dec_align> (0));
	auto re_it = received.begin();
	auto decoded = dec.decode(re_it, received.end());
	uint32_t pac_num = 0;
	while (decoded * sizeof(out_dec_align) < mysize) {
		// receive
		std::vector<out_enc_align> source_sym;
		source_sym.reserve (aligned_symbol_size);
		source_sym.insert (source_sym.begin(), aligned_symbol_size, 0);
		pcap_loop(device, 1, my_callback, (u_char *)buff);
		uint32_t id;
		memcpy(&id, buff, sizeof(uint32_t));
		u_long pointer = sizeof(uint32_t);
		for (uint32_t i=0; i < aligned_symbol_size;++i) {
			memcpy(&source_sym[i], buff+pointer, sizeof(out_enc_align));
			uint32_t x;
			memcpy(&x, buff+pointer, sizeof(out_enc_align));
			pointer += sizeof(out_enc_align);
		}
		// add symbol
		auto it = source_sym.begin();
		if (!dec.add_symbol (it, source_sym.end(), id))
			std::cout << "error adding?\n";
		else
			pac_num += 1;
		cout << "Need more symbols\n";
		// decode
		re_it = received.begin();
		decoded=dec.decode(re_it, received.end());
	}
	std::cout << "Decoded: " << mysize << "\n";

	Mat frame_received = Mat(480, 640, CV_8UC3);
	memcpy(frame_received.data, received.data(), received.size()*sizeof(uint8_t));
	cout << "received.size: " << received.size() << endl;
	char filename[20];
	sprintf(filename, "./image_recv/%d.jpg", obj_num);
	imwrite(filename,frame_received);  
	imshow("frame_received", frame_received);
	//waitKey(5000);

	return true;
}

int main (void)
{
	// get a random number generator
	std::mt19937_64 rnd;
	std::ifstream rand("/dev/random");
	uint64_t seed = 0;
	rand.read (reinterpret_cast<char *> (&seed), sizeof(seed));
	rand.close ();
	rnd.seed (seed);

	std::uniform_int_distribution<uint32_t> distr(1, 10000);

	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
	/* get a device */  
    devStr = pcap_lookupdev(errBuf);  
    if(devStr) {  
    	printf("success: device: %s\n", devStr);  
    }  
    else {  
	    printf("error: %s\n", errBuf);  
	    exit(1);  
    }  
    /* open a device, wait until a packet arrives */  
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);   
    if(!device) {  
      printf("error: pcap_open_live(): %s\n", errBuf);  
      exit(1);  
    }
  	/* construct a filter */
  	struct bpf_program filter; 
  	//pcap_compile(device, &filter, "udp", 1, 0); 
  	pcap_compile(device, &filter, "src host 192.168.141.143", 1, 0); 
  	pcap_setfilter(device, &filter);

	// encode and decode
	for (size_t i = 0; i < 1000; ++i) {
		bool ret;
		clock_t s_all, t_all;
		s_all = clock();
		time_t seconds;  
		seconds = time((time_t *)NULL); 
		ret = decode<uint8_t, uint32_t, uint8_t> (device, 480*640*3);
		//ret = encode<uint8_t, uint32_t, uint8_t> (mat_vec.size()/3, rnd, 10.0, 4);
		if (!ret)
			return -1;
		cout <<time((time_t *)NULL) - seconds << endl;
		t_all = clock();
    	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    	cout << duration << endl;
    	u_char payload[] = "ACK";
		wrapper(payload, sizeof(uint32_t));

	}
	std::cout << "All tests succesfull!\n";
	return 0;
}
