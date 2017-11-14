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
#include <unistd.h>
#include <arpa/inet.h>    
#include <libnet.h>
#include <pcap.h>  
#include <stdio.h>  
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
using namespace std;
using namespace cv;

#define PORT 233
#define MAXNUM 9999

// Demonstration of how to use the C++ interface
// it's pretty simple, we generate some input,
// then encode, drop some packets (source and repair)
// and finally decode everything.


uint8_t wrapper(u_char * payload, u_long payload_s);
void my_callback(u_char *userless, const struct pcap_pkthdr *pkthdr, 
                    const u_char *packet)
{
    u_char *data;
    u_int L = (pkthdr->len - sizeof(struct ether_header) - sizeof(struct iphdr)- sizeof(struct udphdr))/2;
    data = (u_char*)(packet+L+sizeof(struct ether_header)+sizeof(struct iphdr)
                                    +sizeof(struct udphdr));
    memcpy(userless, data, L*sizeof(u_char));
}
// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (uint64_t obj_num, std::vector<in_enc_align> myvec, mt19937_64 &rnd, float drop_prob,
														const uint8_t overhead);
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (uint64_t obj_num, std::vector<in_enc_align> myvec, mt19937_64 &rnd, float drop_prob,
														const uint8_t overhead)
{
	// define the alignment of the input and output data, for
	// decoder and encoder.
	// note that this is independent from the "mysize" argument,
	// which is always in bytes.
	// used as template arguments
	//typedef uint8_t			in_enc_align;
	//typedef uint16_t			out_enc_align;
	typedef out_enc_align	in_dec_align;
	//typedef uint32_t			out_dec_align;
	// NOTE:  out_enc_align is the same as in_dec_align so that we
	// can simulate data trnsmision just by passing along a vector, but
	// they do not need to be the same.

	//std::vector<in_enc_align> myvec;
	const uint32_t mysize = myvec.size();
	u_char *buff;
	buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));

	// std::pair<symbol id (esi), symbol>
	std::vector<std::pair<uint32_t, std::vector<out_enc_align>>> encoded;

	// symbol and sub-symbol sizes
	// sub symbol must be multiple of alignment,
	// symbol must be multiple of subsymbol
	//std::uniform_int_distribution<uint16_t> sub_sym_distr (1, 16);
	//const uint16_t subsymbol = sizeof(in_enc_align) * sub_sym_distr(rnd);
	//std::uniform_int_distribution<uint16_t> sym_distr (1, 100);
	//const uint16_t symbol_size = subsymbol * sym_distr (rnd);
	const uint16_t subsymbol = sizeof(in_enc_align) * 8;	/*** speed ***/
	const uint16_t symbol_size = subsymbol * 88;	/*** speed ***/
	size_t aligned_symbol_size = static_cast<size_t> (
		std::ceil(static_cast<float> (symbol_size) / sizeof(out_enc_align)));
	// udp max 1472 bytes, -id4B, 1468/4=367/2
	std::cout << "Subsymbol: " << subsymbol << " Symbol: " << symbol_size
		<< "aligned_symbol_size: "<<aligned_symbol_size<< "\n";
	auto enc_it = myvec.begin();

	//std::uniform_int_distribution<uint32_t> mem_distr (100, 200000);
	//RaptorQ::Encoder<typename std::vector<in_enc_align>::iterator,
	//						typename std::vector<out_enc_align>::iterator> enc (
	//			enc_it, myvec.end(), subsymbol, symbol_size, mem_distr(rnd));
	RaptorQ::Encoder<typename std::vector<in_enc_align>::iterator,
							typename std::vector<out_enc_align>::iterator> enc (
				enc_it, myvec.end(), subsymbol, symbol_size, 1000);	/*** speed ***/

	std::cout << "Size: " << mysize << " Blocks: " <<
									static_cast<int32_t>(enc.blocks()) << "\n";
	if (!enc) {
		std::cout << "Coud not initialize encoder.\n";
		return false;
	}

	enc.precompute(1, false);

	if (drop_prob > static_cast<float>(90.0))
		drop_prob = 90.0;	// this is still too high probably.
	std::uniform_real_distribution<float> drop (0.0, 100.0);

	int32_t repair;

	uint32_t oti_scheme = enc.OTI_Scheme_Specific();
	uint64_t oti_common = enc.OTI_Common();
	u_long pointer = 0;
	memcpy(buff, "OTI", sizeof(uint32_t));
	pointer += sizeof(uint32_t);
	memcpy(buff+pointer, &obj_num, sizeof(uint64_t));
	pointer += sizeof(uint64_t);
	memcpy(buff+pointer, &oti_scheme, sizeof(oti_scheme));
	pointer += sizeof(oti_scheme);
	memcpy(buff+pointer, &oti_common, sizeof(oti_common));
	pointer += sizeof(oti_common);
	wrapper((u_char*)buff, pointer);
	cout << "oti_scheme" << oti_scheme << endl;
	cout << "oti_common" << oti_common << endl;


	// start encoding
	int32_t blockid = -1;
	for (auto block : enc) {
		repair = overhead;
		++blockid;
		std::cout << "Block " << blockid << " with " << block.symbols() <<
																" symbols\n";
		// Now get the source and repair symbols.
		// make sure that at the end we end with "block.symbols() + overhead"
		// symbols, so that decoding is possible
		for (auto sym_it = block.begin_source(); sym_it != block.end_source();
																	++sym_it) {
			float dropped = drop (rnd);
			if (dropped <= drop_prob) {
				// we dropped one source symbol, we need one more repair.
				++repair;
				continue;
			}
			// create a place where to save our source symbol
			std::vector<out_enc_align> source_sym;
			source_sym.reserve (aligned_symbol_size);
			source_sym.insert (source_sym.begin(), aligned_symbol_size, 0);
			auto it = source_sym.begin();
			// save the symbol
			auto written = (*sym_it) (it, source_sym.end());
			if (written != aligned_symbol_size) {
				std::cout << written << "-vs-" << aligned_symbol_size <<
									" Could not get the whole source symbol!\n";
				return false;
			}
			// finally add it to the encoded vector
			//uint32_t pac_size = sizeof((*sym_it).id()) + aligned_symbol_size*out_enc_align;
			uint32_t pac_size_1 = sizeof((*sym_it).id()); // 4
			uint32_t id = (*sym_it).id();
			uint32_t pac_size_2 = aligned_symbol_size * sizeof(out_enc_align); // 1600
			uint32_t pac_size = pac_size_1 + pac_size_2;
			cout << pac_size << ' ' << pac_size_1 << ' ' << pac_size_2 << endl;
			memcpy(buff, &id, pac_size_1);
			u_long pointer = pac_size_1;
			for (uint32_t i = 0; i < aligned_symbol_size; ++i){
				memcpy(buff+pointer, &source_sym[i], sizeof(out_enc_align));
				//uint32_t x;
				//memcpy(&x, pointer, sizeof(out_enc_align));
				pointer += sizeof(out_enc_align);
				//cout << "source_sym["<<i<<"]:"<<source_sym[i]<<' '<<x<<endl;
			}
			encoded.emplace_back ((*sym_it).id(), std::move(source_sym));
			wrapper((u_char*)buff, pac_size);
			cout << encoded.size()-1<<' '<< encoded[encoded.size()-1].first << ' ' << encoded[encoded.size()-1].second[0]
			<< ' '<< aligned_symbol_size<<' '  <<encoded[encoded.size()-1].second[aligned_symbol_size-1]<< endl;
			//cout << get<0>(encoded[encoded.size()-1]) <<'\t'<< sizeof(encoded[encoded.size()-1]) << endl;

		}
		// now get (overhead + source_symbol_lost) repair symbols.
		std::cout << "Source Packet lost: " << repair - overhead << "\n";
		auto sym_it = block.begin_repair();
		for (; repair >= 0 && sym_it != block.end_repair (block.max_repair()); ++sym_it) {
		//for (; sym_it != block.end_repair (block.max_repair()); ++sym_it) {
			// repair symbols can be lost, too!
			float dropped = drop (rnd);
			if (dropped <= drop_prob) {
				continue;
			}
			--repair;
			// create a place where to save our source symbol
			std::vector<out_enc_align> repair_sym;
			repair_sym.reserve (aligned_symbol_size);
			repair_sym.insert (repair_sym.begin(), aligned_symbol_size, 0);
			auto it = repair_sym.begin();
			// save the repair symbol
			auto written = (*sym_it) (it, repair_sym.end());
			if (written != aligned_symbol_size) {
				std::cout << written << "-vs-" << aligned_symbol_size <<
									" bCould not get the whole repair symbol!\n";
				return false;
			}
			// finally add it to the encoded vector
			uint32_t pac_size_1 = sizeof((*sym_it).id()); // 4
			uint32_t id = (*sym_it).id();
			uint32_t pac_size_2 = aligned_symbol_size * sizeof(out_enc_align); // 1600
			uint32_t pac_size = pac_size_1 + pac_size_2;
			//cout << pac_size << ' ' << pac_size_1 << ' ' << pac_size_2 << endl;
			
			memcpy(buff, &id, pac_size_1);
			u_long pointer = pac_size_1;
			for (uint32_t i = 0; i < aligned_symbol_size; ++i){
				memcpy(buff+pointer, &repair_sym[i], sizeof(out_enc_align));
				pointer += sizeof(out_enc_align);
			}
			encoded.emplace_back ((*sym_it).id(), std::move(repair_sym));
			wrapper((u_char*)buff, pac_size);
			cout << encoded.size()-1<<' '<< encoded[encoded.size()-1].first << ' ' << encoded[encoded.size()-1].second[0]
			<< ' '<< aligned_symbol_size<<' ' <<encoded[encoded.size()-1].second[aligned_symbol_size-1]<< endl;


			//encoded.emplace_back ((*sym_it).id(), std::move(repair_sym));
		}
		if (sym_it == block.end_repair (block.max_repair())) {
			// we dropped waaaay too many symbols! how much are you planning to
			// lose, again???
			std::cout << "Maybe losing " << drop_prob << "% is too much?\n";
			return false;
		}
	}
	

	// encoding done. now "encoded" is the vector with the trnasmitted data.
	//decode<in_enc_align, out_enc_align, out_dec_align>(encoded, oti_common, oti_scheme, mysize);

	return true;
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

int main (int argc, char** argv)
{
	// get a random number generator
	std::mt19937_64 rnd;
	std::ifstream rand("/dev/random");
	uint64_t seed = 0;
	rand.read (reinterpret_cast<char *> (&seed), sizeof(seed));
	rand.close ();
	rnd.seed (seed);

	std::uniform_int_distribution<uint32_t> distr(1, 10000);

	
	char filename[20];
	strcpy(filename, "./image_send/test.jpg");
	Mat frame, frame_bgr[3];
	frame = imread(filename);
	if (frame.empty()) {
		printf("Could not load image\n");
		exit(0);
	}
	split(frame, frame_bgr);

	uint32_t frame_row = frame.rows;
	uint32_t frame_col = frame.cols;
	uint32_t frame_chan = frame.channels();
	uint32_t frame_size = frame_row * frame_col * frame_chan;
	printf("row:%i\tcol:%i\n", frame.rows, frame.cols);
	cout << "mat_size:" << frame.size() << endl;
	cout << "mat_type:" << frame.type() << endl;
	cout << "mat_total:" << frame.total() << endl;
	cout << "mat_elemSize:" << frame.elemSize() << endl;
	cout << "mat_depth:" << frame.depth() << endl;
	cout << "mat_channels:" << frame.channels() << endl;
	/* (1) */
	//uint8_t *mat_vec;
	//mat_vec = (uint8_t*) malloc(frame_size*sizeof(uint8_t));
	/* (1.1) */
	//mat_vec=(uint32_t*)(frame.data);
	/* (1.2) */
	//memcpy(mat_vec, frame.data, frame_size*sizeof(uint8_t));
	//Mat frame_covert(frame_row, frame_col, CV_8UC3, mat_vec);

	/* (2) */
	
	std::vector<uint8_t> mat_vec;
	if (frame.isContinuous()) {
		mat_vec.assign(frame.datastart, frame.dataend);
	} else {
		for (int i = 0; i < frame.rows; ++i) {
			mat_vec.insert(mat_vec.end(), frame.ptr<uint8_t>(i), frame.ptr<uint8_t>(i)+frame.cols);
		}
	}
	Mat frame_covert = Mat(frame_row, frame_col, CV_8UC3);
	/* (3) */
	/*
	std::vector<uint8_t> mat_vec;
	if (frame_bgr[0].isContinuous()) {
		mat_vec.assign(frame_bgr[0].datastart, frame_bgr[0].dataend);
	} else {
		for (int i = 0; i < frame_bgr[0].rows; ++i) {
			mat_vec.insert(mat_vec.end(), frame_bgr[0].ptr<uint8_t>(i), frame_bgr[0].ptr<uint8_t>(i)+frame_bgr[0].cols);
		}
	}
	Mat frame_covert = Mat(frame_row, frame_col, CV_8UC1);*/
	
	memcpy(frame_covert.data, mat_vec.data(), mat_vec.size()*sizeof(uint8_t));
	cout << "mat_vec.size: " << mat_vec.size() << endl;
	//imshow("frame_covert", frame_covert);
	//waitKey(500);

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
  	u_char *buff;
	buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));

	// encode and decode
	for (uint64_t i = 3; i < 21; ++i) {
		sprintf(filename, "./image_send/%d.jpg", i);
		cout << filename << endl;
		Mat frame;
		frame = imread(filename);
		if (frame.empty()) {
			printf("Could not load image\n");
			exit(0);
		}
		if (frame.isContinuous()) {
			mat_vec.assign(frame.datastart, frame.dataend);
		} else {
			for (int i = 0; i < frame.rows; ++i) {
				mat_vec.insert(mat_vec.end(), frame.ptr<uint8_t>(i), frame.ptr<uint8_t>(i)+frame.cols);
			}
		}

		bool ret;
		clock_t s_all, t_all;
		s_all = clock();
		time_t seconds;  
		seconds = time((time_t *)NULL); 
		ret = encode<uint8_t, uint32_t, uint8_t> (i, mat_vec, rnd, 10.0, 4);
		//ret = encode<uint8_t, uint32_t, uint8_t> (mat_vec.size()/3, rnd, 10.0, 4);
		if (!ret)
			return -1;
		cout <<time((time_t *)NULL) - seconds << endl;
		t_all = clock();
    	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    	cout << duration << endl;
    	cout << "Wait for ack..." << endl;
    	pcap_loop(device, 1, my_callback, (u_char *)buff);
    	while (!(buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K'))
    		pcap_loop(device, 1, my_callback, (u_char *)buff);
	}
	std::cout << "All tests succesfull!\n";
	return 0;
}
