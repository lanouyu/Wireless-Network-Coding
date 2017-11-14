#include <stdio.h>
#include <fstream>
#include <iostream>
#include <random>
#include "../src/RaptorQ.hpp"
#include <vector>
#include <time.h>
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
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <opencv2/opencv.hpp>
using namespace cv;
using namespace std;

#define __STDC_CONSTANT_MACROS

#ifdef _WIN32
//Windows
extern "C"
{
#include "libavcodec/avcodec.h"
#include "libswscale/swscale.h"
};
#else
//Linux...
#ifdef __cplusplus
extern "C"
{
#endif
#include <libavcodec/avcodec.h>
#include <libswscale/swscale.h>
#ifdef __cplusplus
};
#endif
#endif

//test different codec
#define TEST_H264  1
#define TEST_HEVC  0
#define MAXNUM 999

int obj_num;
uint8_t *cur_ptr;
int cur_size;

int recv(FILE *fp_out, std::vector<uint8_t> vec_data) {
    uint8_t *write_buff;
    write_buff = (uint8_t*) malloc(vec_data.size() * sizeof(uint8_t));
    uint32_t pointer = 0;
    for (int i=0; i<vec_data.size(); ++i){
        memcpy(write_buff+pointer, &vec_data[i], sizeof(uint8_t));
        pointer += sizeof(uint8_t);
    }
    fwrite(write_buff, 1, pointer, fp_out);
}

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
bool decode (FILE *fp_out, pcap_t * device);

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (FILE *fp_out, pcap_t * device)
{
	u_char *buff;
	buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));
	int recvlen;
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */

	uint32_t oti_scheme;
	uint64_t oti_common;
	//uint64_t obj_num;
	cout << "Wait for oti..." << endl;
	pcap_loop(device, 1, my_callback, (u_char *)buff);
	while (!(buff[0]=='O'&&buff[1]=='T'&&buff[2]=='I')) {
        if (buff[0]=='E'&&buff[1]=='N'&&buff[2]=='D')
            return false;
        cout << "No oti. Wait for oti..." << endl;
        u_char payload[] = "ACK";
        memcpy(payload+sizeof(uint32_t), &obj_num, sizeof(int));
        //wrapper(payload, sizeof(uint32_t)+sizeof(uint64_t));
		pcap_loop(device, 1, my_callback, (u_char *)buff);
    }

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
	uint32_t mysize = F;
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
    time_t beg;  
    beg = time((time_t *)NULL); 
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
        if (time((time_t *)NULL)-beg>1) {
            cout<<"Time too long, skip this object\n";
            return true;
        }
		// decode
		re_it = received.begin();
		decoded=dec.decode(re_it, received.end());
	}
	std::cout << "Decoded: " << mysize << "\n";

	// write to file
	uint8_t *write_buff;
    write_buff = (uint8_t*) malloc(received.size() * sizeof(uint8_t));
    pointer = 0;
    for (int i=0; i<received.size(); ++i){
        memcpy(write_buff+pointer, &received[i], sizeof(uint8_t));
        pointer += sizeof(uint8_t);
    }
    //fwrite(write_buff, 1, pointer, fp_out);
    cur_size = pointer;
    cur_ptr = write_buff;
    
	return true;
}

int main() {
    // time
	clock_t s_all, t_all;
	s_all = clock();
	time_t seconds;  
	seconds = time((time_t *)NULL); 

    // ffmpeg
    AVCodec *pCodec;
    AVCodecContext *pCodecCtx= NULL;
    AVCodecParserContext *pCodecParserCtx=NULL;
    int frame_count;
    FILE *fp_in;
    FILE *fp_out;
    AVFrame *pFrame,*pFrameYUV;
    AVFrame *pFrameRGB = NULL;
    uint8_t *out_bufferRGB = NULL;
    uint8_t *out_buffer;
    const int in_buffer_size=4096;
    uint8_t in_buffer[in_buffer_size + FF_INPUT_BUFFER_PADDING_SIZE]={0};
    //uint8_t *cur_ptr;
    //int cur_size;
    AVPacket packet;
    int ret, got_picture;
    int y_size;
    int sizeout;
#if TEST_HEVC
    enum AVCodecID codec_id=AV_CODEC_ID_HEVC;
    char filepath_in[]="bigbuckbunny_480x272.hevc";
#elif TEST_H264
    AVCodecID codec_id=AV_CODEC_ID_H264;
    char filepath_in[]="bigbuckbunny_480x272.h264";
#else
    AVCodecID codec_id=AV_CODEC_ID_MPEG2VIDEO;
    char filepath_in[]="bigbuckbunny_480x272.m2v";
#endif
    char filepath_out[]="bigbuckbunny_480x272.yuv";
    int first_time=1;
    struct SwsContext *img_convert_ctx;
    avcodec_register_all();
    pCodec = avcodec_find_decoder(codec_id);
    if (!pCodec) {
        printf("Codec not found\n");
        return -1;
    }
    pCodecCtx = avcodec_alloc_context3(pCodec);
    if (!pCodecCtx){
        printf("Could not allocate video codec context\n");
        return -1;
    }
    pCodecParserCtx=av_parser_init(codec_id);
    if (!pCodecParserCtx){
        printf("Could not allocate video parser context\n");
        return -1;
    }
    if (avcodec_open2(pCodecCtx, pCodec, NULL) < 0) {
        printf("Could not open codec\n");
        return -1;
    }
    pFrame = av_frame_alloc();
    av_init_packet(&packet);
	/*FILE *fp_out;
	char filename_out[]="./video/receive.h264";
	fp_out = fopen(filename_out, "wb");
    if (!fp_out) {
        printf("Could not open %s\n", filename_out);
        return -1;
    }*/

    // libpcap
	char errBuf[PCAP_ERRBUF_SIZE], * devStr;
    devStr = pcap_lookupdev(errBuf);  
    if(devStr) {  
    	printf("success: device: %s\n", devStr);  
    }  
    else {  
	    printf("error: %s\n", errBuf);  
	    exit(1);  
    }  
    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);   
    if(!device) {  
      printf("error: pcap_open_live(): %s\n", errBuf);  
      exit(1);  
    }
  	struct bpf_program filter; 
  	pcap_compile(device, &filter, "src host 127.0.0.1", 1, 0); 
  	pcap_setfilter(device, &filter);

  	bool bret = true;
    obj_num = -1;
  	while (bret) {
        u_char payload[] = "ACK";
        memcpy(payload+sizeof(uint32_t), &obj_num, sizeof(int));
        //wrapper(payload, sizeof(uint32_t)+sizeof(int));
  		bret = decode<uint8_t, uint32_t, uint8_t> (fp_out, device);
  		
        // ffmpeg
        if (cur_size == 0) {
            cout << "cur_size: 0" << endl;
            break;
        }
        while (cur_size>0){
            int len = av_parser_parse2(
                pCodecParserCtx, pCodecCtx,
                &packet.data, &packet.size,
                cur_ptr , cur_size ,
                AV_NOPTS_VALUE, AV_NOPTS_VALUE, AV_NOPTS_VALUE);
            //printf("pCodec: %d %d\n", pCodecCtx->width, pCodecCtx->height);
            cur_ptr += len;
            cur_size -= len;
            if(packet.size==0)
                continue;
            //Some Info from AVCodecParserContext
            printf("Packet Size:%6d\t",packet.size);
            switch(pCodecParserCtx->pict_type){
                case AV_PICTURE_TYPE_I: printf("Type: I\t");break;
                case AV_PICTURE_TYPE_P: printf("Type: P\t");break;
                case AV_PICTURE_TYPE_B: printf("Type: B\t");break;
                default: printf("Type: Other\t");break;
            }
            printf("Output Number:%4d\t",pCodecParserCtx->output_picture_number);
            printf("Offset:%lld\n",pCodecParserCtx->cur_offset);

            ret = avcodec_decode_video2(pCodecCtx, pFrame, &got_picture, &packet);
            if (ret < 0) {
                printf("Decode Error.\n");
                return ret;
            }
            if (got_picture) {
                if(first_time){
                    printf("\nCodec Full Name:%s\n",pCodecCtx->codec->long_name);
                    printf("width:%d\nheight:%d\n\n",pCodecCtx->width,pCodecCtx->height);
                    //SwsContext
                    //img_convert_ctx = sws_getContext(pCodecCtx->width, pCodecCtx->height, pCodecCtx->pix_fmt, 
                    //  pCodecCtx->width, pCodecCtx->height, AV_PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL); 
                    img_convert_ctx = sws_getContext(pCodecCtx->width, pCodecCtx->height, pCodecCtx->pix_fmt, 
                        pCodecCtx->width, pCodecCtx->height, AV_PIX_FMT_BGR24, SWS_BICUBIC, NULL, NULL, NULL); 
                    
                    pFrameRGB=av_frame_alloc();
                    //pFrameYUV=av_frame_alloc();
                    //out_buffer=(uint8_t *)av_malloc(avpicture_get_size(AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height));
                    sizeout = avpicture_get_size(AV_PIX_FMT_BGR24, pCodecCtx->width, pCodecCtx->height);
                    out_bufferRGB=(uint8_t *)av_malloc(sizeout);
                    
                    //avpicture_fill((AVPicture *)pFrameYUV, out_buffer, AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height);
                    avpicture_fill((AVPicture *)pFrameRGB, out_bufferRGB, AV_PIX_FMT_BGR24, pCodecCtx->width, pCodecCtx->height);
                    
                    y_size=pCodecCtx->width*pCodecCtx->height;

                    first_time=0;
                }

                printf("Succeed to decode 1 frame!\n");
                /*sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameYUV->data, pFrameYUV->linesize);

                fwrite(pFrameYUV->data[0],1,y_size,fp_out);     //Y 
                fwrite(pFrameYUV->data[1],1,y_size/4,fp_out);   //U
                fwrite(pFrameYUV->data[2],1,y_size/4,fp_out);   //V*/
                sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameRGB->data, pFrameRGB->linesize);
                //Mat *testout;//= Mat(pCodecCtx->width, pCodecCtx->height, CV_8UC3);
                //memcpy(testout->data, out_bufferRGB,sizeout);
                /*imshow("testout", *testout);
                waitKey(40);*/
                sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameRGB->data, pFrameRGB->linesize);
                Mat testout = Mat(pCodecCtx->height, pCodecCtx->width, CV_8UC3);
                memcpy(testout.data, out_bufferRGB,sizeout);
                imshow("testout", testout);
                waitKey(40);
            }
        }
    }
  	fclose(fp_out);
  	cout <<time((time_t *)NULL) - seconds << endl;
	t_all = clock();
	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
	cout << duration << endl;
  	return 0;
}