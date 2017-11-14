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

#define SERVICE_PORT    21234
#define MAXNUM 9999
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

int obj_num;
uint8_t *cur_ptr;
int cur_size;


// mysize is bytes.
// 0 failed, 1 success, -1 end
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
int decode (FILE *fp_out, int fd, struct sockaddr_in remaddr, float drop_prob);

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
int decode (FILE *fp_out, int fd, struct sockaddr_in remaddr, float drop_prob)
{
	u_char *buff;
	buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));
	int recvlen;
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
    //float drop_prob = 0.95;

	uint32_t oti_scheme;
	uint64_t oti_common;
	//uint64_t obj_num;
	cout << "Wait for oti..." << endl;
	//pcap_loop(device, 1, my_callback, (u_char *)buff);
    recvlen = recvfrom(fd, buff, 8 * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, &addrlen);
	while (!(buff[0]=='O'&&buff[1]=='T'&&buff[2]=='I')) {
        if (buff[0]=='E'&&buff[1]=='N'&&buff[2]=='D')
            return -1;
        cout << "No oti. Wait for oti..." << endl;
        u_char payload[] = "ACK";
        memcpy(payload+sizeof(uint32_t), &obj_num, sizeof(int));
        //wrapper(payload, sizeof(uint32_t)+sizeof(uint64_t));
		//pcap_loop(device, 1, my_callback, (u_char *)buff);
        recvlen = recvfrom(fd, buff, 8 * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, &addrlen);
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
    uint32_t pac_size = aligned_symbol_size*sizeof(out_enc_align)+sizeof(uint32_t);
    int err_add = 0;
	//while (decoded * sizeof(out_dec_align) < mysize) {
    
    
    while(pac_num<K) {
		// receive
		std::vector<out_enc_align> source_sym;
		source_sym.reserve (aligned_symbol_size);
		source_sym.insert (source_sym.begin(), aligned_symbol_size, 0);
		//pcap_loop(device, 1, my_callback, (u_char *)buff);
        float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
        if (dropped < drop_prob) {
            cout << "Force to drop this packet" << endl;
            continue;
        }
        //free(buff);
        //buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));
        //memcpy(buff, "fzsdf", sizeof("fzsdf"));
        recvlen = recvfrom(fd, buff, pac_size,
             0, (struct sockaddr *)&remaddr, &addrlen);
        //cout<<recvlen<<endl<<"buff"<<buff;
        /*FILE *fp_buff;
    char file_buff[]="receive_buff.txt";
    fp_buff = fopen(file_buff, "wb");
    if (!fp_buff) {
        printf("Could not open %s\n", file_buff);
        return -1;
    }
        cout<<buff<<endl;fwrite(buff,1,5,fp_buff);
        cout<<"hagsjhgdjhdshdhsghdghsgdhsgdhsgdhshgd"<<pac_size;return 0;*/
		uint32_t id;
		memcpy(&id, buff, sizeof(uint32_t));
		u_long pointer = sizeof(uint32_t);
		for (uint32_t i=0; i < aligned_symbol_size;++i) {
			memcpy(&source_sym[i], buff+pointer, sizeof(out_enc_align));
			uint32_t x;
			memcpy(&x, buff+pointer, sizeof(out_enc_align));
			pointer += sizeof(out_enc_align);
		}
        //cout << "source_sym[0]:" <<source_sym[0] << " source_sym["<<aligned_symbol_size-1<<"]:"<<source_sym[aligned_symbol_size-1]<<endl;
		// add symbol
		auto it = source_sym.begin();
		if (!dec.add_symbol (it, source_sym.end(), id)) {
			std::cout << "error adding?\n";
            err_add += 1;
            if (err_add > 5)
                return 0;
        }
		else
			pac_num += 1;
		cout << "Need more symbols\n";
        /*
        if (time((time_t *)NULL)-beg>1) {
            cout<<"Time too long, skip this object\n";
            return true;
        }*/
		// decode
		//re_it = received.begin();
		//decoded=dec.decode(re_it, received.end());
	}
    re_it = received.begin();
    decoded=dec.decode(re_it, received.end());
    if (decoded * sizeof(out_dec_align) < mysize)
        return 0;
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
    
	return 1;
}

int main(int argc, char* argv[]) {
    // time
	clock_t s_all, t_all;
	s_all = clock();
	time_t seconds;  
	seconds = time((time_t *)NULL); 
    float drop_prob=0;
    if (argc == 2) {
        drop_prob = atof(argv[1]);
    }

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

    // socket
	struct sockaddr_in myaddr; /* our address */
    struct sockaddr_in remaddr; /* remote address */
    socklen_t addrlen = sizeof(remaddr);        /* length of addresses */
    int recvlen;            /* # bytes received */
    int fd;             /* our socket */
    /* create a UDP socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("cannot create socket\n");
        return 0;
    }
    /* bind the socket to any valid IP address and a specific port */
    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(SERVICE_PORT);
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        perror("bind failed");
        return 0;
    }

  	ret = 1;
    obj_num = -1;
  	while (ret != -1) {
        u_char payload[] = "ACK";
        memcpy(payload+sizeof(uint32_t), &obj_num, sizeof(int));
        //wrapper(payload, sizeof(uint32_t)+sizeof(int));
  		ret = decode<uint8_t, uint32_t, uint8_t> (fp_out, fd, remaddr, drop_prob);
        if (ret == 0)
            continue;
  		
        // ffmpeg
        if (cur_size == 0) {
            cout << "cur_size: 0" << endl;
            continue;
        }
        obj_num++;
        while (cur_size>0){
            int len = av_parser_parse2(
                pCodecParserCtx, pCodecCtx,
                &packet.data, &packet.size,
                cur_ptr , cur_size ,
                AV_NOPTS_VALUE, AV_NOPTS_VALUE, AV_NOPTS_VALUE);
            printf("pCodec: %d %d\n", pCodecCtx->width, pCodecCtx->height);
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
                //obj_num++;
                //cout << "obj_num: "<<obj_num<<endl;
                /*sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameYUV->data, pFrameYUV->linesize);

                fwrite(pFrameYUV->data[0],1,y_size,fp_out);     //Y 
                fwrite(pFrameYUV->data[1],1,y_size/4,fp_out);   //U
                fwrite(pFrameYUV->data[2],1,y_size/4,fp_out);   //V*/
                //sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                   // pFrameRGB->data, pFrameRGB->linesize);
                //Mat *testout;//= Mat(pCodecCtx->width, pCodecCtx->height, CV_8UC3);
                //memcpy(testout->data, out_bufferRGB,sizeout);
                /*imshow("testout", *testout);
                waitKey(40);*/
                sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameRGB->data, pFrameRGB->linesize);
                Mat testout = Mat(pCodecCtx->height, pCodecCtx->width, CV_8UC3);
                memcpy(testout.data, out_bufferRGB,sizeout);
                imshow("testout", testout);
                char filename[20];
                sprintf(filename, "video/im/%d.jpg", obj_num);
                imwrite(filename, testout);
                waitKey(8);
            }
        }
    }
    
    packet.data = NULL;
    packet.size = 0;
    while(1){
        ret = avcodec_decode_video2(pCodecCtx, pFrame, &got_picture, &packet);
        if (ret < 0) {
            printf("Decode Error.\n");
            return ret;
        }
        if (!got_picture)
            break;
        if (got_picture) {
            printf("Flush Decoder: Succeed to decode 1 frame!\n");
            /*sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                pFrameYUV->data, pFrameYUV->linesize);

            fwrite(pFrameYUV->data[0],1,y_size,fp_out);     //Y
            fwrite(pFrameYUV->data[1],1,y_size/4,fp_out);   //U
            fwrite(pFrameYUV->data[2],1,y_size/4,fp_out);   //V*/
            sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameRGB->data, pFrameRGB->linesize);
                //Mat testout = Mat(pCodecCtx->height, pCodecCtx->width, CV_8UC3);
                //memcpy(testout.data, out_bufferRGB,sizeout);
                //imshow("testout", testout);
                waitKey(40);
                //pCodecCtx->width*pCodecCtx->height*3
        }
    }
    
  	fclose(fp_out);
  	cout <<time((time_t *)NULL) - seconds << endl;
	t_all = clock();
	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
	cout << duration << endl;
  	return 0;
}