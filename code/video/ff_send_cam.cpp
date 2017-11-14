/**
 * ×î¼òµ¥µÄ»ùÓÚFFmpegµÄÊÓÆµ±àÂëÆ÷£¨´¿¾»°æ£©
 * Simplest FFmpeg Video Encoder Pure
 * 
 * À×Ïöæè Lei Xiaohua
 * leixiaohua1020@126.com
 * ÖÐ¹ú´«Ã½´óÑ§/Êý×ÖµçÊÓ¼¼Êõ
 * Communication University of China / Digital TV Technology
 * http://blog.csdn.net/leixiaohua1020
 * 
 * ±¾³ÌÐòÊµÏÖÁËYUVÏñËØÊý¾Ý±àÂëÎªÊÓÆµÂëÁ÷£¨H264£¬MPEG2£¬VP8µÈµÈ£©¡£
 * Ëü½ö½öÊ¹ÓÃÁËlibavcodec£¨¶øÃ»ÓÐÊ¹ÓÃlibavformat£©¡£
 * ÊÇ×î¼òµ¥µÄFFmpegÊÓÆµ±àÂë·½ÃæµÄ½Ì³Ì¡£
 * Í¨¹ýÑ§Ï°±¾Àý×Ó¿ÉÒÔÁË½âFFmpegµÄ±àÂëÁ÷³Ì¡£
 * This software encode YUV420P data to video bitstream
 * (Such as H.264, H.265, VP8, MPEG2 etc).
 * It only uses libavcodec to encode video (without libavformat)
 * It's the simplest video encoding software based on FFmpeg. 
 * Suitable for beginner of FFmpeg 
 */


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
#define SERVICE_PORT    21234
#define MAXNUM 9999

#ifdef _WIN32
//Windows
extern "C"
{
#include "libavutil/opt.h"
#include "libavcodec/avcodec.h"
#include "libavutil/imgutils.h"
};
#else
//Linux...
#ifdef __cplusplus
extern "C"
{
#endif
#include "libavutil/opt.h"
#include "libavcodec/avcodec.h"
#include "libavformat/avformat.h"
#include "libavutil/time.h"
#include "libavdevice/avdevice.h"
#include "libswscale/swscale.h"
#include "libavutil/mathematics.h"
#ifdef __cplusplus
};
#endif
#endif

//test different codec
#define TEST_H264  1
#define TEST_HEVC  0

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

// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (int fd, struct sockaddr_in remaddr, int obj_num, std::vector<in_enc_align> myvec, float drop_prob,
                                                        const uint8_t overhead);
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (int fd, struct sockaddr_in remaddr, int obj_num, std::vector<in_enc_align> myvec, float drop_prob,
                                                        const uint8_t overhead)
{
    typedef out_enc_align   in_dec_align;
    const uint32_t mysize = myvec.size();
    u_char *buff;
    buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));

    // std::pair<symbol id (esi), symbol>
    std::vector<std::pair<uint32_t, std::vector<out_enc_align>>> encoded;

    const uint16_t subsymbol = sizeof(in_enc_align) * 8;    /*** speed ***/
    const uint16_t symbol_size = subsymbol * 88;    /*** speed ***/
    size_t aligned_symbol_size = static_cast<size_t> (
        std::ceil(static_cast<float> (symbol_size) / sizeof(out_enc_align)));
    // udp max 1472 bytes, -id4B, 1468/4=367/2
    std::cout << "Subsymbol: " << subsymbol << " Symbol: " << symbol_size
        << " aligned_symbol_size: "<<aligned_symbol_size<< "\n";
    
    auto enc_it = myvec.begin();
    RaptorQ::Encoder<typename std::vector<in_enc_align>::iterator,
                            typename std::vector<out_enc_align>::iterator> enc (
                enc_it, myvec.end(), subsymbol, symbol_size, 1000); /*** speed ***/
    std::cout << "Size: " << mysize << " Blocks: " <<
                                    static_cast<int32_t>(enc.blocks()) << "\n";
    if (!enc) {
        std::cout << "Coud not initialize encoder.\n";
        return false;
    }

    enc.precompute(1, false);

    int32_t repair;
    uint32_t oti_scheme = enc.OTI_Scheme_Specific();
    uint64_t oti_common = enc.OTI_Common();
    u_long pointer = 0;
    memcpy(buff, "OTI", sizeof(uint32_t));
    pointer += sizeof(uint32_t);
    memcpy(buff+pointer, &obj_num, sizeof(int));
    pointer += sizeof(int);
    memcpy(buff+pointer, &oti_scheme, sizeof(oti_scheme));
    pointer += sizeof(oti_scheme);
    memcpy(buff+pointer, &oti_common, sizeof(oti_common));
    pointer += sizeof(oti_common);
    //wrapper((u_char*)buff, pointer);
    if (sendto(fd, buff, pointer, 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
            perror("sendto");
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
            float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
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
            //cout << pac_size << ' ' << pac_size_1 << ' ' << pac_size_2 << endl;
            memcpy(buff, &id, pac_size_1);
            u_long pointer = pac_size_1;
            for (uint32_t i = 0; i < aligned_symbol_size; ++i){
                memcpy(buff+pointer, &source_sym[i], sizeof(out_enc_align));
                //uint32_t x;
                //memcpy(&x, pointer, sizeof(out_enc_align));
                pointer += sizeof(out_enc_align);
                //cout << "source_sym["<<i<<"]:"<<source_sym[i]<<' '<<x<<endl;
            }
            cout << "source_sym[0]:" <<source_sym[0] << " source_sym["<<aligned_symbol_size-1<<"]:"<<source_sym[aligned_symbol_size-1]<<endl;
            encoded.emplace_back ((*sym_it).id(), std::move(source_sym));
            //wrapper((u_char*)buff, pac_size);
            FILE *fp_buff;
    char file_buff[]="send_buff.txt";
    fp_buff = fopen(file_buff, "wb");
    if (!fp_buff) {
        printf("Could not open %s\n", file_buff);
        return -1;
    }
            if (sendto(fd, buff, pointer, 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
                perror("sendto");
            fwrite(buff,1,pointer,fp_buff);
            //cout << encoded.size()-1<<' '<< encoded[encoded.size()-1].first << ' ' << encoded[encoded.size()-1].second[0]
            //    << ' '<< aligned_symbol_size<<' '  <<encoded[encoded.size()-1].second[aligned_symbol_size-1]<< endl;
        }
        // now get (overhead + source_symbol_lost) repair symbols.
        std::cout << "Source Packet lost: " << repair - overhead << "\n";
        auto sym_it = block.begin_repair();
        for (; repair >= 0 && sym_it != block.end_repair (block.max_repair()); ++sym_it) {
        //for (; sym_it != block.end_repair (block.max_repair()); ++sym_it) {
            // repair symbols can be lost, too!
            float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
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
            //wrapper((u_char*)buff, pac_size);
            if (sendto(fd, buff, pointer*2, 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
                perror("sendto");
            //cout << encoded.size()-1<<' '<< encoded[encoded.size()-1].first << ' ' << encoded[encoded.size()-1].second[0]
            //<< ' '<< aligned_symbol_size<<' ' <<encoded[encoded.size()-1].second[aligned_symbol_size-1]<< endl;


            //encoded.emplace_back ((*sym_it).id(), std::move(repair_sym));
        }
        if (sym_it == block.end_repair (block.max_repair())) {
            // we dropped waaaay too many symbols! how much are you planning to
            // lose, again???
            std::cout << "Maybe losing " << drop_prob << "% is too much?\n";
            return false;
        }
    }
    return true;
}


int main(int argc, char* argv[])
{
    clock_t s_all, t_all;
    s_all = clock();
    time_t seconds;  
    seconds = time((time_t *)NULL); 

    
    AVFormatContext *ifmt_ctx=NULL;
    AVInputFormat* ifmt;
    AVCodecContext* pCodecCtx;
    AVCodec* pCodec;
    AVPacket *dec_pkt, enc_pkt;
    AVFrame *pframe, *pFrameYUV;
    struct SwsContext *img_convert_ctx;

    int framecnt=0;
    int videoindex;
    int i;
    int ret;
    int dec_got_frame,enc_got_frame;

 /*   AVCodec *pCodec;
    AVCodecContext *pCodecCtx= NULL;
    int i, ret, got_output;
    FILE *fp_in;
    FILE *fp_out;
    AVFrame *pFrame;
    AVPacket pkt;
    int y_size;
    int framecnt=0;

    char filename_in[]="./video/bigbuckbunny.yuv";

#if TEST_HEVC
    AVCodecID codec_id=AV_CODEC_ID_HEVC;
    char filename_out[]="./video/ds.hevc";
#else
    AVCodecID codec_id=AV_CODEC_ID_H264;
    char filename_out[]="./video/ds.h264";
#endif*/


    av_register_all();
    //Register Device
    avdevice_register_all();
    avformat_network_init();

    int in_w=640,in_h=480;  
    int framenum=100; 
    uint8_t *cur_ptr;
    int cur_size;

    ifmt=av_find_input_format("video4linux2");  
    if(avformat_open_input(&ifmt_ctx,"/dev/video0",ifmt,NULL)!=0){  
        printf("Couldn't open input stream.\n");  
        return -1;  
    }
    else printf("open input stream!\n");        
    
    //input initialize
    if (avformat_find_stream_info(ifmt_ctx, NULL)<0)
    {
        printf("Couldn't find stream information.\n");
        return -1;
    }
    videoindex = -1;
    for (i = 0; i<ifmt_ctx->nb_streams; i++)
        if (ifmt_ctx->streams[i]->codec->codec_type == AVMEDIA_TYPE_VIDEO)
        {
            videoindex = i;
            break;
        }
    if (videoindex == -1)
    {
        printf("Couldn't find a video stream.\n");
        return -1;
    }
    if (avcodec_open2(ifmt_ctx->streams[videoindex]->codec, avcodec_find_decoder(ifmt_ctx->streams[videoindex]->codec->codec_id), NULL)<0)
    {
        printf("Could not open codec.\n");
        return -1;
    }

    pCodec = avcodec_find_encoder(AV_CODEC_ID_H264);
    if (!pCodec){
        printf("Can not find encoder! \n");
        return -1;
    }
    pCodecCtx=avcodec_alloc_context3(pCodec);
    pCodecCtx->pix_fmt = AV_PIX_FMT_YUV420P;
    pCodecCtx->width=in_w;
    pCodecCtx->height=in_h;
    //pCodecCtx->width = ifmt_ctx->streams[videoindex]->codec->width;
    //pCodecCtx->height = ifmt_ctx->streams[videoindex]->codec->height;
    pCodecCtx->time_base.num = 1;
    pCodecCtx->time_base.den = 25;
    pCodecCtx->bit_rate = 400000;
    pCodecCtx->gop_size = 10;
    //pCodecCtx->qmin = 10;
    //pCodecCtx->qmax = 51;
    pCodecCtx->max_b_frames = 1;

    AVDictionary *param = 0;
    av_dict_set(&param, "preset", "superfast", 0);
    av_dict_set(&param, "tune", "zerolatency", 0);

    if (avcodec_open2(pCodecCtx, pCodec,&param) < 0){
        printf("Failed to open encoder!\n");
        return -1;
    }

/*
    pCodecCtx = avcodec_alloc_context3(pCodec);
    if (!pCodecCtx) {
        printf("Could not allocate video codec context\n");
        return -1;
    }
    pCodecCtx->bit_rate = 400000;
    pCodecCtx->width = in_w;
    pCodecCtx->height = in_h;
    pCodecCtx->time_base.num=1;
    pCodecCtx->time_base.den=25;
    pCodecCtx->gop_size = 10;
    pCodecCtx->max_b_frames = 1;
    pCodecCtx->pix_fmt = AV_PIX_FMT_YUV420P;

    if (codec_id == AV_CODEC_ID_H264)
        av_opt_set(pCodecCtx->priv_data, "preset", "slow", 0);
 
    if (avcodec_open2(pCodecCtx, pCodec, NULL) < 0) {
        printf("Could not open codec\n");
        return -1;
    }
    
    pFrame = av_frame_alloc();
    if (!pFrame) {
        printf("Could not allocate video frame\n");
        return -1;
    }
    pFrame->format = pCodecCtx->pix_fmt;
    pFrame->width  = pCodecCtx->width;
    pFrame->height = pCodecCtx->height;

    ret = av_image_alloc(pFrame->data, pFrame->linesize, pCodecCtx->width, pCodecCtx->height,
                         pCodecCtx->pix_fmt, 16);
    if (ret < 0) {
        printf("Could not allocate raw picture buffer\n");
        return -1;
    }
*/
    
    // socker
    struct sockaddr_in myaddr, remaddr;
    int fd, slen=sizeof(remaddr);
    char *server = "127.0.0.1"; /* change this to use a different server */
    /* create a socket */
    if ((fd=socket(AF_INET, SOCK_DGRAM, 0))==-1)
        printf("socket created\n");
    /* bind it to all local addresses and pick any port number */
    memset((char *)&myaddr, 0, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(0);
    if (bind(fd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
        perror("bind failed");
        return 0;
    }       
    /* now define remaddr, the address to whom we want to send messages */
    /* For convenience, the host address is expressed as a numeric IP address */
    /* that we will convert to a binary format via inet_aton */
    memset((char *) &remaddr, 0, sizeof(remaddr));
    remaddr.sin_family = AF_INET;
    remaddr.sin_port = htons(SERVICE_PORT);
    if (inet_aton(server, &remaddr.sin_addr)==0) {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

    //prepare before decode and encode
    dec_pkt = (AVPacket *)av_malloc(sizeof(AVPacket));
    img_convert_ctx = sws_getContext(ifmt_ctx->streams[videoindex]->codec->width, ifmt_ctx->streams[videoindex]->codec->height, 
        ifmt_ctx->streams[videoindex]->codec->pix_fmt, pCodecCtx->width, pCodecCtx->height, AV_PIX_FMT_YUV420P, SWS_BICUBIC, NULL, NULL, NULL);
    pFrameYUV = av_frame_alloc();
    pFrameYUV->format = pCodecCtx->pix_fmt;
    pFrameYUV->width  = pCodecCtx->width;
    pFrameYUV->height = pCodecCtx->height;
    uint8_t *out_buffer = (uint8_t *)av_malloc(avpicture_get_size(AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height));
    avpicture_fill((AVPicture *)pFrameYUV, out_buffer, AV_PIX_FMT_YUV420P, pCodecCtx->width, pCodecCtx->height);    


    float drop_prob = 10.0;
    const uint8_t overhead = 5;
    /////////////////////////////////////////////////////////////
    /*
    AVFrame *pFrameRGB = NULL;
    AVFrame *pFrame,*pFrameYUV;
    uint8_t *out_bufferRGB = NULL;
    int y_size;
    int sizeout, got_picture;
    int first_time=1, obj_num;
    AVCodec *pCodec;
    AVCodecContext *pCodecCtx= NULL;
    AVCodecParserContext *pCodecParserCtx=NULL;
    pCodecParserCtx=av_parser_init(codec_id);
    if (!pCodecParserCtx){
        printf("Could not allocate video parser context\n");
        return -1;
    }
    */
/////////////////////////////////////////////////////////////////////
    printf("initial down!.\n");
    //Encode
    for (i = 0; i < framenum; i++) {
        if(av_read_frame(ifmt_ctx, dec_pkt) >= 0)
        {
            av_log(NULL, AV_LOG_DEBUG, "Going to reencode the frame\n");
            pframe = av_frame_alloc();
            if (!pframe) {
                ret = AVERROR(ENOMEM);
                return -1;
            }

            ret = avcodec_decode_video2(ifmt_ctx->streams[dec_pkt->stream_index]->codec, pframe,
                &dec_got_frame, dec_pkt);
            if (ret < 0) {
                av_frame_free(&pframe);
                av_log(NULL, AV_LOG_ERROR, "Decoding failed\n");
                break;
            }
            printf("decode down!\n");
            printf("format\n");
            if (dec_got_frame){
                sws_scale(img_convert_ctx, (const uint8_t* const*)pframe->data, pframe->linesize, 0, pCodecCtx->height, pFrameYUV->data, pFrameYUV->linesize);  

                enc_pkt.data = NULL;
                enc_pkt.size = 0;
                av_init_packet(&enc_pkt);
                pFrameYUV->pts = i;
                ret = avcodec_encode_video2(pCodecCtx, &enc_pkt, pFrameYUV, &enc_got_frame);
                if (ret < 0) {
                    printf("Error encoding frame\n");
                    return -1;}
                printf("encode down!\n");
                //printf("enc_got_frame: %d \n", enc_got_frame);
                av_frame_free(&pframe);
                if (enc_got_frame ){
                    printf("Succeed to encode frame: %5d\tsize:%5d\n", framecnt, enc_pkt.size);
                    framecnt++;
                    std::vector<uint8_t> vec_data;
                    vec_data.insert(vec_data.end(), enc_pkt.data, enc_pkt.data+enc_pkt.size*sizeof(uint8_t));
                    encode<uint8_t, uint32_t, uint8_t>(fd, remaddr, i, vec_data, drop_prob, overhead);  
                    av_free_packet(&enc_pkt);
                    //usleep(40000);  
                    waitKey(40);                    
                }
////////////////////////////////////////////////////////////////////////////////////
                /*
                cur_size = enc_pkt.size;
    cur_ptr = enc_pkt.data;
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
                cout << "obj_num: "<<obj_num<<endl;
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
                waitKey(40);
                sws_scale(img_convert_ctx, (const uint8_t* const*)pFrame->data, pFrame->linesize, 0, pCodecCtx->height, 
                    pFrameRGB->data, pFrameRGB->linesize);
                Mat testout = Mat(pCodecCtx->height, pCodecCtx->width, CV_8UC3);
                memcpy(testout.data, out_bufferRGB,sizeout);
                imshow("testout", testout);
                char filename[20];
                sprintf(filename, "video/im/%d.jpg", obj_num);
                imwrite(filename, testout);
                waitKey(40);
            }
        }
        */
        //////////////////////////////////////////////////////////////////////////////
            }
            else {
                av_frame_free(&pframe);
            }
            av_free_packet(dec_pkt);    
        }
    }
    //Flush Encoder
    for (enc_got_frame = 1; enc_got_frame; i++) {
        ret = avcodec_encode_video2(pCodecCtx, &enc_pkt, NULL, &enc_got_frame);
        if (ret < 0) {
            printf("Error encoding frame\n");
            return -1;
        }
        if (enc_got_frame) {
            printf("Flush Encoder: Succeed to encode 1 frame!\tsize:%5d num%5d\n",enc_pkt.size, framecnt);
            //framecnt++;
            //fwrite(pkt.data, 1, pkt.size, fp_out);
            std::vector<uint8_t> vec_data;
            vec_data.insert(vec_data.end(), enc_pkt.data, enc_pkt.data+enc_pkt.size*sizeof(uint8_t));
            //recv(fp_out, vec_data);
            //cout << "Wait for ack..." << endl;
            //pcap_loop(device, 1, my_callback, (u_char *)buff);
            //int obj_num;
            //memcpy(&obj_num, buff+sizeof(uint32_t), sizeof(int));
            /*while ((!(buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K')) or obj_num != i-1) {
                cout << "No ack. Wait for ack..." << endl;
                if (buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K'){
                    cout << "Wrong obj num: " << obj_num << endl;
                }
                pcap_loop(device, 1, my_callback, (u_char *)buff);
            }*/
            ret = encode<uint8_t, uint32_t, uint8_t>(fd, remaddr, i, vec_data, drop_prob, overhead);
            if (!ret) {
                cout << "encode failed\n";
                return -1;
            }
            av_free_packet(&enc_pkt);
            //usleep(40000);
            waitKey(40);
        }
    }

    u_char payload[] = "END";
    //wrapper(payload, sizeof(uint32_t));
    if (sendto(fd, payload, sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
                perror("sendto");

    av_free(out_buffer);
    avformat_free_context(ifmt_ctx);
    avcodec_close(pCodecCtx);
    av_free(pCodecCtx);
    //av_freep(&pFrame->data[0]);
    //av_frame_free(&pFrame);
    cout <<"time: "<<time((time_t *)NULL) - seconds << endl;
    t_all = clock();
    double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    cout <<"time: "<< duration << endl;

    return 0;
}

