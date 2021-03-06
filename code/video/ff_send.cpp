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

using namespace std;

#define __STDC_CONSTANT_MACROS

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
#include <libavutil/opt.h>
#include <libavcodec/avcodec.h>
#include <libavutil/imgutils.h>
#ifdef __cplusplus
};
#endif
#endif

//test different codec
#define TEST_H264  1
#define TEST_HEVC  0
#define MAXNUM 999

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
bool encode (int obj_num, std::vector<in_enc_align> myvec, float drop_prob,
                                                        const uint8_t overhead);
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (int obj_num, std::vector<in_enc_align> myvec, float drop_prob,
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
            encoded.emplace_back ((*sym_it).id(), std::move(source_sym));
            wrapper((u_char*)buff, pac_size);
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
            wrapper((u_char*)buff, pac_size);
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

uint8_t wrapper(u_char * payload, u_long payload_s){
    libnet_t *handle; /* Libnet句柄 */
    char *device = "ens33"; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    char *src_ip_str = "192.168.141.147"; /* 源IP地址字符串 */
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

int main(int argc, char* argv[])
{
    clock_t s_all, t_all;
    s_all = clock();
    time_t seconds;  
    seconds = time((time_t *)NULL); 

    AVCodec *pCodec;
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
#endif


    int in_w=480,in_h=272;  
    int framenum=100;   

    avcodec_register_all();

    pCodec = avcodec_find_encoder(codec_id);
    if (!pCodec) {
        printf("Codec not found\n");
        return -1;
    }
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
    //Input raw data
    fp_in = fopen(filename_in, "rb");
    if (!fp_in) {
        printf("Could not open %s\n", filename_in);
        return -1;
    }
    //Output bitstream
    fp_out = fopen(filename_out, "wb");
    if (!fp_out) {
        printf("Could not open %s\n", filename_out);
        return -1;
    }
    
    // pcap
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
    pcap_compile(device, &filter, "src host 192.168.141.147", 1, 0); 
    pcap_setfilter(device, &filter);
    u_char *buff;
    buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));

    y_size = pCodecCtx->width * pCodecCtx->height;
    float drop_prob = 10.0;
    const uint8_t overhead = 5;
    //Encode
    for (i = 0; i < framenum; i++) {
        av_init_packet(&pkt);
        pkt.data = NULL;    // packet data will be allocated by the encoder
        pkt.size = 0;
        //Read raw YUV data
        if (fread(pFrame->data[0],1,y_size,fp_in)<= 0||     // Y
            fread(pFrame->data[1],1,y_size/4,fp_in)<= 0||   // U
            fread(pFrame->data[2],1,y_size/4,fp_in)<= 0){   // V
            return -1;
        }else if(feof(fp_in)){
            break;
        }

        pFrame->pts = i;
        /* encode the image */
        ret = avcodec_encode_video2(pCodecCtx, &pkt, pFrame, &got_output);
        if (ret < 0) {
            printf("Error encoding frame\n");
            return -1;
        }
        if (got_output) {
            printf("Succeed to encode frame: %5d\tsize:%5d\n",framecnt,pkt.size);
            framecnt++;
            //fwrite(pkt.data, 1, pkt.size, fp_out);
            std::vector<uint8_t> vec_data;
            vec_data.insert(vec_data.end(), pkt.data, pkt.data+pkt.size*sizeof(uint8_t));
            //recv(fp_out, vec_data);
            //cout << "Wait for ack..." << endl;
            //pcap_loop(device, 1, my_callback, (u_char *)buff);
            int obj_num;
            memcpy(&obj_num, buff+sizeof(uint32_t), sizeof(int));
            /*while ((!(buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K')) or obj_num != i-1) {
                cout << "No ack. Wait for ack..." << endl;
                if (buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K'){
                    cout << "Wrong obj num: " << obj_num << ", instead of "<<i<<endl;
                }
                pcap_loop(device, 1, my_callback, (u_char *)buff);
            }*/
            //if (framecnt % 10 != 0)
                encode<uint8_t, uint32_t, uint8_t>(i, vec_data, drop_prob, overhead);

            av_free_packet(&pkt);
        }
    }
    //Flush Encoder
    for (got_output = 1; got_output; i++) {
        ret = avcodec_encode_video2(pCodecCtx, &pkt, NULL, &got_output);
        if (ret < 0) {
            printf("Error encoding frame\n");
            return -1;
        }
        if (got_output) {
            printf("Flush Encoder: Succeed to encode 1 frame!\tsize:%5d\n",pkt.size);
            //fwrite(pkt.data, 1, pkt.size, fp_out);
            std::vector<uint8_t> vec_data;
            vec_data.insert(vec_data.end(), pkt.data, pkt.data+pkt.size*sizeof(uint8_t));
            //recv(fp_out, vec_data);
            //cout << "Wait for ack..." << endl;
            //pcap_loop(device, 1, my_callback, (u_char *)buff);
            int obj_num;
            memcpy(&obj_num, buff+sizeof(uint32_t), sizeof(int));
            /*while ((!(buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K')) or obj_num != i-1) {
                cout << "No ack. Wait for ack..." << endl;
                if (buff[0]=='A'&&buff[1]=='C'&&buff[2]=='K'){
                    cout << "Wrong obj num: " << obj_num << endl;
                }
                pcap_loop(device, 1, my_callback, (u_char *)buff);
            }*/
            ret = encode<uint8_t, uint32_t, uint8_t>(i, vec_data, drop_prob, overhead);
            if (!ret) {
                cout << "encode failed\n";
                return -1;
            }
            av_free_packet(&pkt);
        }
    }

    u_char payload[] = "END";
    wrapper(payload, sizeof(uint32_t));
    fclose(fp_out);
    avcodec_close(pCodecCtx);
    av_free(pCodecCtx);
    av_freep(&pFrame->data[0]);
    av_frame_free(&pFrame);
    cout <<"time: "<<time((time_t *)NULL) - seconds << endl;
    t_all = clock();
    double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    cout <<"time: "<< duration << endl;

    return 0;
}

