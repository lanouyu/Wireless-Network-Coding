#include <iostream>  
  
using namespace std;  
  
extern "C" {  
#include <libavcodec/avcodec.h>   
#include <libavformat/avformat.h>  
#include <libavdevice/avdevice.h>  
#include <libavutil/dict.h>  
#include "libswscale/swscale.h"  
};    
  
int main(int argc, char **argv) {  
    int ret;  
    AVFormatContext *fmtCtx = NULL;  
    AVPacket pkt1, *pcaket = &pkt1;  
  
    /*1、注册*/
    av_register_all();    
    avformat_network_init();   
    avdevice_register_all();  
    /*2、连接视频源*/  
    AVInputFormat *inputFmt = av_find_input_format("video4linux2");  
    if (NULL != inputFmt) {  
        std::cout << "input device name:" << inputFmt->name << std::endl;  
    } else {  
        std::cout << "Null point!" << std::endl;  
    }  
    /*3、打开视频采集设备*/  
    ret = avformat_open_input(&fmtCtx, "/dev/video0", inputFmt, NULL);  
    if (0 == ret) {  
        std::cout << "Open input device seccess!" << std::endl;  
    }  
    /*4、读取一帧数据，编码依据摄像头类型而定，我使用的摄像头输出的是yuv422格式*/  
    av_read_frame(fmtCtx, pcaket);  
    cout << "packet size:" << (pcaket->size) << endl;  
    /*5、写入帧数据到文件*/  
    FILE *fp = NULL;  
    fp = fopen("out.yuv", "wb");  
    if (NULL != fp) {  
        //将数据写入文件  
        fwrite(pcaket->data, 1, pcaket->size, fp);  
    }  
    //关闭文件  
    fclose(fp);  
    /*6、释放读取的帧数据*/  
    av_free_packet(pcaket);  
    /*7、关闭视频输入源*/  
    avformat_close_input(&fmtCtx);  
  
    return 0;  
}  