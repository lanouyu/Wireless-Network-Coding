/*
        demo-udp-03: udp-recv: a simple udp server
	receive udp messages

        usage:  udp-recv

        Paul Krzyzanowski
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h> 
#include <string.h>
#include <errno.h>
#include <sys/types.h>  

#include <fstream>
#include <iostream>
#include <random>
#include "../src/RaptorQ.hpp"
#include <vector>
#include <time.h>
#include <opencv2/opencv.hpp>
#include <opencv2/highgui.hpp>
#include <opencv2/videoio.hpp>
#define SERVICE_PORT	21234

#define BUFSIZE 2048
using namespace std;
using namespace cv;

#define MAXNUM 9999

// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (int fd, struct sockaddr_in remaddr, const uint32_t mysize);

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (int fd, struct sockaddr_in remaddr, const uint32_t mysize)
{
	u_char *buff;
	buff = (u_char*) malloc(MAXNUM * sizeof(uint32_t));
	int recvlen;
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */

	uint32_t oti_scheme;
	uint64_t oti_common;
	uint64_t obj_num;
	cout << "Wait for oti..." << endl;
	//pcap_loop(device, 1, my_callback, (u_char *)buff);
	recvlen = recvfrom(fd, buff, 170 * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, &addrlen);
	while (!(buff[0]=='O'&&buff[1]=='T'&&buff[2]=='I'))
		recvlen = recvfrom(fd, buff, 170 * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, &addrlen);

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
		//pcap_loop(device, 1, my_callback, (u_char *)buff);
		recvlen = recvfrom(fd, buff, (aligned_symbol_size+1) * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, &addrlen);
		uint32_t id;
		memcpy(&id, buff, sizeof(uint32_t));
		u_long pointer = sizeof(uint32_t);
		for (uint32_t i=0; i < aligned_symbol_size;++i) {
			memcpy(&source_sym[i], buff+pointer, sizeof(out_enc_align));
			uint32_t x;
			memcpy(&x, buff+pointer, sizeof(out_enc_align));
			pointer += sizeof(out_enc_align);
			//cout << "source_sym["<<i<<"]: "<<source_sym[i]<<endl;
		}
		// add symbol
		auto it = source_sym.begin();
		if (!dec.add_symbol (it, source_sym.end(), id))
			std::cout << "error adding?\n";
		else
			pac_num += 1;
		// decode
		re_it = received.begin();
		decoded=dec.decode(re_it, received.end());
		cout << "Need more symbols, now is "<<pac_num<<" symbols, decoded: "<<decoded<<"\n";
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

int main(int argc, char **argv)
{
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int fd;				/* our socket */
	//unsigned char buf[BUFSIZE];	/* receive buffer */


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

	uint32_t* buf;	/* receive buffer */
	buf = (uint32_t*) malloc(170 * sizeof(uint32_t));
	for (size_t i = 0; i < 1000; ++i) {
		bool ret;
		clock_t s_all, t_all;
		s_all = clock();
		time_t seconds;  
		seconds = time((time_t *)NULL); 
		ret = decode<uint8_t, uint32_t, uint8_t> (fd, remaddr, 480*640*3);
		//ret = encode<uint8_t, uint32_t, uint8_t> (mat_vec.size()/3, rnd, 10.0, 4);
		if (!ret)
			return -1;
		cout <<time((time_t *)NULL) - seconds << endl;
		t_all = clock();
    	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    	cout << duration << endl;

	}
	/* now loop, receiving data and printing what we received 
	for (;;) {
		printf("waiting on port %d\n", SERVICE_PORT);
		recvlen = recvfrom(fd, buf, 170 * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, &addrlen);
		printf("received %d bytes\n", recvlen);
		if (recvlen > 0) {
			buf[recvlen] = 0;
			printf("received message: \"%s\buf"\n", buf);
		}
		char a, b;
		for (int i=0; i<170; i++)
			printf("%d\n", buf[i]);
	}
	 never exits */
}
