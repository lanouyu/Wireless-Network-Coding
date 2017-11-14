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
using namespace std;
using namespace cv;

#define PORT 233
#define MAXNUM 9999

// Demonstration of how to use the C++ interface
// it's pretty simple, we generate some input,
// then encode, drop some packets (source and repair)
// and finally decode everything.


// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (int connfd, const uint32_t mysize);

template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool decode (int connfd, const uint32_t mysize)
{
	uint32_t *buff;
	buff = (uint32_t*) malloc(MAXNUM * sizeof(uint32_t));
	//char buff[100000];
	int recvlen;
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */

	uint32_t oti_scheme;
	uint64_t oti_common;
	cout << "Wait for oti..." << endl;
	recvlen = recvfrom(connfd, &oti_scheme, sizeof(oti_scheme), 0, (struct sockaddr *)&remaddr, &addrlen);
	printf("received %d bytes\n", recvlen);
	recvlen = recvfrom(connfd, &oti_common, sizeof(oti_common), 0, (struct sockaddr *)&remaddr, &addrlen);
	printf("received %d bytes\n", recvlen);

	cout << "oti_scheme" << oti_scheme << endl;
	printf("%x\n", oti_scheme);
	cout << "oti_common" << oti_common << endl;

	// std::pair<symbol id (esi), symbol>
	//std::vector<std::pair<uint32_t, std::vector<out_enc_align>>> encoded;
	//encoded.reserve(100);
	typedef out_enc_align	in_dec_align;
	uint32_t aligned_symbol_size = 176;
	uint32_t pac_size=aligned_symbol_size*sizeof(out_enc_align)+sizeof(uint32_t);
	
	//encoded.emplace_back (id, std::move(source_sym));
	//cout << encoded[0].first << ' ' << encoded[0].second[0] << endl;
	
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
/*
	for (size_t i = 0; i < encoded.size(); ++i) {
		auto it = encoded[i].second.begin();
		if (!dec.add_symbol (it, encoded[i].second.end(), encoded[i].first))
			std::cout << "error adding?\n";
	}

	auto re_it = received.begin();
	// decode all blocks
	// you can actually call ".decode(...)" as many times
	// as you want. It will only start decoding once
	// it has enough data.
	auto decoded = dec.decode(re_it, received.end());

	if (decoded * sizeof(out_dec_align) < mysize) {
		if (decoded == 0) {
			std::cout << "Couldn't decode, RaptorQ Algorithm failure. Retry.\n";
			return true;
		} else {
			std::cout << "Partial Decoding? This should not have happened: " <<
					decoded * sizeof(out_dec_align) << " vs " << mysize << "\n";
		}
		return false;
	} else {
		std::cout << "Decoded: " << mysize << "\n";
	}*/
	auto re_it = received.begin();
	auto decoded = dec.decode(re_it, received.end());
	uint32_t pac_num = 0;
	while (decoded * sizeof(out_dec_align) < mysize) {
		// receive
		std::vector<out_enc_align> source_sym;
		source_sym.reserve (aligned_symbol_size);
		source_sym.insert (source_sym.begin(), aligned_symbol_size, 0);
		recvlen = recvfrom(connfd, buff, pac_size, 0, (struct sockaddr *)&remaddr, &addrlen);
		uint32_t id;
		memcpy(&id, buff, sizeof(uint32_t));
		uint32_t pointer = sizeof(uint32_t);
		for (uint32_t i=0; i < aligned_symbol_size;++i) {
			memcpy(&source_sym[i], buff+pointer, sizeof(out_enc_align));
			uint32_t x;
			memcpy(&x, pointer, sizeof(out_enc_align));
			pointer += sizeof(out_enc_align);
			cout << "source_sym["<<i<<"]:"<<source_sym[i]<<' '<<x<<endl;
		}
		cout <<"pac_num: "<<pac_num<<"\tid: "<<id << "\tsource_sym: "<<source_sym[1]
		<<' '<< aligned_symbol_size<<' ' <<source_sym[aligned_symbol_size-1]<<endl;
		//return -1;
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
	imshow("frame_received", frame_received);
	waitKey(5000);

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

	/********************** socket****************************/
	struct sockaddr_in myaddr;	/* our address */
	struct sockaddr_in remaddr;	/* remote address */
	socklen_t addrlen = sizeof(remaddr);		/* length of addresses */
	int recvlen;			/* # bytes received */
	int sockfd;				/* our socket */

	/* create a UDP socket */
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("cannot create socket\n");
		return 0;
	}

	/* bind the socket to any valid IP address and a specific port */
	memset((char *)&myaddr, 0, sizeof(myaddr));
	myaddr.sin_family = AF_INET;
	myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	myaddr.sin_port = htons(PORT);

	if (bind(sockfd, (struct sockaddr *)&myaddr, sizeof(myaddr)) < 0) {
		perror("bind failed");
		return 0;
	}


	// encode and decode
	//for (size_t i = 0; i < 1000; ++i) {
		bool ret;
		clock_t s_all, t_all;
		s_all = clock();
		time_t seconds;  
		seconds = time((time_t *)NULL); 
		ret = decode<uint8_t, uint32_t, uint8_t> (sockfd, 480*640*3);
		//ret = encode<uint8_t, uint32_t, uint8_t> (mat_vec.size()/3, rnd, 10.0, 4);
		if (!ret)
			return -1;
		cout <<time((time_t *)NULL) - seconds << endl;
		t_all = clock();
    	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    	cout << duration << endl;

	//}
	std::cout << "All tests succesfull!\n";
	return 0;
}
