/*
        demo-udp-03: udp-send: a simple udp client
	send udp messages
	sends a sequence of messages (the # of messages is defined in MSGS)
	The messages are sent to a port defined in SERVICE_PORT

        usage:  udp-send

        Paul Krzyzanowski
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>      
using namespace std;
using namespace cv;
#define SERVICE_PORT	21234

#define BUFLEN 2048
#define PORT 233
#define MAXNUM 9999

// mysize is bytes.
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (int fd, struct sockaddr_in remaddr, uint64_t obj_num, std::vector<in_enc_align> myvec, float drop_prob,
														const uint8_t overhead);
template <typename in_enc_align, typename out_enc_align, typename out_dec_align>
bool encode (int fd, struct sockaddr_in remaddr, uint64_t obj_num, std::vector<in_enc_align> myvec, float drop_prob,
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
			//wrapper((u_char*)buff, pac_size);
			if (sendto(fd, buff, pac_size, 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
				perror("sendto");
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
			if (sendto(fd, buff, pac_size, 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
				perror("sendto");
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

int main(void)
{
	struct sockaddr_in myaddr, remaddr;
	int fd, i, slen=sizeof(remaddr);
	char *server = "127.0.0.1";	/* change this to use a different server */


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

	/* now let's send the messages */
	//char buf[BUFLEN];
	//uint32_t* buff;
	//buff = (uint32_t*) malloc(170 * sizeof(uint32_t));
	char filename[20];

	//for (uint64_t i = 3; i < 21; ++i) {
		sprintf(filename, "./image_send/3.jpg");
		cout << filename << endl;
		Mat frame;
		frame = imread(filename);
		if (frame.empty()) {
			printf("Could not load image\n");
			exit(0);
		}
		std::vector<uint8_t> mat_vec;
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
		ret = encode<uint8_t, uint32_t, uint8_t> (fd, remaddr, 3, mat_vec, 10.0, 100);
		if (!ret)
			return -1;
		cout <<time((time_t *)NULL) - seconds << endl;
		t_all = clock();
    	double duration=(double)(t_all - s_all) / CLOCKS_PER_SEC;
    	cout << duration << endl;

	//}
	//if (sendto(fd, buff, 170 * sizeof(uint32_t), 0, (struct sockaddr *)&remaddr, sizeof(remaddr))==-1)
	//		perror("sendto");
	close(fd);
	return 0;
}
