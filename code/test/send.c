#include "../src/cRaptorQ.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>

/************socket*********/
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 6666
#define MAXLINE 4096

int main(int argc, char** argv) {
	uint32_t mysize = 50;
	float drop_prob = 10.0;
	uint8_t overhead = 4;
	const uint16_t subsymbol = 8;
	const uint16_t symbol_size = 16;

	int sockfd, n;
	struct sockaddr_in servaddr;
	char buff[MAXLINE];
	
	/******socket***********************************************/
	if (argc != 2){
	printf("usage: ./program <ipaddress>\n");
	exit(0);
	}

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0))<0){
	printf("create socket error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(PORT);
	if (inet_pton(AF_INET, argv[1], &servaddr.sin_addr) <= 0){
	printf("inet_pton error for %s\n", argv[1]);
	exit(0);
	}

	if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) <0 ){
	printf("connect error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}

	/*****creat data*******************************************/
	uint32_t *myvec;
	srand((uint32_t)time(NULL));
	myvec = (uint32_t*) malloc(mysize * sizeof(uint32_t));
	for (uint32_t i = 0; i < mysize; ++i) {
		myvec[i] = (uint32_t)rand();
		printf("myvec[%x]: %x\n", i, myvec[i]);
	}
	struct pair {
		uint32_t id;
		uint32_t *symbol;
	};

	/******encode*********************************************/
	struct RaptorQ_ptr *enc = RaptorQ_Enc(ENC_32, myvec, mysize,
		subsymbol, symbol_size, 500);
				/* RaptorQ_ptr* RaptorQ_Enc (const RaptorQ_type type,
											void *data,
											const uint64_t size,
											const uint16_t min_subsymbol_size,
											const uint16_t symbol_size,
											const size_t max_memory);
				*/
	if (enc == NULL) {
		fprintf(stderr, "Initialize encoder error!\n");
		free (myvec);
		return -1;
	}

	RaptorQ_precompute(enc, 2, true);
		/* start background precomputation while we get the source symbols.
			void RAPTORQ_API RaptorQ_precompute (struct RaptorQ_ptr *enc,
														const uint8_t threads,
														const bool background);
		*/

	// create and initial encoded pair array
	uint32_t symbols_tot = 0;
	uint32_t blocks = RaptorQ_blocks(enc);
	for (uint8_t b = 0; b < blocks; ++b) {
		uint16_t sym = RaptorQ_symbols(enc, b);
		symbols_tot += (sym + overhead);
	}
	printf("symbols_tot: %x\n",symbols_tot);

	struct pair *encoded;
	uint32_t next_encoded = 0;
	encoded = (struct pair*) malloc(sizeof(struct pair)* symbols_tot);
	for (uint32_t i = 0; i < symbols_tot; ++i)
		encoded[i].symbol = NULL;


	for (uint8_t b = 0; b < blocks; ++b) {
		uint32_t sym = RaptorQ_symbols(enc, b);
		int32_t repair = overhead;

		// get source symbol
		for (uint32_t source = 0; source < sym; ++source) {
			float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
			if (dropped < drop_prob) {
				// dropped source symbol. Don't even get it.
				++repair;
				continue;
			}
			encoded[next_encoded].id = RaptorQ_id(source, b);
			uint32_t data_size = symbol_size / sizeof(uint32_t);
			encoded[next_encoded].symbol = (uint32_t*) malloc(symbol_size);
			uint32_t *data = encoded[next_encoded].symbol;
			uint64_t written = RaptorQ_encode(enc, (void**)&data, data_size,
				source, (uint8_t)b);
			if (written != data_size) {
				fprintf(stderr, "Source symbol error!\n");
				free(myvec);
				for (uint32_t k = 0; k <= next_encoded; ++k)
					free(encoded[k].symbol);
				free(encoded);
				RaptorQ_free(&enc);
				return -1;
			}
			++next_encoded;
		}

		// get repair symbol
		uint32_t sym_rep;
		for (sym_rep = sym; repair > 0 && sym_rep < RaptorQ_max_repair(enc, b);
			++sym_rep) {
			float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
			if (dropped < drop_prob) {
				// dropped repair symbol. Don't even get it.
				continue;
			}
			--repair;
			encoded[next_encoded].id = RaptorQ_id(sym_rep, b);
			uint32_t data_size = symbol_size / sizeof(uint32_t);
			encoded[next_encoded].symbol = (uint32_t*) malloc(symbol_size);
			uint32_t *data = encoded[next_encoded].symbol;
			uint64_t written = RaptorQ_encode(enc, (void**)&data, data_size,
				sym_rep, (uint8_t)b);
			if (written != data_size) {
				fprintf(stderr, "Source symbol error!\n");
				free(myvec);
				for (uint32_t k = 0; k <= next_encoded; ++k)
					free(encoded[k].symbol);
				free(encoded);
				RaptorQ_free(&enc);
				return -1;
			}
			++next_encoded;
		}
		if (sym_rep == RaptorQ_max_repair(enc, b)) {
			fprintf(stderr, "lost too much symbol error!\n");
			free(myvec);
			for (uint32_t k = 0; k <= next_encoded; ++k)
				free(encoded[k].symbol);
			free(encoded);
			RaptorQ_free(&enc);
				return -1;
		}
	}
	
	// get oti information
	uint32_t oti_scheme = RaptorQ_OTI_Scheme(enc);
	uint64_t oti_common = RaptorQ_OTI_Common(enc);

	RaptorQ_free(&enc);

	/********send******************************************/
	printf("send oti_common: %x\n", oti_common);
	//memcpy(buff, &oti_common, sizeof(oti_common));
	if (send(sockfd, &oti_common, sizeof(oti_common), 0) <0 ){
		printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}

	printf("send oti_scheme: %x\n", oti_scheme);
	//memcpy(buff, &oti_scheme, sizeof(oti_scheme));
	if (send(sockfd, &oti_scheme, sizeof(oti_scheme), 0) <0 ){
		printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
		exit(0);
	}

	for (uint32_t k = 0; k < next_encoded; ++k) {
		printf("send encoded[%x]: id: %x;\tsymbol: %x\n", 
				k, encoded[k].id, *encoded[k].symbol);
		
		memcpy(buff, &encoded[k].id, sizeof(uint32_t));
		memcpy(buff+sizeof(uint32_t), encoded[k].symbol, symbol_size);
		if (send(sockfd, buff, sizeof(uint32_t)+symbol_size, 0) < 0){
			printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
			exit(0);
		}
	}

	close(sockfd);

	/******************decode******************************/
	struct RaptorQ_ptr *dec = RaptorQ_Dec(DEC_32, oti_common, oti_scheme);
	if (dec == NULL) {
		fprintf(stderr, "Could not initialize decoder!\n");
		free(myvec);
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
		return -1;
	}

	for (size_t i = 0; i < next_encoded; ++i) {
		uint32_t *data = encoded[i].symbol;
		uint32_t data_size = RaptorQ_symbol_size (dec) / sizeof(uint32_t);
		printf("encoded[%x]=%x\tdata_size: %x\n", i,*data, data_size);
		if (!RaptorQ_add_symbol_id (dec, (void **)&data, data_size,
									encoded[i].id)) {
			fprintf(stderr, "Error: couldn't add the symbol to the decoder\n");
			free(myvec);
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			RaptorQ_free (&dec);
			return -1;
		}
	}

	uint64_t decoded_size = ceil (RaptorQ_bytes (dec) / sizeof(uint32_t));
	uint32_t *received = (uint32_t *) malloc (decoded_size * sizeof(uint32_t));

	for (uint32_t *shit = received; shit != received + decoded_size; ++ shit);
	uint32_t *rec = received;
	uint64_t written = RaptorQ_decode (dec, (void **)&rec, decoded_size);
	
	printf("written: %x\ndecoded_size: %x\nmysize: %x\n",
		written, decoded_size, mysize);

	if ((written != decoded_size) || (decoded_size != mysize)) {
		fprintf(stderr, "Couldn't decode: %i - %lu\n", mysize, written);
		free(received);
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
		RaptorQ_free(&dec);
		return false;
	} else {
		printf("Decoded: %i\n", mysize);
	}

	for (uint16_t i = 0; i < mysize; ++i) {
		printf("received[%x]: %x\n", i, received[i]);
	}

	RaptorQ_free(&dec);



	free(myvec);
	for (uint32_t k = 0; k < next_encoded; ++k)
		free (encoded[k].symbol);
	free (encoded);
	return 0;
}