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

#define MAXLINE 4096
#define PORT 6666

// Demonstration of how to use the C interface.
// This is kinda basic, we use only one function
// to encode, drop some (random) packets, and then
// decode what remains.

// Encode / decode "mysize" uint32_t
// for a more elaborate examlpe with different alignments, see test_cpp
bool decode (int sockfd, uint32_t mysize, float drop_prob, uint8_t overhead);
bool decode (int sockfd, uint32_t mysize, float drop_prob, uint8_t overhead)
{
	uint32_t *myvec;


	srand((uint32_t)time(NULL));
	// initialize vector with random data
	myvec = (uint32_t *) malloc (mysize * sizeof(uint32_t));
	for (uint32_t i = 0; i < mysize; ++i)
{		myvec[i] = (uint32_t)rand();
		printf("myvec[%x]: %x\n", i, myvec[i]);
}
	// what needs to be sent in a packet.
	// 32bit id (sbn + esi) and the actual data.
	struct pair {
		uint32_t id;
		uint32_t *symbol;
	};

	// will keep "sent" symbols here.
	struct pair *encoded;

	// symbol and sub-symbol sizes
	const uint16_t subsymbol = 8;
	const uint16_t symbol_size = 16;


	/***********socket***********/

	char buff[MAXLINE];
	

	/*
	 * Now start decoding things
	 */

	// use multiple blocks
	struct RaptorQ_ptr *enc = RaptorQ_Enc (ENC_32, myvec, mysize, subsymbol,
										symbol_size, 500);

	if (enc == NULL) {
		fprintf(stderr, "Coud not initialize encoder.\n");
		free (myvec);
		return false;
	}

	// start background precomputation while we get the source symbols.
	RaptorQ_precompute (enc, 2, true);

	/* everything is encoded now.
	 * well, it might be running in background, but don't worry:
	 * if needed you'll just block on the call.
	 */

	if (drop_prob > 90.0)
		drop_prob = 90.0;	// this is still too high probably.


	// we used a lot of memory before so there will be only one block.
	// allocate memory only for that data.
	uint32_t symbols_tot = 0;
	for (uint8_t b = 0; b < RaptorQ_blocks (enc); ++b) {
		uint16_t sym = RaptorQ_symbols (enc, b);
		symbols_tot += (sym + overhead + drop_prob*sym);
	}
	printf("symbols_tot: %x\n",symbols_tot);
	encoded = (struct pair *) malloc (sizeof(struct pair) * symbols_tot);
	for (uint32_t i = 0; i < symbols_tot; ++i)
		encoded[i].symbol = NULL;

	uint32_t next_encoded = 0;

	uint32_t blocks = RaptorQ_blocks (enc);
	for (uint8_t block = 0; block < blocks; ++block) {
		printf("Block: %i\n", block);
		uint32_t sym_for_blk = RaptorQ_symbols (enc, block);
		// some source packets will be lost. Be sure we will have
		// exactly (overhead + dropped_source) repair symbols.
		// and "sym_for_blk + overhead" total symbols
		int32_t repair = overhead;
		for (uint32_t source = 0; source < sym_for_blk; ++source) {
			float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
			if (dropped < drop_prob) {
				// dropped source symbol. Don't even get it.
				++repair;
				continue;
			}
			// successfully transmitted source symbol. Add it to "encoded";
			encoded[next_encoded].id = RaptorQ_id (source, block);
			uint32_t data_size = symbol_size / sizeof(uint32_t);
			encoded[next_encoded].symbol = (uint32_t *) malloc (symbol_size);
			uint32_t *data = encoded[next_encoded].symbol;
			uint64_t written = RaptorQ_encode (enc, (void **)&data, data_size,
													source, (uint8_t)block);
			// printf("after source symbol encoded written: %x", written);
			// "data" now points to "encoded[next_encoded].symbol + written"
			// you can use this for some tricks if you *really* need it.
			if (written != data_size) {
				fprintf(stderr, "Error in getting source symbol\n");
				free (myvec);
				for (uint32_t k = 0; k <= next_encoded; ++k)
					free (encoded[k].symbol);
				free (encoded);
				RaptorQ_free (&enc);
				return false;
			}
			++next_encoded;
		}
		printf("Dropped %i source packets\n", repair - overhead);
		// some repair packets will be lost. Be sure we will have
		// exactly (overhead + dropped_source) repair symbols,
		// and "sym_for_blk + overhead" total symbols
		uint32_t sym_rep;
		for (sym_rep = sym_for_blk; repair > 0 &&
						sym_rep < RaptorQ_max_repair (enc, block); ++sym_rep) {
			// repair symbols can be dropped, too!
			float dropped = ((float)(rand()) / (float) RAND_MAX) * (float)100.0;
			if (dropped < drop_prob) {
				// dropped repair symbol. Don't even get it.
				continue;
			}
			--repair;
			// successfully transmitted repair symbol. Add it to "encoded";
			encoded[next_encoded].id = RaptorQ_id (sym_rep, block);
			uint32_t data_size = symbol_size / sizeof(uint32_t);
			encoded[next_encoded].symbol = (uint32_t *) malloc (symbol_size);
			uint32_t *data = encoded[next_encoded].symbol;
			uint64_t written = RaptorQ_encode (enc, (void **)&data, data_size,
													sym_rep, (uint8_t)block);
			// "*data" now points to "encoded[next_encoded].symbol + written"
			// you can use this for some tricks if you *really* need it.
			if (written != data_size) {
				fprintf(stderr, "Error in getting repair symbol\n");
				free (myvec);
				for (uint32_t k = 0; k <= next_encoded; ++k)
					free (encoded[k].symbol);
				free (encoded);
				RaptorQ_free (&enc);
				return false;
			}
			++next_encoded;
		}
	printf("send %x repair packet\n",next_encoded);
		if (sym_rep == RaptorQ_max_repair (enc, block)) {
			fprintf(stderr, "Maybe losing %f%% symbols is too much?\n",
																	drop_prob);
			free (myvec);
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			RaptorQ_free (&enc);
			return false;
		}
}
	uint32_t oti_scheme = RaptorQ_OTI_Scheme (enc);
	uint64_t oti_common = RaptorQ_OTI_Common (enc);

	printf(" oti_common: %x\n", oti_common);
	printf(" oti_scheme: %x\n", oti_scheme);
	// optionally: free the memory just of block 0
	// this is done by the RaptorQ_free call anyway
	// RaptorQ_free_block (&enc, 0);
	// free the whole encoder memory:
	RaptorQ_free (&enc);
	// enc == NULL now	
	

	printf("send oti_common: %x\n", oti_common);
	memcpy(buff, &oti_common, sizeof(oti_common));
	if (send(sockfd,buff, sizeof(oti_common), 0) <0 ){
	printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}

	printf("send oti_scheme: %x\n", oti_scheme);
	memcpy(buff, &oti_scheme, sizeof(oti_scheme));
	if (send(sockfd,buff, sizeof(oti_scheme), 0) <0 ){
	printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}

	for (uint32_t k = 0; k < next_encoded; ++k){
	printf("send encoded[%x]: id: %x;\tsymbol: %x\n", k, encoded[k].id, *encoded[k].symbol);
	memcpy(buff, &encoded[k].id, sizeof(encoded[k].id));
	memcpy(buff+sizeof(encoded[k].id), encoded[k].symbol, symbol_size);
	if (send(sockfd, buff, sizeof(encoded[k].id)+symbol_size, 0) < 0){
	printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}}
	
	strcpy(buff, "");
	if (send(sockfd, buff, 0, 0) < 0){
	printf("send msg error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}
	close(sockfd);


	/*
	 * Now start decoding things
	 */

	printf("start decoding\n");

	struct RaptorQ_ptr *dec = RaptorQ_Dec (DEC_32, oti_common, oti_scheme);
	// printf("dec: %x\n", dec);

	if (dec == NULL) {
		fprintf(stderr, "Could not initialize decoder!\n");
		free (myvec);
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
		return false;
}

	// we made things so there is only one block.
	// if you want to generalize things,
	// RaptorQ_blocks (dec); will tell you how many blocks
	// there are.
	for (size_t i = 0; i < next_encoded; ++i) {
		uint32_t *data = encoded[i].symbol;
		uint32_t data_size = RaptorQ_symbol_size (dec) / sizeof(uint32_t);
		printf("encoded[%x]=%x\tdata_size: %x\n", i,*data, data_size);
		if (!RaptorQ_add_symbol_id (dec, (void **)&data, data_size,
															encoded[i].id)) {
			// this can happen if we receive the same symbol twice
			// (which doesn't make much sense). But we constructed
			// everything so that there are no duplicates here,
			// so this is some other error.
			fprintf(stderr, "Error: couldn't add the symbol to the decoder\n");
			free (myvec);
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			RaptorQ_free (&dec);
			return false;
		}
		// "data" now points to encoded[i].symbol +
		//					ceil(RaptorQ_symbol_size(dec) / sizeof(uint32_t))
	}

	// make sure that there's enough place in "received" to get the
	// whole decoded data.
	// note: the length of the decoded data is in bytes and might not fit
	// a whole uint32_t.
	uint64_t decoded_size = ceil (RaptorQ_bytes (dec) / sizeof(uint32_t));
	uint32_t *received = (uint32_t *) malloc (decoded_size * sizeof(uint32_t));

	for (uint32_t *shit = received; shit != received + decoded_size; ++ shit);
	uint32_t *rec = received;
	uint64_t written = RaptorQ_decode (dec, (void **)&rec, decoded_size);
	
	printf("written: %x\ndecoded_size: %x\nmysize: %x\n",
		written, decoded_size, mysize);

	if ((written != decoded_size) || (decoded_size != mysize)) {
		fprintf(stderr, "Couldn't decode: %i - %lu\n", mysize, written);
		free (myvec);
		free(received);
		for (uint32_t k = 0; k < next_encoded; ++k)
			free (encoded[k].symbol);
		free (encoded);
		RaptorQ_free(&dec);
		return false;
	} else {
		printf("Decoded: %i\n", mysize);
	}
	// check if everything was decoded nicely
/*	for (uint16_t i = 0; i < mysize; ++i) {
		if (myvec[i] != received[i]) {
			fprintf(stderr, "FAILED, but we though otherwise! %i - %f: %i "
													"%i -- %i\n",
													mysize, drop_prob, i,
													myvec[i], received[i]);
			free (myvec);
			free (received);
			for (uint32_t k = 0; k < next_encoded; ++k)
				free (encoded[k].symbol);
			free (encoded);
			RaptorQ_free (&dec);
			return false;
		}
	}
*/
	for (uint16_t i = 0; i < mysize; ++i) {
	printf("received[%x]: %x\n", i, received[i]);
	}
	// optionally: free the memory just of block 0
	// this is done by the RaptorQ_free call anyway
	// RaptorQ_free_block (&dec, 0);
	// free the decoder memory
	free (myvec);
	free(received);
	for (uint32_t k = 0; k < next_encoded; ++k)
		free (encoded[k].symbol);
	free (encoded);
	RaptorQ_free(&dec);
	// dec == NULL now
	return true;
}

int main (int argc, char** argv)
{

	int sockfd, n;
	char recvline[4096], sendline[4096];
	struct sockaddr_in servaddr;

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


	// encode and decode
	bool ret = decode (sockfd, 50, 10.0, 4);

	return (ret == true ? 0 : -1);
}

