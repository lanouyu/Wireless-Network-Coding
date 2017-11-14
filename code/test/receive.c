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
#define MAXSYMBOL 100

int main(void) {
	const uint16_t subsymbol = 8;
	const uint16_t symbol_size = 16;
	uint32_t mysize = 50;
	float drop_prob = 20.0;
	uint8_t overhead = 4;

	/********************** socket****************************/
	int listenfd, connfd;
	struct sockaddr_in servaddr, addr;
	char buff[MAXLINE];
	int n;

	if((listenfd = socket(AF_INET, SOCK_STREAM, 0))==-1){
	printf("create socket error: %s(errno: %d)\n",strerror(errno),errno);
	exit(0);
	}

	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(PORT);

	if (bind(listenfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) == -1){
	printf("bind socket error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}

	if (listen(listenfd, 10) == -1){
	printf("listen socket error: %s(errno: %d)\n", strerror(errno), errno);
	exit(0);
	}

	printf("======waiting for client's request======\n");

	if ((connfd = accept(listenfd, (struct sockaddr*)NULL, NULL)) == -1){
	printf("accept socket error: %s(errno: %d)", strerror(errno), errno);
	exit(0);
	}
	printf("connected!\n");

	/*******************receive****************************/
	struct pair
	{
		uint32_t id;
		uint32_t *symbol;
	};
	struct pair *encoded;
	uint32_t next_encoded = 0;
	uint32_t oti_scheme = 0;
	uint32_t oti_common = 0;

	n = recv(connfd, &oti_common, sizeof(oti_common), 0);
	//buff[n] = '\0';
	//memcpy(&oti_common, buff, sizeof(oti_common));
	printf("recv oti_common from client: %x\n", oti_common);

	recv(connfd, &oti_scheme, sizeof(oti_scheme), 0);
	n = recv(connfd, &oti_scheme, sizeof(oti_scheme), 0);
	//buff[n] = '\0';
	//memcpy(&oti_scheme, buff, sizeof(oti_scheme));
	printf("recv oti_scheme from client: %x\n", oti_scheme);

	encoded = (struct pair*) malloc(sizeof(struct pair)* MAXSYMBOL);
	for (uint32_t i = 0; i < MAXSYMBOL; ++i)
		encoded[i].symbol = NULL;

	n = recv(connfd, buff, sizeof(uint32_t)+symbol_size, 0);
	while (n > 1) {
		memcpy(&encoded[next_encoded].id, buff, sizeof(uint32_t));
		encoded[next_encoded].symbol = (uint32_t*) malloc(symbol_size);
		memcpy(encoded[next_encoded].symbol, buff+sizeof(uint32_t), 
				symbol_size);
		printf("recv encoded[%x]:\tid: %x;\tsymbol: %x\n", next_encoded, 
		encoded[next_encoded].id, *encoded[next_encoded].symbol);
		
		++next_encoded;
		n = recv(connfd, buff, sizeof(uint32_t)+symbol_size, 0);
	}

	printf("receive all data!\n");

	/******************decode******************************/
	struct RaptorQ_ptr *dec = RaptorQ_Dec(DEC_32, oti_common, oti_scheme);
	if (dec == NULL) {
		fprintf(stderr, "Could not initialize decoder!\n");
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
	for (uint32_t k = 0; k < next_encoded; ++k)
		free (encoded[k].symbol);
	free (encoded);
	return 0;
}