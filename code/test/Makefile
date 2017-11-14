send-receive: send-udp.c receive-udp.c
	gcc -o send-udp send-udp.c -L/home/blue/libRaptorQ/lib -lRaptorQ -lm -pthread -lnet
	gcc -o send-udp-2 send-udp-2.c  -L/home/blue/libRaptorQ/lib -lRaptorQ -lm -pthread -lnet
	gcc -o send-udp-symbol send-udp-symbol.c  -L/home/blue/libRaptorQ/lib -lRaptorQ -lm -pthread -lnet -lpcap
	gcc -o receive-udp receive-udp.c  -L/home/blue/libRaptorQ/lib -lRaptorQ -lm -pthread -lpcap
	gcc -o receive-udp-2 receive-udp-2.c  -L/home/blue/libRaptorQ/lib -lRaptorQ -lm -pthread -lpcap
	gcc -o receive-udp-symbol receive-udp-symbol.c  -L/home/blue/libRaptorQ/lib -lRaptorQ -lm -pthread -lpcap -lnet

clean:
	rm -rf *.o send-receive
