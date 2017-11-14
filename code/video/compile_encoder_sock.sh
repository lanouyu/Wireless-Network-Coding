
g++ ffsock_send.cpp -g -o ffsock_send.out `pkg-config --cflags --libs opencv` \
-I /usr/local/bin -L /usr/local/lib -lavcodec -lavutil \
-lpthread -lswresample -lm -lz -lavformat -lswscale -ldl -llzma -lx264 \
-L/home/blue/libRaptorQ-0.1.X/lib -lRaptorQ -lnet -lpcap -std=c++11 \
-I /usr/include/eigen3