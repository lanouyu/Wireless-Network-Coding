
g++ ff_recv.cpp -g -o ff_recv.out `pkg-config --cflags --libs opencv` \
-I /usr/local/bin -L /usr/local/lib -lavcodec -lavutil \
-lpthread -pthread -lswresample -lm -lz -lavformat -lswscale -ldl -llzma -lx264 \
-L/home/blue/libRaptorQ-0.1.X/lib -lRaptorQ -lnet -lpcap -std=c++11 \
-I /usr/include/eigen3
