
g++ ff_send_cam.cpp -g -o ff_send_cam.out `pkg-config --cflags --libs opencv` \
-I /usr/local/bin -L /usr/local/lib -lavdevice -lavfilter \
-lavformat -lavcodec -lpthread -lswresample  -lswscale -lpostproc -lavutil -lasound \
-L /usr/lib/x86_64-linux-gnu/  -ldl -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes -lxcb-render \
-lxcb-shape -lxcb -lxcb-shape -lxcb -lx264 -lm -llzma -lbz2 -lz -pthread \
-L/home/blue/libRaptorQ-0.1.X/lib -lRaptorQ -lnet -lpcap -std=c++11 \
-I /usr/include/eigen3