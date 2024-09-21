sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386 m4
sudo apt install linux-headers-$(uname -r)
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump 

cd modules/xdp-tools
./configure
make 
make install
cd ../../
cd src
make
cd ..