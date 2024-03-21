cd src/
make
llvm-objdump -S fsx_kern.o
sudo ip link set dev lo xdpgeneric obj fsx_kern.o sec xdp
sudo bpftool prog trace log
