TARGETS = trail

all : $(TARGETS)
.PHONY: all

$(TARGETS): % : %_kern.o

%_kern.o : %_kern.c
	clang \
	    -target bpf \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-g \
	    -Wall \
	    -O2 -o $@ -c $<

clean:
	- rm *.o 
	- rm -f /sys/fs/bpf/$(TARGETS) 


