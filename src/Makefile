TARGETS = fsx
HEADERS = fsx_struct.h parsing_helper.h
INCLUDE_DIRS = -I/usr/include/$(shell uname -m)-linux-gnu -I .


all: $(TARGETS)
.PHONY: all

$(TARGETS): % : %_kern.o 


%_kern.o :%_kern.c $(HEADERS)
	clang \
		-target bpf \
		$(INCLUDE_DIRS)  \
		-g \
		-w \
		-O2 -o $@ -c $<

clean:
	- rm *.o 
	- rm -f /sys/fs/bpf/$(TARGETS)