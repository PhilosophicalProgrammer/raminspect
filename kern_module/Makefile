obj-m += raminspect.o
raminspect-objs += src/raminspect.o
ccflags-y := -Wall -Werror -Wno-declaration-after-statement -Wno-discarded-qualifiers

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean