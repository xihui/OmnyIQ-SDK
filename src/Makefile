#sinclude mips.mk
#sinclude arm-brcm.mk

ifdef HOST
CC= $(HOST)-gcc
CXX = $(HOST)-g++
AR = $(HOST)-ar
LD = $(HOST)-ld
else
CC= gcc
CXX = g++
AR = ar
LD = ld
endif

IKSEMEL_DIR = third_parts/iksemel-1.4
BUILD_DIR = ./build

STATIC_LIB = libdevice.a
#DYNAMIC_LIB = libdevice.so
TARGETS = $(STATIC_LIB) $(DYNAMIC_LIB)

SRC = $(shell ls *.c cJSON/*.c)
#SRC = sfxhash.c
INCS = $(shell ls *.h cJSON/*.h)
#INCS = sfxhash.h
OBJS = $(SRC:%.c=%.o)
DEPS = $(OBJS:%.o=%.d)

INC_PATH = -I. -I$(IKSEMEL_DIR)/include -IcJSON
LD_PATH = 
#LD_LIBS = -lpthread -lrt
LD_LIBS = -lm

LD_FLAGS = -g -shared
AR_FLAGS = rs
C_FLAGS = -Wall -fPIC
RM = rm -f

all : iksemel $(STATIC_LIB)

iksemel :
	(cd $(IKSEMEL_DIR) && if [ ! -f Makefile ]; then (echo `pwd` && ./configure --host=$(HOST) --with-libgnutls=no); fi)
	make -C $(IKSEMEL_DIR)

$(STATIC_LIB) : $(OBJS)
	@echo "=*= making static library $@ =*="
	$(AR) $(AR_FLAGS) $@ ${OBJS} $(IKSEMEL_DIR)/src/*.o 
	ranlib $@
$(DYNAMIC_LIB) : $(OBJS)
	@echo "=*= making dynamic library $@ =*="
	$(LD) $(LD_FLAGS) $(LD_LIBS) $^ $(IKSEMEL_DIR)/src/*.o -o $@
%.d : %.c
	$(CC) $(INC_PATH) -MM -MD $(C_FLAGS) $< -o $@
%.o : %.c
	$(CC) $(C_FLAGS) $(INC_PATH) -c $< -o $@
sinclude $(DEPS)
distclean : clean
	if [ -f $(IKSEMEL_DIR)/Makefile ] ;then make -C $(IKSEMEL_DIR) distclean; fi
clean:
	if [ -f $(IKSEMEL_DIR)/Makefile ] ;then make -C $(IKSEMEL_DIR) clean; fi
	$(RM) $(OBJS) $(TARGETS) $(DEPS)

install:
	mkdir -p $(BUILD_DIR)/lib
	mkdir -p $(BUILD_DIR)/examples
	mkdir -p $(BUILD_DIR)/include
	cp DeviceProfileInterface.h $(BUILD_DIR)/include
	cp Debug.h $(BUILD_DIR)/include
	cp cJSON/cJSON.h $(BUILD_DIR)/include
	cp $(STATIC_LIB) $(BUILD_DIR)/lib

#clean_src:
#	$(RM) $(SRC)
#depend:
#	for i in $(OBJS)
#	do
#	gcc -MM $(i) > $(i:%.o=%.d)
#	done
.PHONY : all clean install clean_src iksemel distclean
