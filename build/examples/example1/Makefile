ifdef HOST
CC = $(HOST)-gcc
AR = $(HOST)-ar
LD = $(HOST)-ld
else
CC = gcc
AR = ar
LD = ld
endif
RM = rm -f

TGT = client
SRC = $(shell ls |grep "\.c$$")
INCS = $(shell ls |grep "\.h$$")
#SRC = $(shell ls *.c)
#INCS = $(shell ls *.h)

OBJS = $(SRC:%.c=%.o)
DEPS = $(OBJS:%.o=%.d)

INC_PATH = -I. -I../../include
#ST stands for static
LD_PATH = -L../../lib
#ST_LIBS = Device/libdevice.a
ST_LIBS = 
#ST_LIBS = ../lib/libtimer.a
LD_LIBS = -lm -ldevice -lpthread

CFLAGS = -O2 -g
LDFLAGS = -Wl,-O2
ARFLAGS =

all : $(TGT)
$(TGT) : $(OBJS)
#$(TGT) : $(OBJS) $(ST_LIBS)
	$(CC) $(CFLAGS) $(LD_PATH) $^ $(LD_LIBS) -o $@
%.d : %.c
	@$(CC) $(INC_PATH) -MM -MD $<
%.o : %.c
	$(CC) $(CFLAGS) $(INC_PATH) -c $<
sinclude $(DEPS)
clean:
	$(RM) $(OBJS) $(TGT) $(DEPS)
install:
	cp $(TGT) ../bin -f

#depend:
#	for i in $(OBJS)
#	do
#	gcc -MM $(i) > $(i:%.o=%.d)
#	done
.PHONY : all clean install clean_src
