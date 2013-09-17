CC=gcc
CCP=g++

OBJS=jobconnect.o handylib.o spidevc.o miner.o json/libjson.a

CCFLAGS=-g -Wall -pthread -O2 -march=armv6 -mfloat-abi=hard -mfpu=vfp -Wall -I .
#CCFLAGS=-g -Wall -DNO_PTHREADS -pthread -O2 -I .

APP = miner

all: $(APP)

.cpp.o:
	$(CCP) $(CCFLAGS) -c $< -o $@

.c.o:
	$(CC) $(CCFLAGS) -c $< -o $@

# Generate static 32-bit binary!
# That will be able to run on multiple versions of OSes
$(APP): $(OBJS) 
#	$(CCP) $(CCFLAGS) $< libftd2xx.a json/libjson.a libftd2xx.a lu10.a -lrt -ldl -o $@
#	$(CC) -g -static -m32 $(CFLAGS) test.c bmtp.c tvec.c libftd2xx.a lu10.a -lrt -ldl -pthread -o $(APP) 
	$(CCP) $(CCFLAGS) $(OBJS) -o $@

clean:
	rm -f *.o $(APP)
	$(MAKE) -C json clean
json/libjson.a:
	$(MAKE) -C json

jobconnect.o: jobconnect.cpp miner.h

spidevc.o: spidevc.cpp miner.h

miner.o: miner.cpp miner.h
