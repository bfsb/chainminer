all: libjson.a

clean:
	rm -f *.o libjson.a

%.o: %.cpp
	g++ -pthread -I .. -O2 -g -c $< -o $@

OBJS=json_reader.o json_value.o json_writer.o

# jsonrpc_client.o jsonrpc_handler.o jsonrpc_server.o jsonrpc_tcpclient.o jsonrpc_tcpserver.o jsonrpc_udpclient.o jsonrpc_udpserver.o netstring.o networking.o system.o

#jsonrpc_httpclient.o 

libjson.a: $(OBJS)
	rm -f libjson.a
	ar cruv libjson.a $(OBJS)

#	ld -Ur $(OBJS) -o json.o

