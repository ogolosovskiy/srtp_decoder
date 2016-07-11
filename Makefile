
CC=g++
CFLAGS= -std=c++11  -c -Wall  -fPIC -I../libsrtp/crypto/include/ -I../libsrtp/include/
LDLIBS = -shared -lsrtp2 -lpcap
LDFLAGS= -fPIC -L../libsrtp/
SOURCES=base64.cpp  decoder.cpp  pcap_reader.cpp  srtp_decoder.cpp
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=srtp_decoder

all: $(SOURCES) $(EXECUTABLE)


$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(LDLIBS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o ./srtp_decoder
