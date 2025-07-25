TARGET=pcap-test
CXXFLAGS=-g

all: $(TARGET)

$(TARGET) : pcap-test.c ethernet.c ip.c tcp.c
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap

clean:
	rm -f $(TARGET)
	rm -f *.o
