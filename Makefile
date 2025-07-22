TARGET=pcap-test
CXXFLAGS=-g

all: $(TARGET)

$(TARGET) : pcap-test.c
	$(LINK.cpp) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f $(TARGET)
	rm -f *.o
