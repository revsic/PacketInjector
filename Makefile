CC = g++
TARGET = http_inject
OBJECTS = Protocol/Tcp.o Protocol/IPv4.o Protocol/Ethernet.o PacketInjector.o main.o

all : $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ -lpcap

clean:
	rm -rf *.o Protocol/*.o http_inejct
