include /usr/local/etc/PcapPlusPlus.mk

# All Target
all:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o pcap-convert main.o $(PCAPPP_LIBS)

debug:
	g++ $(PCAPPP_BUILD_FLAGS) $(PCAPPP_INCLUDES) -g -c -o main.o main.cpp
	g++ $(PCAPPP_LIBS_DIR) -g -static-libstdc++ -o pcap-convert main.o $(PCAPPP_LIBS)


# Clean Target
clean:
	rm main.o
	rm pcap-convert
