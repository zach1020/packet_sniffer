#include <pcap.h>
#include <iostream>
#include <cstring>

// Callback function for each captured packet
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet ) {
	std::cout << "Packet captured!" << std::endl;
	std::cout << "Packet length: " << pkthdr->len << std::endl;
	std::cout << "Packet content: ";
	for(int i = 0; i < pkthdr->len; i++) {
		std::cout << std::hex << (int)packet[i] << " ";
	}

	std::cout << std::endl;
}

// Initialize and start packet capture
int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	pcap_if_t *device;

	// Find all avialble devices
	if (pcap_findalldevs(&alldevs, errbuf) == -1) {
		std::cerr << "Error finding devices: " << errbuf << std::endl;
		return 1;
	}

	// Select the first avaialb edevice (for simplicity)
	device = alldevs;
	if(!device) {
		std::cerr << "No devices found!" << std::endl;
		return 1;
	}

	// Open the device for packet capture
	pcap_t *handle = pcap_open_live(device->name, BUFSIZ, 1, 1000, errbuf);
	if(!handle) {
		std::cerr << "Error opening device: " << errbuf << std::endl;
		return 1;
	}

	std::cout << "Listening on " << device->name << "..." << std::endl;

	// Start packet caputre
	pcap_loop(handle, 0, packetHandler, nullptr);

	// Close the capture handle
	pcap_close(handle);

	// Free the device list
	pcap_freealldevs(alldevs);

	return 0;

}
