#include <cstdio>
#include <pcap.h>
#include <vector>
#include <utility>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : send-arp enp6s0 192.168.200.141 192.168.200.254\n");
}

struct Param {
	char* dev_; // 인터페이스 이름
	std::vector<std::pair<Ip, Ip>> pairs_; // (sender IP, target IP) 쌍 목록 
};

Param param;

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 4) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	for (int i = 2; i + 1 < argc; i += 2) {
		param->pairs_.push_back({Ip(argv[i]), Ip(argv[i + 1])});
	}
	return true;
}

// https://www.binarytides.com/c-program-to-get-mac-address-from-interface-name-on-linux/
Mac getMyMac(const char* dev) {
	int fd;
	struct ifreq ifr;
	unsigned char *mac;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

	return Mac(mac);
}

Ip getMyIp(const char* dev) {
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	struct sockaddr_in* sin = (struct sockaddr_in*)&ifr.ifr_addr;
	return Ip(ntohl(sin->sin_addr.s_addr));
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return EXIT_FAILURE;

	char* dev = param.dev_;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	// 1. Attacker MAC 주소 휙득
	Mac attackerMac = getMyMac(dev);
	// 2. Attacker IP 주소 휙득
	Ip attackerIp = getMyIp(dev);

	printf("MAC: %s\n", std::string(attackerMac).c_str());
	printf("IP : %s\n", std::string(attackerIp).c_str());

	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("00:00:00:00:00:00");
	packet.eth_.smac_ = Mac("00:00:00:00:00:00");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac("00:00:00:00:00:00");
	packet.arp_.sip_ = htonl(Ip("0.0.0.0"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip("0.0.0.0"));

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
	}

	pcap_close(pcap);
}
