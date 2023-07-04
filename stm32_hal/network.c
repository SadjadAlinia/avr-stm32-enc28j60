#include <string.h>
#include "enc28j60.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "network.h"
#include "icmp.h"
#include "util.h"
#include "tcp.h"
#include "udp.h"

#if defined(TCP) || defined(UDP)
unsigned short connectPortRotaiting = NET_MIN_DINAMIC_PORT;
#endif

unsigned char buffer[NET_BUFFER_SIZE];
char RxBuffer[100];

unsigned char TCP_ON_NEW_CONNETION(const unsigned char connectionId) {
	return NET_HANDLE_RESULT_OK;
}

void TCP_ON_CONNECT(const unsigned char connectionId) {
	return;
}

void TCP_ON_INCOMING_DATA(const unsigned char connectionId,
		const unsigned char *data, unsigned short dataLength) {
	memcpy((char *)&RxBuffer,(char *)data,dataLength);
	TcpSendData(connectionId, 10, data, dataLength);
}

void TCP_ON_DISCONNECT(const unsigned char connectionId) {

}

void NetInit() {
	enc28j60_init();
	ArpInit();
#ifdef TCP
	TCP_ON_NEW_CONNETION_CALLBACK = &TCP_ON_NEW_CONNETION;
	TCP_ON_CONNECT_CALLBACK = &TCP_ON_CONNECT;
	TCP_ON_INCOMING_DATA_CALLBACK = &TCP_ON_INCOMING_DATA;
	TCP_ON_DISCONNECT_CALLBACK = &TCP_ON_DISCONNECT;
	TcpInit();
#endif
#ifdef HTTP
	HttpInit();
 #endif
}

unsigned char* NetGetBuffer() {
	return buffer;
}

void NetHandleNetwork() {
	unsigned short length;
	length = enc28j60_packet_receive((unsigned char*) &buffer, NET_BUFFER_SIZE);
	if (length == 0) {
		return;
	}
	NetHandleIncomingPacket(length);
}

void NetHandleIncomingPacket(unsigned short length) {
	{
		unsigned char srcMac[MAC_ADDRESS_SIZE];
		memcpy(srcMac, buffer + ETH_SRC_MAC_P, MAC_ADDRESS_SIZE);
		if (ArpPacketIsArp(buffer, ARP_OPCODE_REQUEST_V)) {
			ArpSendReply(buffer, srcMac);
			return;
		}
		if (!ip_packet_is_ip(buffer)) {
			return;
		}
		unsigned char srcIp[IP_V4_ADDRESS_SIZE];
		memcpy(srcIp, buffer + IP_SRC_IP_P, IP_V4_ADDRESS_SIZE);
#ifdef ICMP
		if (icmp_send_reply(buffer, length, srcMac, srcIp)) {
			return;
		}
#endif
	}
#ifdef UDP
	if (buffer[IP_PROTO_P] == IP_PROTO_UDP_V) {
		UdpHandleIncomingPacket(buffer, length);
		return;
	}
#endif
#ifdef TCP
	if (buffer[IP_PROTO_P] == IP_PROTO_TCP_V) {
		TcpHandleIncomingPacket(buffer, length);
		return;
	}
#endif
}
