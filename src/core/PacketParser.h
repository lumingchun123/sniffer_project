#pragma once
#include "Packet.h"
#include "ProtocolHeaders.h"
#include <pcap.h>

class IpReassembler;

class PacketParser
{
public:
    PacketParser();

    // pcap 回调得到的数据，解析成 Packet
    Packet parse(const pcap_pkthdr *header, const u_char *data,
                 IpReassembler *reassembler);

private:
    void parseEthernet(const u_char *&ptr, int &remaining, ParsedLayers &layers);
    void parseArp(const u_char *ptr, int remaining, ParsedLayers &layers);
    void parseIp(const u_char *&ptr, int &remaining, ParsedLayers &layers);
    void parseIcmp(const u_char *ptr, int remaining, ParsedLayers &layers);
    void parseTcp(const u_char *&ptr, int &remaining, ParsedLayers &layers);
    void parseUdp(const u_char *&ptr, int &remaining, ParsedLayers &layers);

    PacketSummary buildSummary(const ParsedLayers &layers, int len,
                               const timeval &ts);
};
