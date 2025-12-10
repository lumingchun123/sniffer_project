#pragma once
#include <QByteArray>
#include <QString>
#include <QDateTime>
#include "ProtocolHeaders.h"

enum class LinkLayerType {
    Ethernet,
    Unknown
};

enum class NetworkProtocol {
    None,
    ARP,
    IPv4
};

enum class TransportProtocol {
    None,
    ICMP,
    TCP,
    UDP
};


struct PacketSummary {
    QDateTime       timestamp;
    QString         srcAddr;    // IP/MAC 统一转成字符串
    QString         dstAddr;
    QString         protocol;   // "ARP"/"TCP"/"UDP" 等
    QString         info;       // 一行简要信息，列表里显示
    int             length = 0;     // 报文字节数
};


class ParsedLayers {
public:
    NetworkProtocol  networkProto = NetworkProtocol::None;
    TransportProtocol transportProto = TransportProtocol::None;

    EthernetHeader   eth{};
    bool             hasEth = false;

    ArpHeader        arp{};
    bool             hasArp = false;

    IpHeader         ip{};
    bool             hasIp = false;

    IcmpHeader       icmp{};
    bool             hasIcmp = false;

    TcpHeader        tcp{};
    bool             hasTcp = false;

    UdpHeader        udp{};
    bool             hasUdp = false;

    QByteArray       appPayload;   // 传输层之后的数据
};

class Packet
{
public:
    PacketSummary summary;
    ParsedLayers  layers;
    QByteArray    rawData;
};

