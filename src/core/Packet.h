#pragma once
#include <QByteArray>
#include <QString>
#include <QDateTime>
#include "ProtocolHeaders.h"
#include <QMetaType>
enum class LinkLayerType {
    Ethernet,
    Unknown
};

enum class NetworkProtocol {
    None,
    ARP,
    IPv4,
    IPv6
};

enum class TransportProtocol {
    None,
    ICMP,
    TCP,
    UDP
};


struct PacketSummary {
    QDateTime       timestamp;
    QString         srcAddr;    
    QString         dstAddr;
    QString         protocol;   
    QString         info;       
    int             length = 0;     
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


    Ipv6Header ipv6{};

    bool hasIpv6 = false;

    QByteArray       appPayload;   // 传输层之后的数据
};

class Packet
{
public:
    PacketSummary summary;
    ParsedLayers  layers;
    QByteArray    rawData;
};

Q_DECLARE_METATYPE(Packet)
