#pragma once
#include <QtGlobal>
#include <cstdint>  //这两个库是为了保证跨平台类型长度也相同

#pragma pack(push, 1) //让结构体编译时按1Byte对齐

struct EthernetHeader{
    quint8 dstMac[6];
    quint8 srcMac[6];
    quint16 etherType; //注意不需要FCS帧，因为网卡会自动丢弃，收到的MAC都是只有前面的首部
};


struct ArpHeader {
    quint16 htype;//硬件类型
    quint16 ptype;//上层协议类型
    quint8  hlen;//mac地址长度
    quint8  plen;//ip地址长度
    quint16 oper;//操作类型
    quint8  sha[6];//源mac地址
    quint32 spa;//源ip地址
    quint8  tha[6];//目的mac地址
    quint32 tpa;//目的ip地址
};


struct IpHeader {
    quint8  verIhl;      //高4位版本, 低4位首部长度
    quint8  tos;
    quint16 totalLength;
    quint16 identification;
    quint16 flagsFragOffset; //3 bits flags + 13 bits offset
    quint8  ttl;
    quint8  protocol;       //1:ICMP, 6:TCP, 17:UDP
    quint16 headerChecksum;
    quint32 srcIp;
    quint32 dstIp;
    quint8 option[40];
};

struct IcmpHeader {
    quint8  type;
    quint8  code;
    quint16 checksum;
};


struct TcpHeader {
    quint16 srcPort;
    quint16 dstPort;
    quint32 seq;
    quint32 ack;
    quint8  dataOffsetRes;  // 高4位为数据偏移
    quint8  flags;
    quint16 window;
    quint16 checksum;
    quint16 urgentPtr;
    // 选择字段省略
};

struct UdpHeader {
    quint16 srcPort;
    quint16 dstPort;
    quint16 length;
    quint16 checksum;
};

#pragma pack(pop)


