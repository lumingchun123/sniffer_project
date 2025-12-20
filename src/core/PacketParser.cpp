#include "Packet.h"
#include "ProtocolHeaders.h"
#include <pcap.h>
#include "IpReassembler.h"
#include "Packet.h"
#include "PacketParser.h"
#include <QtEndian>
#include <QtNetwork/QHostAddress>
#include <QtNetwork/qhostaddress.h>



bool isFragmented(const IpHeader &ip)//判断一个ip包是不是分片
{
    quint16 flagsOffset = ip.flagsFragOffset;
    quint16 offset8     = flagsOffset & 0x1FFF;
    bool    MF          = flagsOffset & 0x2000;

    return (offset8 != 0) || MF;
}



PacketParser::PacketParser(){}
// pcap 回调得到的数据，解析成 Packet
Packet PacketParser::parse(const pcap_pkthdr *header, const u_char *data,
             IpReassembler *reassembler){
    Packet result_packet;
    int remaining = header->caplen;//这个remaining会随解析过程一直变短，最后成为packet的apppayload的length
    const u_char* current_head = data; //这个当前最开头的指针也会随解析过程往后指，最后变成应用层的开始指针
    result_packet.rawData = QByteArray(reinterpret_cast<const char*>(data), header->caplen);//qbytearray不仅仅是指针，还有长度
    parseEthernet(current_head, remaining, result_packet.layers);
    if (result_packet.layers.eth.etherType == 0x0800){//尝试解析IP
        QByteArray possible_ip_reassemble_payload = QByteArray();
        parseIp(current_head, remaining, result_packet.layers);
        if (result_packet.layers.hasIp){

//********************************************************************
            //todo: 处理分片重组后的payload的解析！！！               ｜
//********************************************************************
            if (isFragmented(result_packet.layers.ip)){
                possible_ip_reassemble_payload = reassembler->feedFragment(result_packet.layers.ip, QByteArray(reinterpret_cast<const char*>(current_head), remaining));
                if (possible_ip_reassemble_payload.isEmpty()){
                    result_packet.layers.networkProto = NetworkProtocol::IPv4;
                    result_packet.layers.transportProto = TransportProtocol::None;
                    return Packet();//这里IP报片还没到齐，那就不把它们显示出来了
                }
                else{//组装出来了完整IP报文
                    current_head = reinterpret_cast<const u_char*>(possible_ip_reassemble_payload.constData());
                    remaining = possible_ip_reassemble_payload.size();

                    if(result_packet.layers.ip.protocol == 6){
                        parseTcp(current_head, remaining, result_packet.layers);
                        result_packet.summary = buildSummary(
                            result_packet.layers,
                            header->len,         
                            header->ts           
                            );
                        result_packet.layers.appPayload =
                            QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                        return result_packet;
                    }

                    if (result_packet.layers.ip.protocol == 17){
                        parseUdp(current_head, remaining, result_packet.layers);
                        result_packet.summary = buildSummary(
                            result_packet.layers,
                            header->len,         
                            header->ts           
                            );
                        result_packet.layers.appPayload =
                            QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                        return result_packet;
                    }

                    if (result_packet.layers.ip.protocol == 1){
                        parseIcmp(current_head, remaining, result_packet.layers);
                        result_packet.summary = buildSummary(
                            result_packet.layers,
                            header->len,         
                            header->ts            
                            );
                        result_packet.layers.appPayload =
                            QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                        return result_packet;
                    }
                }
            }



           //以下为这个IP不是分片的情况
            if (result_packet.layers.ip.protocol == 6 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的tcp包，不需要任何重组，就直接解析掉
                parseTcp(current_head, remaining, result_packet.layers);
                result_packet.summary = buildSummary(
                    result_packet.layers,
                    header->len,          
                    header->ts            
                    );
                result_packet.layers.appPayload =
                    QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                return result_packet;
            }

            if (result_packet.layers.ip.protocol == 17 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的udp包，不需要任何重组，就直接解析掉
                parseUdp(current_head, remaining, result_packet.layers);
                result_packet.summary = buildSummary(
                    result_packet.layers,
                    header->len,          
                    header->ts            
                    );
                result_packet.layers.appPayload =
                    QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                return result_packet;
            }

            if (result_packet.layers.ip.protocol == 1 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的icmp包，不需要任何重组，就直接解析掉
                parseIcmp(current_head, remaining, result_packet.layers);
                result_packet.summary = buildSummary(
                    result_packet.layers,
                    header->len,          
                    header->ts            
                    );
                result_packet.layers.appPayload =
                    QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                return result_packet;
            }
        }
    }

    else if (result_packet.layers.eth.etherType == 0x0806){ 
        parseArp(current_head, remaining, result_packet.layers);
        result_packet.summary = buildSummary(
            result_packet.layers,
            header->len,         
            header->ts           
            );
        return result_packet;
    }

    else if (result_packet.layers.eth.etherType == 0x86DD) { // IPv6
        
        if (remaining < 40) {
          
            return Packet();
        }

        const Ipv6Header* ip6 = reinterpret_cast<const Ipv6Header*>(current_head);


        const quint8 version = (qFromBigEndian(ip6->verTcFl) >> 28) & 0x0F;
        if (version != 6) {
            return Packet();
        }

        const quint16 payloadLen = qFromBigEndian(ip6->payloadLength);
        quint8 next = ip6->nextHeader;


        result_packet.layers.hasIpv6 = true;
        result_packet.layers.ipv6 = *ip6;
        result_packet.layers.networkProto = NetworkProtocol::IPv6; 

  
        current_head += 40;
        remaining -= 40;

     
        if (payloadLen < remaining) {
            remaining = payloadLen;
        }

      
        auto needBytes = [&](int n) { return remaining >= n; };

        
        while (true) {
            if (next == 0   ||
                next == 43  || 
                next == 60  || 
                next == 51  || 
                next == 50  )  
            {
                if (!needBytes(2)) return Packet();

               
                int extLenBytes = 0;

                if (next == 51) { // AH
                    if (!needBytes(2)) return Packet();
                    quint8 ahNext = current_head[0];
                    quint8 ahLen  = current_head[1];
                    
                    extLenBytes = (static_cast<int>(ahLen) + 2) * 4;
                    if (!needBytes(extLenBytes)) return Packet();
                    next = ahNext;
                } else if (next == 50) { 
                    result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
                    return result_packet;
                } else {
                    quint8 extNext = current_head[0];
                    quint8 extLen  = current_head[1];
                    extLenBytes = (static_cast<int>(extLen) + 1) * 8; 
                    if (!needBytes(extLenBytes)) return Packet();
                    next = extNext;
                }

                current_head += extLenBytes;
                remaining -= extLenBytes;
                continue;
            }
            else if (next == 44) { 
                if (!needBytes(8)) return Packet();

                
                quint8 fragNext = current_head[0];
                quint16 offResM = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(current_head + 2));
                quint16 fragOff8 = (offResM >> 3) & 0x1FFF;
                bool more = (offResM & 0x1) != 0;

                
                current_head += 8;
                remaining -= 8;
                next = fragNext;

               
                if (fragOff8 != 0 || more) {
                    result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
                    return result_packet;
                }
                continue;
            }

            break; 
        }


        if (next == 17) { // UDP
            parseUdp(current_head, remaining, result_packet.layers);
            result_packet.layers.transportProto = TransportProtocol::UDP;

            result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
            result_packet.layers.appPayload =
                QByteArray(reinterpret_cast<const char*>(current_head), remaining);
            return result_packet;
        }

        if (next == 6) { // TCP
            parseTcp(current_head, remaining, result_packet.layers);
            result_packet.layers.transportProto = TransportProtocol::TCP;

            result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
            result_packet.layers.appPayload =
                QByteArray(reinterpret_cast<const char*>(current_head), remaining);
            return result_packet;
        }

        if (next == 58) { // ICMPv6

            result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
            result_packet.layers.appPayload =
                QByteArray(reinterpret_cast<const char*>(current_head), remaining);
            return result_packet;
        }

        result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
        return result_packet;
    }


    result_packet.summary = buildSummary(
        result_packet.layers,
        header->len,        
        header->ts            
        );

    return result_packet;
}


void PacketParser::parseEthernet(const u_char *&ptr, int &remaining, ParsedLayers &layers){
    if (remaining < 14){return;}
    else {
        const EthernetHeader *eth = reinterpret_cast<const EthernetHeader*> (ptr);
        memcpy(layers.eth.dstMac, eth->dstMac, 6);
        memcpy(layers.eth.srcMac, eth->srcMac, 6);
        layers.eth.etherType = qFromBigEndian(eth->etherType);//这里多字节整数的存储要注意大端序和小端序的问题

        layers.hasEth = true;
        ptr += 14;
        remaining -= 14;

    }
}
void PacketParser::parseArp(const u_char *ptr, int remaining, ParsedLayers &layers){
    if (remaining < 28){return;}
    else {
        const ArpHeader *arp = reinterpret_cast<const ArpHeader*> (ptr);
        layers.arp.htype = qFromBigEndian(arp->htype);
        layers.arp.ptype = qFromBigEndian(arp->ptype);
        layers.arp.hlen = arp->hlen;
        layers.arp.plen = arp->plen;
        layers.arp.oper = qFromBigEndian(arp->oper);
        memcpy(layers.arp.sha, arp->sha, 6);
        memcpy(layers.arp.tha, arp->tha, 6);
        layers.arp.spa = qFromBigEndian(arp->spa);
        layers.arp.tpa = qFromBigEndian(arp->tpa);

        layers.hasArp = true;
        layers.networkProto = NetworkProtocol::ARP;

    }

}
void PacketParser::parseIp(const u_char *&ptr, int &remaining, ParsedLayers &layers){
    if (remaining == 0) return;
    const IpHeader *ip = reinterpret_cast<const IpHeader*> (ptr);
    int IpHeaderLength = ((ip->verIhl) & 0x0F) * 4;
    if (remaining < IpHeaderLength) return;
    layers.ip.verIhl = ip->verIhl;
    layers.ip.tos = ip->tos;
    layers.ip.totalLength = qFromBigEndian(ip->totalLength);
    layers.ip.identification = qFromBigEndian(ip->identification);
    layers.ip.flagsFragOffset = qFromBigEndian(ip->flagsFragOffset);
    layers.ip.ttl = ip->ttl;
    layers.ip.protocol = ip->protocol;
    layers.ip.headerChecksum = qFromBigEndian(ip->headerChecksum);
    layers.ip.srcIp = qFromBigEndian(ip->srcIp);
    layers.ip.dstIp = qFromBigEndian(ip->dstIp);
    const u_char* byteptr = reinterpret_cast<const u_char*>(ip);
    byteptr += 20;
    memcpy(layers.ip.option, byteptr, IpHeaderLength - 20);

    layers.hasIp = true;
    layers.networkProto = NetworkProtocol::IPv4;
    ptr += IpHeaderLength;
    remaining -= IpHeaderLength;

}
void PacketParser::parseIcmp(const u_char *ptr, int remaining, ParsedLayers &layers){
    if (remaining < 8) return;
    const IcmpHeader *icmp = reinterpret_cast<const IcmpHeader *>(ptr);
    layers.icmp.type = icmp->type;
    layers.icmp.code = icmp->code;
    layers.icmp.checksum = qFromBigEndian(icmp->checksum);

    layers.hasIcmp = true;
    layers.transportProto = TransportProtocol::ICMP;

}
void PacketParser::parseTcp(const u_char *&ptr, int &remaining, ParsedLayers &layers){
    if (remaining < 20) return;
    const TcpHeader *tcp = reinterpret_cast<const TcpHeader*>(ptr);
    int dataOffset = (tcp->dataOffsetRes >> 4) * 4;
    if (dataOffset < 20) return;
    if (remaining < dataOffset) return;
    layers.tcp.srcPort   = qFromBigEndian(tcp->srcPort);
    layers.tcp.dstPort   = qFromBigEndian(tcp->dstPort);
    layers.tcp.seq       = qFromBigEndian(tcp->seq);
    layers.tcp.ack       = qFromBigEndian(tcp->ack);
    layers.tcp.dataOffsetRes = tcp->dataOffsetRes;
    layers.tcp.flags     = tcp->flags;
    layers.tcp.window    = qFromBigEndian(tcp->window);
    layers.tcp.checksum  = qFromBigEndian(tcp->checksum);
    layers.tcp.urgentPtr = qFromBigEndian(tcp->urgentPtr);

    layers.hasTcp = true;
    layers.transportProto = TransportProtocol::TCP;
    ptr      += dataOffset;
    remaining -= dataOffset;

}
void PacketParser::parseUdp(const u_char *&ptr, int &remaining, ParsedLayers &layers){
    if (remaining < static_cast<int>(sizeof(UdpHeader))) return;
    const UdpHeader *udp = reinterpret_cast<const UdpHeader*>(ptr);

    layers.udp.srcPort  = qFromBigEndian(udp->srcPort);
    layers.udp.dstPort  = qFromBigEndian(udp->dstPort);
    layers.udp.length   = qFromBigEndian(udp->length);
    layers.udp.checksum = qFromBigEndian(udp->checksum);

    layers.hasUdp = true;
    layers.transportProto = TransportProtocol::UDP;
    ptr      += sizeof(UdpHeader);
    remaining -= sizeof(UdpHeader);
}

PacketSummary PacketParser::buildSummary(const ParsedLayers &layers, int len, const timeval &ts)
{
    PacketSummary summary;

    qint64 msecs = static_cast<qint64>(ts.tv_sec) * 1000
                   + static_cast<qint64>(ts.tv_usec) / 1000;
    summary.timestamp = QDateTime::fromMSecsSinceEpoch(msecs);
    summary.length = len;
    auto macToString = [](const quint8 mac[6]) -> QString {
        return QString("%1:%2:%3:%4:%5:%6")
        .arg(mac[0], 2, 16, QLatin1Char('0'))
            .arg(mac[1], 2, 16, QLatin1Char('0'))
            .arg(mac[2], 2, 16, QLatin1Char('0'))
            .arg(mac[3], 2, 16, QLatin1Char('0'))
            .arg(mac[4], 2, 16, QLatin1Char('0'))
            .arg(mac[5], 2, 16, QLatin1Char('0'))
            .toUpper();
    };

    auto ipv4ToString = [](quint32 ipHostOrder) -> QString {
        return QString("%1.%2.%3.%4")
        .arg((ipHostOrder >> 24) & 0xFF)
            .arg((ipHostOrder >> 16) & 0xFF)
            .arg((ipHostOrder >> 8)  & 0xFF)
            .arg(ipHostOrder & 0xFF);
    };

    auto ipv6ToString = [](const quint8 ip6[16]) -> QString {
        Q_IPV6ADDR a;
        memcpy(a.c, ip6, 16);
        return QHostAddress(a).toString();
    };

    QString src, dst, proto, info;

    if (layers.hasArp) {
        proto = "ARP";
        src   = ipv4ToString(layers.arp.spa);
        dst   = ipv4ToString(layers.arp.tpa);

        quint16 oper = layers.arp.oper;
        if (oper == 1) {
            info = QString("ARP Request %1 → %2").arg(src, dst);
        } else if (oper == 2) {
            info = QString("ARP Reply %1 is-at %2")
            .arg(src, macToString(layers.arp.sha));
        } else {
            info = QString("ARP op %1 %2 → %3").arg(oper).arg(src, dst);
        }
    }
    else if (layers.hasIp) {
        src = ipv4ToString(layers.ip.srcIp);
        dst = ipv4ToString(layers.ip.dstIp);

        if (layers.hasTcp) {
            proto = "TCP";
            info = QString("TCP %1 → %2  Seq=%3 Ack=%4")
                       .arg(layers.tcp.srcPort)
                       .arg(layers.tcp.dstPort)
                       .arg(static_cast<qulonglong>(layers.tcp.seq))
                       .arg(static_cast<qulonglong>(layers.tcp.ack));
        } else if (layers.hasUdp) {
            proto = "UDP";
            info = QString("UDP %1 → %2  Len=%3")
                       .arg(layers.udp.srcPort)
                       .arg(layers.udp.dstPort)
                       .arg(layers.udp.length);
        } else if (layers.hasIcmp) {
            proto = "ICMP";
            info = QString("ICMP type=%1 code=%2")
                       .arg(layers.icmp.type)
                       .arg(layers.icmp.code);
        } else {
            proto = "IPv4";
            info  = QString("IPv4 proto=%1").arg(layers.ip.protocol);
        }
    }
    else if (layers.hasIpv6) {
        src = ipv6ToString(layers.ipv6.src);
        dst = ipv6ToString(layers.ipv6.dst);

        if (layers.hasTcp) {
            proto = "TCP";
            info = QString("TCP %1 → %2  Seq=%3 Ack=%4")
                       .arg(layers.tcp.srcPort)
                       .arg(layers.tcp.dstPort)
                       .arg(static_cast<qulonglong>(layers.tcp.seq))
                       .arg(static_cast<qulonglong>(layers.tcp.ack));
        } else if (layers.hasUdp) {
            proto = "UDP";
            info = QString("UDP %1 → %2  Len=%3")
                       .arg(layers.udp.srcPort)
                       .arg(layers.udp.dstPort)
                       .arg(layers.udp.length);
        } else if (layers.hasIcmp) {
            proto = "ICMPv6";
            info = QString("ICMPv6 type=%1 code=%2")
                       .arg(layers.icmp.type)
                       .arg(layers.icmp.code);
        } else {
            proto = "IPv6";
            info  = QString("IPv6 next=%1 hop=%2")
                       .arg(layers.ipv6.nextHeader)
                       .arg(layers.ipv6.hopLimit);
        }
    }
    else if (layers.hasEth) {
        proto = "Ethernet";
        src   = macToString(layers.eth.srcMac);
        dst   = macToString(layers.eth.dstMac);
        info  = QString("Ethertype=0x%1")
                   .arg(layers.eth.etherType, 4, 16, QLatin1Char('0'))
                   .toUpper();
    }
    else {
        proto = "Unknown";
        info  = "Unknown packet";
    }

    summary.srcAddr  = src;
    summary.dstAddr  = dst;
    summary.protocol = proto;
    summary.info     = info;
    return summary;
}


