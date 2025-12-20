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
                            header->len,          // 报文长度（你也可以用 caplen）
                            header->ts            // pcap 的 timeval，直接传给你的函数
                            );
                        result_packet.layers.appPayload =
                            QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                        return result_packet;
                    }

                    if (result_packet.layers.ip.protocol == 17){
                        parseUdp(current_head, remaining, result_packet.layers);
                        result_packet.summary = buildSummary(
                            result_packet.layers,
                            header->len,          // 报文长度（你也可以用 caplen）
                            header->ts            // pcap 的 timeval，直接传给你的函数
                            );
                        result_packet.layers.appPayload =
                            QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                        return result_packet;
                    }

                    if (result_packet.layers.ip.protocol == 1){
                        parseIcmp(current_head, remaining, result_packet.layers);
                        result_packet.summary = buildSummary(
                            result_packet.layers,
                            header->len,          // 报文长度（你也可以用 caplen）
                            header->ts            // pcap 的 timeval，直接传给你的函数
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
                    header->len,          // 报文长度（你也可以用 caplen）
                    header->ts            // pcap 的 timeval，直接传给你的函数
                    );
                result_packet.layers.appPayload =
                    QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                return result_packet;
            }

            if (result_packet.layers.ip.protocol == 17 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的udp包，不需要任何重组，就直接解析掉
                parseUdp(current_head, remaining, result_packet.layers);
                result_packet.summary = buildSummary(
                    result_packet.layers,
                    header->len,          // 报文长度（你也可以用 caplen）
                    header->ts            // pcap 的 timeval，直接传给你的函数
                    );
                result_packet.layers.appPayload =
                    QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                return result_packet;
            }

            if (result_packet.layers.ip.protocol == 1 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的icmp包，不需要任何重组，就直接解析掉
                parseIcmp(current_head, remaining, result_packet.layers);
                result_packet.summary = buildSummary(
                    result_packet.layers,
                    header->len,          // 报文长度（你也可以用 caplen）
                    header->ts            // pcap 的 timeval，直接传给你的函数
                    );
                result_packet.layers.appPayload =
                    QByteArray(reinterpret_cast<const char*>(current_head), remaining);
                return result_packet;
            }
        }
    }

    else if (result_packet.layers.eth.etherType == 0x0806){ //尝试解析ARP协议
        parseArp(current_head, remaining, result_packet.layers);
        result_packet.summary = buildSummary(
            result_packet.layers,
            header->len,          // 报文长度（你也可以用 caplen）
            header->ts            // pcap 的 timeval，直接传给你的函数
            );
        return result_packet;
    }

    else if (result_packet.layers.eth.etherType == 0x86DD) { // IPv6
        // 1) 解析 IPv6 基本首部
        if (remaining < 40) {
            // 截断包，直接返回空
            return Packet();
        }

        const Ipv6Header* ip6 = reinterpret_cast<const Ipv6Header*>(current_head);

        // version 在高 4 位
        const quint8 version = (qFromBigEndian(ip6->verTcFl) >> 28) & 0x0F;
        if (version != 6) {
            return Packet();
        }

        const quint16 payloadLen = qFromBigEndian(ip6->payloadLength);
        quint8 next = ip6->nextHeader;

        // 可选：存进 layers（如果你已经加了 hasIpv6/ipv6）
        result_packet.layers.hasIpv6 = true;
        result_packet.layers.ipv6 = *ip6;
        result_packet.layers.networkProto = NetworkProtocol::IPv6; // 如果你有这个枚举

        // 把 current_head / remaining 推进到 IPv6 payload 起点
        current_head += 40;
        remaining -= 40;

        // IPv6 的 payloadLen 表示“IPv6 基本首部之后”的长度
        // caplen 可能更短，所以用 min 防止越界
        if (payloadLen < remaining) {
            remaining = payloadLen;
        }

        // 2) 跳过常见扩展头（支持 mDNS 场景；也避免遇到扩展头就解析错位）
        auto needBytes = [&](int n) { return remaining >= n; };

        // Fragment header 的识别：next == 44
        // 其它可变长扩展头：长度字段单位 8 字节（不含前 8）
        while (true) {
            if (next == 0   || // Hop-by-Hop Options
                next == 43  || // Routing
                next == 60  || // Destination Options
                next == 51  || // AH
                next == 50  )  // ESP (严格来说结构不同，这里只“跳过”可能不准确，但至少不崩)
            {
                if (!needBytes(2)) return Packet();

                // 对于 0/43/60：格式是 [NextHeader(1), HdrExtLen(1), ...]
                // HdrExtLen: 以 8 字节为单位，不包括首 8 字节
                // AH: [NextHeader, PayloadLen]，PayloadLen 以 4 字节为单位，不包括前 2 个 4 字节
                int extLenBytes = 0;

                if (next == 51) { // AH
                    if (!needBytes(2)) return Packet();
                    quint8 ahNext = current_head[0];
                    quint8 ahLen  = current_head[1];
                    // RFC：AH 长度字段单位 4 字节，且不包括前 2 个 4 字节
                    extLenBytes = (static_cast<int>(ahLen) + 2) * 4;
                    if (!needBytes(extLenBytes)) return Packet();
                    next = ahNext;
                } else if (next == 50) { // ESP：这里没法可靠跳过（需要 SPI/Seq + 加密体 + ICV）
                    // 最保守：遇到 ESP 直接停止上层解析，只显示到 IPv6
                    result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
                    return result_packet;
                } else {
                    quint8 extNext = current_head[0];
                    quint8 extLen  = current_head[1];
                    extLenBytes = (static_cast<int>(extLen) + 1) * 8; // +1 表示含前 8 字节
                    if (!needBytes(extLenBytes)) return Packet();
                    next = extNext;
                }

                current_head += extLenBytes;
                remaining -= extLenBytes;
                continue;
            }
            else if (next == 44) { // Fragment header（固定 8 字节）
                if (!needBytes(8)) return Packet();

                // Fragment header: next(1), reserved(1), fragOff/flags(2), id(4)
                quint8 fragNext = current_head[0];
                quint16 offResM = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(current_head + 2));
                quint16 fragOff8 = (offResM >> 3) & 0x1FFF;
                bool more = (offResM & 0x1) != 0;

                // 这里只做“跳过 fragment header 并继续解析后续”，不做 IPv6 分片重组
                // 作业要求是 IPv4 分片重组，IPv6 可不实现重组，只要不解析错位即可
                current_head += 8;
                remaining -= 8;
                next = fragNext;

                // 如果是分片且不是首片（fragOff8 != 0），此时上层头不一定在本片里
                // 最保守：只展示到 IPv6，不继续解析 L4
                if (fragOff8 != 0 || more) {
                    result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
                    return result_packet;
                }
                continue;
            }

            break; // next 不是扩展头，进入 L4
        }

        // 3) 解析 L4
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
            // 如果你没有 parseIcmpv6，可以先用现有 parseIcmp（但字段含义不同）
            // 建议你新写 parseIcmpv6；如果来不及，这里只做 payload 展示
            // parseIcmpv6(current_head, remaining, result_packet.layers);

            result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
            result_packet.layers.appPayload =
                QByteArray(reinterpret_cast<const char*>(current_head), remaining);
            return result_packet;
        }

        // 其他 next header：只显示到 IPv6
        result_packet.summary = buildSummary(result_packet.layers, header->len, header->ts);
        return result_packet;
    }


    result_packet.summary = buildSummary(
        result_packet.layers,
        header->len,          // 报文长度（你也可以用 caplen）
        header->ts            // pcap 的 timeval，直接传给你的函数
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

    // 1) 时间戳
    qint64 msecs = static_cast<qint64>(ts.tv_sec) * 1000
                   + static_cast<qint64>(ts.tv_usec) / 1000;
    summary.timestamp = QDateTime::fromMSecsSinceEpoch(msecs);
    summary.length = len;

    // 2) 工具：MAC / IPv4 / IPv6 -> QString
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

    // 3) 先 ARP
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
    // 4) IPv4（你原来的逻辑）
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
    // 5) ✅ 新增：IPv6（核心改动）
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
            // 你如果复用 hasIcmp 来表示 ICMPv6，也能先这样显示；
            // 更严谨是加 hasIcmpv6/icmpv6 结构体
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
    // 6) fallback：只有以太网
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


