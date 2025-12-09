#include "Packet.h"
#include "ProtocolHeaders.h"
#include <pcap.h>
#include "IpReassembler.h"
#include <QtEndian>

class PacketParser
{
public:
    PacketParser();

    // pcap 回调得到的数据，解析成 Packet
    Packet parse(const pcap_pkthdr *header, const u_char *data,
                 IpReassembler *reassembler){
        Packet result_packet;
        int remaining = header->caplen;//这个remaining会随解析过程一直变短，最后成为packet的apppayload的length
        const u_char* current_head = data; //这个当前最开头的指针也会随解析过程往后指，最后变成应用层的开始指针
        result_packet.rawData = QByteArray(reinterpret_cast<const char*>(data), header->caplen);//qbytearray不仅仅是指针，还有长度
        parseEthernet(current_head, remaining, result_packet.layers);
        if (result_packet.layers.eth.etherType == 0x0800){//尝试解析IP
            QByteArray possible_ip_reassemble_result = QByteArray();
            parseIp(current_head, remaining, result_packet.layers);
            if (result_packet.layers.hasIp){
                possible_ip_reassemble_result = reassembler->feedFragment(result_packet.layers.ip, QByteArray(reinterpret_cast<const char*>(current_head), remaining));
//********************************************************************
                //todo: 处理分片重组后的payload的解析！！！               ｜
//********************************************************************
                if (result_packet.layers.ip.protocol == 6 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的tcp包，不需要任何重组，就直接解析掉
                    parseTcp(current_head, remaining, result_packet.layers);
                    return result_packet;
                }

                if (result_packet.layers.ip.protocol == 17 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的udp包，不需要任何重组，就直接解析掉
                    parseUdp(current_head, remaining, result_packet.layers);
                    return result_packet;
                }

                if (result_packet.layers.ip.protocol == 1 && result_packet.layers.ip.flagsFragOffset == 0){//直接收到了一个很小的icmp包，不需要任何重组，就直接解析掉
                    parseIcmp(current_head, remaining, result_packet.layers);
                    return result_packet;
                }
            }
        }

        else if (result_packet.layers.eth.etherType == 0x0806){ //尝试解析ARP协议
            parseArp(current_head, remaining, result_packet.layers);
            return result_packet;
        }

        return result_packet;
    }


private:
    void parseEthernet(const u_char *&ptr, int &remaining, ParsedLayers &layers){
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
    void parseArp(const u_char *ptr, int remaining, ParsedLayers &layers){
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

        }

    }
    void parseIp(const u_char *&ptr, int &remaining, ParsedLayers &layers){
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
        ptr += IpHeaderLength;
        remaining -= IpHeaderLength;

    }
    void parseIcmp(const u_char *ptr, int remaining, ParsedLayers &layers){
        if (remaining < 8) return;
        const IcmpHeader *icmp = reinterpret_cast<const IcmpHeader *>(ptr);
        layers.icmp.type = icmp->type;
        layers.icmp.code = icmp->code;
        layers.icmp.checksum = qFromBigEndian(icmp->checksum);

        layers.hasIcmp = true;

    }
    void parseTcp(const u_char *&ptr, int &remaining, ParsedLayers &layers){
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
        ptr      += dataOffset;
        remaining -= dataOffset;

    }
    void parseUdp(const u_char *&ptr, int &remaining, ParsedLayers &layers){
        if (remaining < static_cast<int>(sizeof(UdpHeader))) return;
        const UdpHeader *udp = reinterpret_cast<const UdpHeader*>(ptr);

        layers.udp.srcPort  = qFromBigEndian(udp->srcPort);
        layers.udp.dstPort  = qFromBigEndian(udp->dstPort);
        layers.udp.length   = qFromBigEndian(udp->length);
        layers.udp.checksum = qFromBigEndian(udp->checksum);

        layers.hasUdp = true;
        ptr      += sizeof(UdpHeader);
        remaining -= sizeof(UdpHeader);
    }

    PacketSummary buildSummary(const ParsedLayers &layers, int len,
                               const timeval &ts){

        PacketSummary summary;

        // 1. 时间戳：timeval -> QDateTime
        qint64 msecs = static_cast<qint64>(ts.tv_sec) * 1000
                       + static_cast<qint64>(ts.tv_usec) / 1000;
        summary.timestamp = QDateTime::fromMSecsSinceEpoch(msecs);
        summary.length    = len;

        // 2. 小工具：MAC / IP 转 QString
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

        auto ipToString = [](quint32 ip) -> QString {
            // 这里 ip 已经是主机序（之前用 qFromBigEndian 转过）
            return QString("%1.%2.%3.%4")
                .arg((ip >> 24) & 0xFF)
                .arg((ip >> 16) & 0xFF)
                .arg((ip >> 8)  & 0xFF)
                .arg(ip & 0xFF);
        };

        QString src;
        QString dst;
        QString proto;
        QString info;

        // 3. 先看网络层 / 传输层类型，决定显示内容
        if (layers.hasArp) {
            // ARP
            proto = "ARP";
            src   = ipToString(layers.arp.spa);
            dst   = ipToString(layers.arp.tpa);

            quint16 oper = layers.arp.oper;
            if (oper == 1) {
                info = QString("ARP Request %1 → %2")
                           .arg(src, dst);
            } else if (oper == 2) {
                info = QString("ARP Reply %1 is-at %2")
                .arg(src,
                     macToString(layers.arp.sha));
            } else {
                info = QString("ARP op %1 %2 → %3")
                           .arg(oper).arg(src, dst);
            }
        } else if (layers.hasIp) {
            // IPv4
            src = ipToString(layers.ip.srcIp);
            dst = ipToString(layers.ip.dstIp);

            // 传输层优先
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
                info = QString("IPv4 proto=%1")
                           .arg(layers.ip.protocol);
            }
        } else if (layers.hasEth) {
            // 只有以太网
            proto = "Ethernet";
            src   = macToString(layers.eth.srcMac);
            dst   = macToString(layers.eth.dstMac);
            info  = QString("Ethertype=0x%1")
                       .arg(layers.eth.etherType, 4, 16, QLatin1Char('0'))
                       .toUpper();
        } else {
            // 实在啥都没有解析出来
            proto = "Unknown";
            src.clear();
            dst.clear();
            info = "Unknown packet";
        }

        summary.srcAddr  = src;
        summary.dstAddr  = dst;
        summary.protocol = proto;
        summary.info     = info;

        return summary;
    }
};
