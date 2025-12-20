#include "PacketDetailDialog.h"

#include <QVBoxLayout>
#include <QTextEdit>
#include <QDialogButtonBox>
#include <QDateTime>
#include <QHostAddress>
#include <QtGlobal>

static QString macToString(const quint8 mac[6])
{
    return QString("%1:%2:%3:%4:%5:%6")
    .arg(mac[0], 2, 16, QLatin1Char('0'))
        .arg(mac[1], 2, 16, QLatin1Char('0'))
        .arg(mac[2], 2, 16, QLatin1Char('0'))
        .arg(mac[3], 2, 16, QLatin1Char('0'))
        .arg(mac[4], 2, 16, QLatin1Char('0'))
        .arg(mac[5], 2, 16, QLatin1Char('0'))
        .toUpper();
}

static QString ipToString(quint32 ipHostOrder)
{
    return QHostAddress(ipHostOrder).toString();
}

static QString etherTypeToString(quint16 etherType)
{
    switch (etherType) {
    case 0x0800: return "IPv4 (0x0800)";
    case 0x0806: return "ARP  (0x0806)";
    case 0x86DD: return "IPv6 (0x86DD)";
    default:     return QString("0x%1").arg(etherType, 4, 16, QLatin1Char('0')).toUpper();
    }
}

static QString ipProtoToString(quint8 proto)
{
    switch (proto) {
    case 1:  return "ICMP(1)";
    case 6:  return "TCP(6)";
    case 17: return "UDP(17)";
    default: return QString("%1").arg(proto);
    }
}

static QString tcpFlagsToString(quint8 flags)
{
    QStringList on;
    // 常见顺序：FIN SYN RST PSH ACK URG ECE CWR
    if (flags & 0x01) on << "FIN";
    if (flags & 0x02) on << "SYN";
    if (flags & 0x04) on << "RST";
    if (flags & 0x08) on << "PSH";
    if (flags & 0x10) on << "ACK";
    if (flags & 0x20) on << "URG";
    if (flags & 0x40) on << "ECE";
    if (flags & 0x80) on << "CWR";
    if (on.isEmpty()) return "NONE";
    return on.join("|");
}

static QString arpOperToString(quint16 oper)
{
    switch (oper) {
    case 1: return "Request(1)";
    case 2: return "Reply(2)";
    default: return QString("%1").arg(oper);
    }
}

static QString icmpTypeCodeToString(quint8 type, quint8 code)
{

    if (type == 8 && code == 0)  return "Echo Request (ping)";
    if (type == 0 && code == 0)  return "Echo Reply (ping)";
    if (type == 3)               return "Destination Unreachable";
    if (type == 11)              return "Time Exceeded";
    return QString("Type=%1 Code=%2").arg(type).arg(code);
}

static QString payloadPreview(const QByteArray &payload, int maxLen = 256)
{
    if (payload.isEmpty()) return "(empty)";
    QByteArray cut = payload.left(maxLen);

    QString out;
    out.reserve(cut.size());
    for (unsigned char c : cut) {
        if (c >= 32 && c <= 126) out += QChar(c);
        else out += '.';
    }
    if (payload.size() > maxLen) out += " ...";
    return out;
}

PacketDetailDialog::PacketDetailDialog(const Packet &packet, QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("Packet Details");
    resize(900, 600);

    auto *layout = new QVBoxLayout(this);

    m_text = new QTextEdit(this);
    m_text->setReadOnly(true);
    m_text->setLineWrapMode(QTextEdit::NoWrap);

    auto *btns = new QDialogButtonBox(QDialogButtonBox::Ok, this);
    connect(btns, &QDialogButtonBox::accepted, this, &QDialog::accept);

    layout->addWidget(m_text, 1);
    layout->addWidget(btns);

    const auto &s = packet.summary;
    const auto &L = packet.layers;

    QString header;
    header += QString("Time:     %1\n").arg(s.timestamp.toString("yyyy-MM-dd HH:mm:ss.zzz"));
    header += QString("Length:   %1 bytes\n").arg(s.length);
    header += QString("Protocol: %1\n").arg(s.protocol);
    header += QString("Source:   %1\n").arg(s.srcAddr);
    header += QString("Dest:     %1\n").arg(s.dstAddr);
    header += QString("Info:     %1\n").arg(s.info);

    QString decoded;
    decoded += "\n--- DECODED FIELDS ---\n";

    // Ethernet
    if (L.hasEth) {
        decoded += "[Ethernet]\n";
        decoded += QString("  Src MAC:   %1\n").arg(macToString(L.eth.srcMac));
        decoded += QString("  Dst MAC:   %1\n").arg(macToString(L.eth.dstMac));
        decoded += QString("  EtherType: %1\n").arg(etherTypeToString(L.eth.etherType));
    }

    // ARP
    if (L.hasArp) {
        decoded += "[ARP]\n";
        decoded += QString("  HType: %1\n").arg(L.arp.htype);
        decoded += QString("  PType: 0x%1\n").arg(L.arp.ptype, 4, 16, QLatin1Char('0')).toUpper();
        decoded += QString("  HLen:  %1\n").arg(L.arp.hlen);
        decoded += QString("  PLen:  %1\n").arg(L.arp.plen);
        decoded += QString("  Oper:  %1\n").arg(arpOperToString(L.arp.oper));
        decoded += QString("  Sender MAC: %1\n").arg(macToString(L.arp.sha));
        decoded += QString("  Sender IP:  %1\n").arg(ipToString(L.arp.spa));
        decoded += QString("  Target MAC: %1\n").arg(macToString(L.arp.tha));
        decoded += QString("  Target IP:  %1\n").arg(ipToString(L.arp.tpa));
    }

    // IPv4
    if (L.hasIp) {
        const quint8 version = (L.ip.verIhl >> 4) & 0x0F;
        const quint8 ihl     = (L.ip.verIhl & 0x0F) * 4;

        const quint16 flagsFrag = L.ip.flagsFragOffset;
        const quint16 flags     = (flagsFrag >> 13) & 0x7;
        const quint16 fragOff8  = (flagsFrag & 0x1FFF); // 单位 8 bytes 的 offset

        const bool DF = (flags & 0x2) != 0; // 010
        const bool MF = (flags & 0x1) != 0; // 001

        decoded += "[IPv4]\n";
        decoded += QString("  Version: %1\n").arg(version);
        decoded += QString("  IHL:     %1 bytes\n").arg(ihl);
        decoded += QString("  TOS:     0x%1\n").arg(L.ip.tos, 2, 16, QLatin1Char('0')).toUpper();
        decoded += QString("  TotalLen:%1\n").arg(L.ip.totalLength);
        decoded += QString("  ID:      0x%1 (%2)\n").arg(L.ip.identification, 4, 16, QLatin1Char('0')).arg(L.ip.identification).toUpper();
        decoded += QString("  Flags:   DF=%1 MF=%2 (raw=%3)\n")
                       .arg(DF ? "1" : "0")
                       .arg(MF ? "1" : "0")
                       .arg(flags);
        decoded += QString("  FragOff: %1 (=> %2 bytes)\n").arg(fragOff8).arg(fragOff8 * 8);
        decoded += QString("  TTL:     %1\n").arg(L.ip.ttl);
        decoded += QString("  Proto:   %1\n").arg(ipProtoToString(L.ip.protocol));
        decoded += QString("  Cksum:   0x%1\n").arg(L.ip.headerChecksum, 4, 16, QLatin1Char('0')).toUpper();
        decoded += QString("  Src IP:  %1\n").arg(ipToString(L.ip.srcIp));
        decoded += QString("  Dst IP:  %1\n").arg(ipToString(L.ip.dstIp));

        if (ihl > 20) {
            decoded += QString("  Options: %1 bytes\n").arg(ihl - 20);
        }
    }

    // ICMP
    if (L.hasIcmp) {
        decoded += "[ICMP]\n";
        decoded += QString("  %1\n").arg(icmpTypeCodeToString(L.icmp.type, L.icmp.code));
        decoded += QString("  Type:   %1\n").arg(L.icmp.type);
        decoded += QString("  Code:   %1\n").arg(L.icmp.code);
        decoded += QString("  Cksum:  0x%1\n").arg(L.icmp.checksum, 4, 16, QLatin1Char('0')).toUpper();
    }

    // TCP
    if (L.hasTcp) {
        const int dataOffsetBytes = ((L.tcp.dataOffsetRes >> 4) & 0x0F) * 4;
        decoded += "[TCP]\n";
        decoded += QString("  SrcPort: %1\n").arg(L.tcp.srcPort);
        decoded += QString("  DstPort: %1\n").arg(L.tcp.dstPort);
        decoded += QString("  Seq:     %1\n").arg(L.tcp.seq);
        decoded += QString("  Ack:     %1\n").arg(L.tcp.ack);
        decoded += QString("  HdrLen:  %1 bytes\n").arg(dataOffsetBytes);
        decoded += QString("  Flags:   0x%1 (%2)\n")
                       .arg(L.tcp.flags, 2, 16, QLatin1Char('0'))
                       .arg(tcpFlagsToString(L.tcp.flags))
                       .toUpper();
        decoded += QString("  Window:  %1\n").arg(L.tcp.window);
        decoded += QString("  Cksum:   0x%1\n").arg(L.tcp.checksum, 4, 16, QLatin1Char('0')).toUpper();
        decoded += QString("  Urgent:  %1\n").arg(L.tcp.urgentPtr);

        if (dataOffsetBytes > 20) {
            decoded += QString("  Options: %1 bytes\n").arg(dataOffsetBytes - 20);
        }
    }

    // UDP
    if (L.hasUdp) {
        decoded += "[UDP]\n";
        decoded += QString("  SrcPort: %1\n").arg(L.udp.srcPort);
        decoded += QString("  DstPort: %1\n").arg(L.udp.dstPort);
        decoded += QString("  Length:  %1\n").arg(L.udp.length);
        decoded += QString("  Cksum:   0x%1\n").arg(L.udp.checksum, 4, 16, QLatin1Char('0')).toUpper();
    }

 
    decoded += "[Payload]\n";
    decoded += QString("  Size: %1 bytes\n").arg(L.appPayload.size());
    decoded += QString("  ASCII preview: %1\n").arg(payloadPreview(L.appPayload));


    QString raw;
    raw += "\n--- RAW HEX DUMP ---\n";
    raw += hexDump(packet.rawData);

    m_text->setPlainText(header + decoded + raw);
}

QString PacketDetailDialog::hexDump(const QByteArray &data, int bytesPerLine)
{
    auto toPrintable = [](uchar c) -> QChar {
        if (c >= 32 && c <= 126) return QChar(c);
        return '.';
    };

    QString out;
    const int n = data.size();

    for (int i = 0; i < n; i += bytesPerLine) {
        out += QString("%1  ").arg(i, 6, 16, QLatin1Char('0')).toUpper();

        QString hexPart;
        QString asciiPart;
        for (int j = 0; j < bytesPerLine; ++j) {
            const int idx = i + j;
            if (idx < n) {
                const uchar c = static_cast<uchar>(data[idx]);
                hexPart += QString("%1 ").arg(c, 2, 16, QLatin1Char('0')).toUpper();
                asciiPart += toPrintable(c);
            } else {
                hexPart += "   ";
                asciiPart += " ";
            }
            if (j == 7) hexPart += " ";
        }

        out += hexPart;
        out += " ";
        out += asciiPart;
        out += "\n";
    }

    return out;
}

