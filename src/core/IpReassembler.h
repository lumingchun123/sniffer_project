#pragma once
#include <QObject>
#include <QMap>
#include <QByteArray>
#include <QElapsedTimer>
#include "ProtocolHeaders.h"
#include "Packet.h"

struct IpFragmentKey {
    quint32 src;
    quint32 dst;
    quint16 id;
    quint8  protocol;

    bool operator<(const IpFragmentKey &other) const {
        if (src != other.src) return src < other.src;
        if (dst != other.dst) return dst < other.dst;
        if (id  != other.id)  return id  < other.id;
        return protocol < other.protocol;
    }
};

struct FragmentInfo {
    quint16 offset;   // 单位：8 字节
    QByteArray data;  // 该分片的 IP 载荷部分
    bool moreFragments; // MF 标志
};

struct ReassemblyBuffer {
    QList<FragmentInfo> fragments;
    int         totalLength = -1; // 期望的完整长度，最后一个分片得知
    QElapsedTimer timer;          // 用于超时清理
};

class IpReassembler : public QObject
{
    Q_OBJECT
public:
    explicit IpReassembler(QObject *parent = nullptr);

    // 传入 IP 头 + 头之后的 payload，返回：
    // - 若未完成重组，则返回空 QByteArray；
    // - 若完成，返回完整 IP payload（已按 offset 拼好）。
    QByteArray feedFragment(const IpHeader &ipHeader,
                            const QByteArray &payload);

private slots:
    void onCleanupTimeout(); // 定期清理超时未完成的分片

private:
    bool tryAssemble(ReassemblyBuffer &buf, QByteArray &outPayload);

    QMap<IpFragmentKey, ReassemblyBuffer> m_buffers;
};
