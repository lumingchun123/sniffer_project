#pragma once
#include <QObject>
#include <QMap>
#include <QByteArray>
#include <QElapsedTimer>
#include "ProtocolHeaders.h"

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
    quint16 offset;   
    QByteArray data; 
    bool moreFragments; 
};

struct ReassemblyBuffer {
    QList<FragmentInfo> fragments;
    int         totalLength = -1; 
    QElapsedTimer timer;          
};

class IpReassembler : public QObject
{
    Q_OBJECT
public:
    explicit IpReassembler(QObject *parent = nullptr);
    QByteArray feedFragment(const IpHeader &ipHeader,
                            const QByteArray &payload);

private slots:
    void onCleanupTimeout(); 

private:
    bool tryAssemble(ReassemblyBuffer &buf, QByteArray &outPayload);
    QMap<IpFragmentKey, ReassemblyBuffer> m_buffers;

};
