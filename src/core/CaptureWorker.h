#pragma once
#include <QObject>
#include <QString>
#include "Packet.h"
#include <pcap.h>
class PacketParser;
class IpReassembler;

class CaptureWorker : public QObject
{
    Q_OBJECT
public:
    explicit CaptureWorker(QObject *parent = nullptr);
    ~CaptureWorker();

public slots:
    void start(const QString &ifaceName, const QString &filterExp);
    void stop();

signals:
    void packetCaptured(const Packet &packet);
    void errorOccurred(const QString &err);
    void finished();

private:
    void packetHandler(uchar *user, const struct pcap_pkthdr *header, const u_char *packet);//传给pcap_loop回调时用
    void captureLoop(); // 内部调用 pcap_loop / pcap_next_ex
    static void pcapCallback(u_char *user,
                             const struct pcap_pkthdr *header,
                             const u_char *packet);

    pcap_t          *m_handle = nullptr;
    bool             m_running = false;
    PacketParser    *m_parser = nullptr;
    IpReassembler   *m_reassembler = nullptr;
};
