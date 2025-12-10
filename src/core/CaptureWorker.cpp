#include "CaptureWorker.h"
#include "PacketParser.h"
#include "IpReassembler.h"

#include <pcap.h>
#include <QThread>

void CaptureWorker::pcapCallback(u_char *user,
                                 const struct pcap_pkthdr *header,
                                 const u_char *packet)
{
    auto *worker = reinterpret_cast<CaptureWorker*>(user);
    if (!worker) return;

    worker->packetHandler(user, header, packet);
}

CaptureWorker::CaptureWorker(QObject *parent)
    : QObject(parent)
    , m_handle(nullptr)
    , m_running(false)
    , m_parser(new PacketParser())
    , m_reassembler(new IpReassembler(this)) // 让 Qt 管理它的生命周期
{
}

CaptureWorker::~CaptureWorker()
{
    stop(); // 尝试停止抓包循环

    if (m_handle) {
        pcap_close(m_handle);
        m_handle = nullptr;
    }

    delete m_parser;
    m_parser = nullptr;
    // m_reassembler 由 Qt 自动 delete（parent = this）
}

void CaptureWorker::start(const QString &ifaceName, const QString &filterExp)
{
    if (m_running) {
        // 已经在运行，就不再重复启动
        return;
    }

    char errbuf[PCAP_ERRBUF_SIZE] = {0};

    // 1. 打开网卡
    QByteArray devName = ifaceName.toLocal8Bit();
    m_handle = pcap_open_live(devName.constData(),
                              65535,   // snaplen: 抓取最大长度
                              1,       // promisc: 混杂模式
                              1000,    // read timeout (ms)
                              errbuf);
    if (!m_handle) {
        emit errorOccurred(QStringLiteral("pcap_open_live failed: %1")
                               .arg(QString::fromLocal8Bit(errbuf)));
        emit finished();
        return;
    }

    // 2. 可选：设置过滤表达式
    if (!filterExp.isEmpty()) {
        struct bpf_program fp;
        QByteArray filter = filterExp.toLocal8Bit();
        if (pcap_compile(m_handle, &fp, filter.constData(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
            emit errorOccurred(
                QStringLiteral("pcap_compile failed: %1")
                    .arg(QString::fromLocal8Bit(pcap_geterr(m_handle)))
                );
            pcap_close(m_handle);
            m_handle = nullptr;
            emit finished();
            return;
        }

        if (pcap_setfilter(m_handle, &fp) == -1) {
            emit errorOccurred(
                QStringLiteral("pcap_setfilter failed: %1")
                    .arg(QString::fromLocal8Bit(pcap_geterr(m_handle)))
                );
            pcap_freecode(&fp);
            pcap_close(m_handle);
            m_handle = nullptr;
            emit finished();
            return;
        }

        pcap_freecode(&fp);
    }

    m_running = true;

    // 真正进入抓包循环（会阻塞当前线程，通常这个线程是 QThread）
    captureLoop();
}

void CaptureWorker::stop()
{
    if (!m_running)
        return;

    m_running = false;

    if (m_handle) {
        // 让 pcap_loop 尽快返回
        pcap_breakloop(m_handle);
    }
}

void CaptureWorker::captureLoop()
{
    if (!m_handle) {
        emit finished();
        return;
    }

    // -1 / 0 的语义视实现不同，这里用 -1 表示“一直抓包直到错误或 breakloop”
    int ret = pcap_loop(m_handle,
                        -1,
                        &CaptureWorker::pcapCallback,
                        reinterpret_cast<u_char*>(this));

    Q_UNUSED(ret);
    // ret 可以是 PCAP_ERROR, PCAP_ERROR_BREAK 等，你可以按需处理

    m_running = false;
    emit finished();
}


void CaptureWorker::packetHandler(uchar *user,
                                  const struct pcap_pkthdr *header,
                                  const u_char *packet)
{

    if (!m_running || !m_parser)
        return;

    // 用 PacketParser + IpReassembler 解析出高层协议
    Packet parsed = m_parser->parse(header, packet, m_reassembler);

    // 线程间靠信号传 Packet，Qt 会自动做 queued connection（如果在不同线程）
    emit packetCaptured(parsed);
}
