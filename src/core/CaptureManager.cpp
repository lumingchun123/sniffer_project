#include "CaptureManager.h"
#include "CaptureWorker.h"

#include <pcap.h>
#include <QThread>

CaptureManager::CaptureManager(QObject *parent)
    : QObject(parent)
{
}

CaptureManager::~CaptureManager()
{
    stopCapture();
}

QVector<NetworkInterfaceInfo> CaptureManager::listInterfaces()
{
    QVector<NetworkInterfaceInfo> results;

    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t *alldevs = nullptr;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        emit errorOccurred(QStringLiteral("pcap_findalldevs failed: %1")
                               .arg(errbuf));
        return results;
    }

    for (pcap_if_t *d = alldevs; d; d = d->next) {
        NetworkInterfaceInfo info;
        info.name = QString::fromLocal8Bit(d->name);
        if (d->description) {
            info.description = QString::fromLocal8Bit(d->description);
        }

        // 获取 IP 地址
        for (pcap_addr_t *addr = d->addresses; addr; addr = addr->next) {
            if (addr->addr && addr->addr->sa_family == AF_INET) {
                sockaddr_in *sin = reinterpret_cast<sockaddr_in*>(addr->addr);
                info.ipAddress = QString::fromLocal8Bit(inet_ntoa(sin->sin_addr));
                break;
            }
        }

        results.push_back(info);
    }

    pcap_freealldevs(alldevs);
    return results;
}

void CaptureManager::startCapture(const QString &ifaceName, const QString &filterExp)
{
    if (m_worker != nullptr) {
        emit errorOccurred(QStringLiteral("Capture is already running."));
        return;
    }

    // 创建 worker 和线程
    m_worker = new CaptureWorker();
    QThread *thread = new QThread(this);

    m_worker->moveToThread(thread);

    //
    // 信号连接：线程启动后执行 CaptureWorker::start()
    //
    connect(thread, &QThread::started,
            [=](){ m_worker->start(ifaceName, filterExp); });

    //
    // worker -> manager 信号传递
    //
    connect(m_worker, &CaptureWorker::packetCaptured,
            this, &CaptureManager::packetCaptured);

    connect(m_worker, &CaptureWorker::errorOccurred,
            this, &CaptureManager::errorOccurred);

    connect(m_worker, &CaptureWorker::finished,
            [=](){
                emit captureStopped();
                thread->quit();
            });

    //
    // thread 退出后 清理 worker
    //
    connect(thread, &QThread::finished,
            [=](){
                m_worker->deleteLater();
                m_worker = nullptr;
                thread->deleteLater();
            });

    thread->start();
    emit captureStarted();
}

void CaptureManager::stopCapture()
{
    if (!m_worker)
        return;

    m_worker->stop();  // 这会触发 worker 内部调用 pcap_breakloop()
}
