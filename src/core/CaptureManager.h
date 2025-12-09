#pragma once
#include <QObject>
#include <QString>
#include <QVector>
#include "Packet.h"

struct NetworkInterfaceInfo {
    QString name;        // pcap 设备名
    QString description; // 描述
    QString ipAddress;   // 主 IP
};//其实就是网卡的名称、描述和ip地址

class CaptureWorker; // 前置声明

class CaptureManager : public QObject{
    Q_OBJECT
public:
    explicit CaptureManager(QObject *parent = nullptr);
    ~CaptureManager();
    QVector<NetworkInterfaceInfo> listInterfaces();// 调用 pcap_findalldevs

public slots:
    void startCapture(const QString &ifaceName, const QString &filterExp);//filterexp是用于过滤的表达式
    void stopCapture();
signals:
    void packetCaptured(const Packet &packet);
    void captureStarted();
    void captureStopped();
    void errorOccurred(const QString &err);
private:
    CaptureWorker *m_worker = nullptr; //属于这个manager的工人

};

