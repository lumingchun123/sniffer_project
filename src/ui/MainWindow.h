#pragma once

#include <QMainWindow>

class QComboBox;
class QLineEdit;
class QPushButton;
class QLabel;
class QListWidget;

#include "../core/CaptureManager.h"
#include "../core/Packet.h"


class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onStartClicked();
    void onStopClicked();

    void onPacketCaptured(const Packet &packet);
    void onCaptureStarted();
    void onCaptureStopped();
    void onErrorOccurred(const QString &err);
    void onItemDoubleClicked();

private:
    void setupUi();
    void loadInterfaces();

    CaptureManager m_captureManager;

    QComboBox   *m_ifaceCombo   = nullptr;
    QLineEdit   *m_filterEdit   = nullptr;
    QPushButton *m_startButton  = nullptr;
    QPushButton *m_stopButton   = nullptr;
    QLabel      *m_statusLabel  = nullptr;
    QListWidget *m_packetList   = nullptr;
    QVector<Packet> m_packets;

    int m_packetCount = 0;
};
