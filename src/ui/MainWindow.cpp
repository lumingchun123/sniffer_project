#include "MainWindow.h"

#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QListWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
{
    setupUi();
    loadInterfaces();

    // 连接 CaptureManager 的信号
    connect(&m_captureManager, &CaptureManager::packetCaptured,
            this, &MainWindow::onPacketCaptured);
    connect(&m_captureManager, &CaptureManager::captureStarted,
            this, &MainWindow::onCaptureStarted);
    connect(&m_captureManager, &CaptureManager::captureStopped,
            this, &MainWindow::onCaptureStopped);
    connect(&m_captureManager, &CaptureManager::errorOccurred,
            this, &MainWindow::onErrorOccurred);
}

MainWindow::~MainWindow()
{
}

void MainWindow::setupUi()
{
    auto *central = new QWidget(this);
    auto *mainLayout = new QVBoxLayout(central);

    // 顶部：网卡选择 + filter + 按钮
    auto *topLayout = new QHBoxLayout();

    m_ifaceCombo  = new QComboBox(this);
    m_filterEdit  = new QLineEdit(this);
    m_startButton = new QPushButton(tr("Start"), this);
    m_stopButton  = new QPushButton(tr("Stop"), this);
    m_statusLabel = new QLabel(tr("Idle"), this);

    m_filterEdit->setPlaceholderText("BPF filter, e.g. tcp port 80");

    topLayout->addWidget(new QLabel(tr("Interface:"), this));
    topLayout->addWidget(m_ifaceCombo, 1);
    topLayout->addWidget(new QLabel(tr("Filter:"), this));
    topLayout->addWidget(m_filterEdit, 1);
    topLayout->addWidget(m_startButton);
    topLayout->addWidget(m_stopButton);

    mainLayout->addLayout(topLayout);
    mainLayout->addWidget(m_statusLabel);

    // 中间：简单的列表，先把抓到的包数展示出来
    m_packetList = new QListWidget(this);
    mainLayout->addWidget(m_packetList, 1);

    setCentralWidget(central);
    resize(900, 600);
    setWindowTitle("Sniffer");

    // 按钮连接
    connect(m_startButton, &QPushButton::clicked,
            this, &MainWindow::onStartClicked);
    connect(m_stopButton, &QPushButton::clicked,
            this, &MainWindow::onStopClicked);
}

void MainWindow::loadInterfaces()
{
    m_ifaceCombo->clear();

    QVector<NetworkInterfaceInfo> ifaces = m_captureManager.listInterfaces();
    if (ifaces.isEmpty()) {
        m_statusLabel->setText(tr("No interfaces found"));
        return;
    }

    for (const auto &info : ifaces) {
        QString text;
        if (!info.description.isEmpty())
            text = QString("%1 (%2) [%3]").arg(info.description, info.name, info.ipAddress);
        else
            text = QString("%1 [%2]").arg(info.name, info.ipAddress);

        // 显示友好文字，把真正的 pcap 设备名放在 itemData 里
        m_ifaceCombo->addItem(text, info.name);
    }

    if (m_ifaceCombo->count() > 0)
        m_ifaceCombo->setCurrentIndex(0);
}

void MainWindow::onStartClicked()
{
    if (m_ifaceCombo->count() == 0) {
        QMessageBox::warning(this, tr("Warning"), tr("No interface available."));
        return;
    }

    const QString ifaceName = m_ifaceCombo->currentData().toString();
    const QString filterExp = m_filterEdit->text().trimmed();

    m_packetCount = 0;
    m_packetList->clear();
    m_statusLabel->setText(tr("Starting capture..."));

    m_captureManager.startCapture(ifaceName, filterExp);
}

void MainWindow::onStopClicked()
{
    m_captureManager.stopCapture();
}

void MainWindow::onPacketCaptured(const Packet &packet)
{

    ++m_packetCount;

    const auto &s = packet.summary;

    QString line = QString("[%1] %2 → %3  %4  (%5 bytes)  %6")
                       .arg(s.timestamp.toString("HH:mm:ss.zzz"))
                       .arg(s.srcAddr)
                       .arg(s.dstAddr)
                       .arg(s.protocol)
                       .arg(s.length)
                       .arg(s.info);

    m_packetList->addItem(line);
    m_statusLabel->setText(
        QString("Capturing... (%1 packets)").arg(m_packetCount));
}

void MainWindow::onCaptureStarted()
{
    m_statusLabel->setText(tr("Capture started"));
}

void MainWindow::onCaptureStopped()
{
    m_statusLabel->setText(tr("Capture stopped"));
}

void MainWindow::onErrorOccurred(const QString &err)
{
    m_statusLabel->setText(tr("Error: %1").arg(err));
    QMessageBox::critical(this, tr("Error"), err);
}
