#pragma once

#include <QDialog>
#include "../core/Packet.h"

class QTextEdit;

class PacketDetailDialog : public QDialog
{
    Q_OBJECT
public:
    explicit PacketDetailDialog(const Packet &packet, QWidget *parent = nullptr);

private:
    static QString hexDump(const QByteArray &data, int bytesPerLine = 16);

    QTextEdit *m_text = nullptr;
};
