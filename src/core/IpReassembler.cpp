#include "IpReassembler.h"
#include <QTimer>
#include <algorithm>

static const qint64 REASSEMBLY_TIMEOUT_MS = 30000; // 30 秒超时

IpReassembler::IpReassembler(QObject *parent)
    : QObject(parent)
{
    // 周期性清理超时的分片缓存
    auto timer = new QTimer(this);
    connect(timer, &QTimer::timeout,
            this, &IpReassembler::onCleanupTimeout);
    timer->start(5000); // 每5秒扫一遍
}

bool IpReassembler::tryAssemble(ReassemblyBuffer &buf, QByteArray &outPayload)
{
    if (buf.fragments.isEmpty())
        return false;

    // 没有最后一个分片（MF=0）就无法知道总长度，一般不组装
    bool hasLast = false;
    for (const auto &f : buf.fragments) {
        if (!f.moreFragments) {
            hasLast = true;
            break;
        }
    }
    if (!hasLast)
        return false;

    if (buf.totalLength <= 0)
        return false;

    // 按 offset 排序
    std::sort(buf.fragments.begin(), buf.fragments.end(),
              [](const FragmentInfo &a, const FragmentInfo &b){
                  return a.offset < b.offset;
              });

    outPayload.clear();
    outPayload.reserve(buf.totalLength);

    int currentPos = 0; 

    for (const FragmentInfo &frag : buf.fragments) {
        int start = frag.offset * 8; 
        if (start > currentPos) {
            // 中间有洞，说明还缺分片
            return false;
        }

        int overlap = currentPos - start;
        if (overlap < frag.data.size()) {
            const char *dataPtr = frag.data.constData() + std::max(0, overlap);
            int copyLen = frag.data.size() - std::max(0, overlap);

            outPayload.append(dataPtr, copyLen);
            currentPos += copyLen;
        } else {
            // 这个分片完全被之前的覆盖，也无所谓，跳过
        }
    }

    if (currentPos < buf.totalLength) {
        // 还没达到完整长度，缺分片
        return false;
    }

    
    if (outPayload.size() > buf.totalLength) {
        outPayload.truncate(buf.totalLength);
    }

    return true;
}

QByteArray IpReassembler::feedFragment(const IpHeader &ipHeader,
                                       const QByteArray &payload)
{
   
    IpFragmentKey key;
    key.src      = ipHeader.srcIp;
    key.dst      = ipHeader.dstIp;
    key.id       = ipHeader.identification;
    key.protocol = ipHeader.protocol;


    quint16 flagsOffset = ipHeader.flagsFragOffset;
    quint16 offset8     = flagsOffset & 0x1FFF;   
    bool    moreFrag    = (flagsOffset & 0x2000); 

    FragmentInfo fi;
    fi.offset        = offset8;
    fi.data          = payload;    // 这里存的是当前分片的 IP payload
    fi.moreFragments = moreFrag;

    ReassemblyBuffer &buf = m_buffers[key];
    if (!buf.timer.isValid()) {
        buf.timer.start();
    }

    buf.fragments.push_back(fi);

    // 如果这是最后一个分片（MF=0），就可以知道完整长度了
    if (!moreFrag) {
        const int start = offset8 * 8;
        buf.totalLength = start + payload.size();   // 注意 payload 就是 IP header 后的数据
    }

    QByteArray fullPayload;
    if (tryAssemble(buf, fullPayload)) {
        // 完成了，删除这个 key 的缓存
        m_buffers.remove(key);
        return fullPayload; // 返回完整的 IP payload
    }


    return QByteArray();
}

void IpReassembler::onCleanupTimeout()
{
    auto it = m_buffers.begin();
    while (it != m_buffers.end()) {
        if (!it->timer.isValid() ||
            it->timer.elapsed() > REASSEMBLY_TIMEOUT_MS) {
            it = m_buffers.erase(it);
        } else {
            ++it;
        }
    }
}
