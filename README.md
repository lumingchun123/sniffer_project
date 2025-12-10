# sniffer_project

一个用 **Qt 6 + libpcap** 写的轻量级抓包工具，用来学习和观察以太网 / IP / TCP / UDP / ICMP 等协议。

## 功能概览

- 实时抓包（基于 `pcap_loop`）
- 支持选择网卡 + BPF 过滤表达式（如 `tcp port 80`）
- 解析并展示：
  - Ethernet：源/目的 MAC、EtherType
  - IPv4：源/目的 IP、协议号、总长度
  - ARP：Request / Reply
  - TCP：源/目的端口、Seq / Ack（基础版）
  - UDP：源/目的端口、长度
  - ICMP：type / code
- IPv4 分片重组（`IpReassembler`）
- 简单 GUI：用 `QListWidget` 实时显示一行 summary

