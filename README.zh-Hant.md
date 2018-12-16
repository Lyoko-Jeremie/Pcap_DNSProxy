Pcap_DNSProxy
=====
Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap

### Releases
[![GitHub release](https://img.shields.io/github/release/chengr28/Pcap_DNSProxy.svg)](https://github.com/chengr28/Pcap_DNSProxy/releases/latest)
[![GitHub (pre-)release](https://img.shields.io/github/release/chengr28/Pcap_DNSProxy/all.svg?label=pre-release)](https://github.com/chengr28/Pcap_DNSProxy/releases)

### Usage
**說明文檔參見專案 [Documents 資料夾](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的內容**

### Summary
Pcap_DNSProxy 是一個基於 WinPcap/LibPcap 用於過濾 DNS 投毒污染的工具，提供便捷和強大的包含正則運算式的修改 Hosts 的方法，以及對 DNSCurve/DNSCrypt 協定、並行和 TCP 協定請求的支援。多伺服器並行請求功能，更可提高在惡劣網路環境下網域名稱解析的可靠性：
* IPv4/IPv6 協定雙棧支援，並可自訂多埠多位址監聽和遠端請求協定
* 伺服器模式為其它設備提供解析服務，可限制請求範圍
* 支援對 CNAME 記錄和解析結果進行 Hosts 並同時支援 Local Hosts 境內 DNS 伺服器解析，可提高對境內網域名稱解析速度和伺服器存取速度
* 主要/備用雙伺服器模式，境外伺服器支援並行多次請求，提高 DNS 解析可靠性
* 獨立 DNS 緩存、EDNS 標籤、DNSSEC 請求功能以及完整的 DNSCurve/DNSCrypt 協定支援
* 原生 SOCKS 版本 4/4a/5 和 HTTP CONNECT 隧道協定包括 TLS/SSL 加密連接的支援
* 豐富的配置參數和選項以及錯誤報表功能
* 支援 ASCII 和 UTF-8(/BOM) 和 UTF-16(LE/BE) 和 UTF-32(LE/BE) 編碼以及 Unicode 標準要求實現的所有空格/換行格式

### Platform
* Windows
  * **64位/x64版本：Windows Vista/2008 以及更新的版本**
  * **32位/x86版本：Windows XP SP3/2003 SP2 以及更新的版本**
* FreeBSD/Linux
  * 支援 [編譯所需依賴包](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的 FreeBSD/Linux 版本
* macOS
  * **支援 64 位 Mac OS X 10.8(Mountain Lion) 以及更新的 macOS 版本**
* OpenWrt/LEDE
  * **參見 [openwrt-Pcap_DNSProxy 專案](https://github.com/wongsyrone/openwrt-Pcap_DNSProxy)**
* 本工具**抓包模組**所支援的網路類型
  * 網路裝置類型為 Ethernet 和 Apple IEEE 1394/FireWire 的網路
  * 原生 IPv4/PPPoE 和 IPv6/PPPoEv6 網路

### License
GNU General Public License/GNU GPL v2
