Pcap_DNSProxy
=====
A local DNS server based on WinPcap and LibPcap

### Usage
**本分支 master 为 Pcap_DNSProxy 项目用于存放源代码的分支，可执行编译版本请移步 [Release 分支](https://github.com/chengr28/Pcap_DNSProxy/tree/Release)，说明文档参见项目 [Documents 文件夹](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的内容**

### Updated
**0.4.4.1** for Windows/Linux/Mac

### Summary
Pcap_DNSProxy 是一个基于 WinPcap/LibPcap 用于过滤 DNS 投毒污染的工具，提供支持正则表达式的 Hosts 提供更便捷和强大的修改 Hosts 的方法，以及对 DNSCurve/DNSCrypt 协议、并行和 TCP 协议请求的支持。多服务器并行请求功能，更可提高在恶劣网络环境下域名解析的可靠性。
* 原生 64 位编译
* IPv4/IPv6 协议双栈支持，并可自定义多端口多地址监听和远程请求协议
* 服务器模式为其它设备提供解析服务，可限制请求的范围
* Pcap 在系统底层驱动抓取数据包，多种方法过滤收到的伪造数据包
* 支持 Local Hosts 境内 DNS 服务器解析，可提高对境内域名解析速度和服务器访问速度
* 主要/备用双服务器模式，境外服务器支持多服务器并行多次请求，提高 DNS 解析可靠性
* 独立 DNS 缓存、EDNS 标签、DNSSEC 请求功能以及完整的 DNSCurve/DNSCrypt 协议支持
* 原生 SOCKS 版本 4/4a/5 协议支持
* 丰富的配置参数和选项，以及错误报告功能
* 完全支持 ASCII、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 编码以及 Unicode 标准要求实现的所有空格/换行格式

### Platform
* 本工具**抓包模块**所支持的网络类型
  * 网络设备类型为 Ethernet 和 Apple IEEE 1394/FireWire 的网络
  * 原生 IPv4/PPPoE 网络和原生 IPv6/PPPoEv6 网络
* Windows
  * **64位/x64版本：Windows Vista/2008 以及更新的版本**
  * **32位/x86版本：Windows XP SP3/2003 SP2 以及更新的版本**
* Linux
  * 支持 [编译所需依赖包](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的 Linux 发行版
* Mac
  * **支持 64 位平台 Mac OS X 10.7 Lion 以及更新的版本**
  * Mac OS X 平台可通过 Homebrew 进行安装

### License
GNU General Public License/GNU GPL v2
