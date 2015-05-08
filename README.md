Pcap_DNSProxy
=====
A local DNS server base on WinPcap and LibPcap. 

### Usage
**本分支 master 为 Pcap_DNSProxy 项目的主分支用于存放源代码，编译版本请移步 [Release 分支](https://github.com/chengr28/Pcap_DNSProxy/tree/Release)**<br />
说明文档等参见项目 [Documents 文件夹](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的内容

### Updated
* 0.4 Beta 17   on Windows
* 0.4 Beta 3    on Linux
* 0.4 Beta 1    on Mac

### Summary
Pcap_DNSProxy 是一个基于 WinPcap/LibPcap 制作用于过滤 DNS 投毒污染的工具，包含对支持正则表达式的 Hosts 和 DNSCurve/DNSCrypt 协议以及多线程、TCP 协议请求的支持，可以提供便捷途径和更强大修改 Hosts 的方法。多服务器多线程请求功能，更可提高在恶劣网络环境下域名解析的可靠性。
* Native Code 原生编译不含任何托管代码，x64 版为原生 64 位目标平台编译
* 多线程请求模型，充分利用多线程处理器的硬件资源
* 支持 IPv4/IPv6 协议以及自定义多端口多地址监听和远程请求
* 使用 Pcap 系统底层驱动抓取数据包，多种方法过滤收到的伪造数据包
* 支持服务器模式，相当于一台 DNS 服务器，能为其它设备提供解析服务，并可限制请求的范围
* 主要/备用双服务器模式，请求服务器支持多服务器多线程多次请求，提高 DNS 解析可靠性
* 独立 DNS 缓存、支持 EDNS0 标签和请求 DNSSEC 的功能
* Local Hosts 境内 DNS 服务器解析功能，可提高对境内域名解析速度和服务器访问速度
* 支持 DNSCurve/DNSCrypt 协议
* 丰富的配置选项，配置文件支持 ANSI、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 编码以及 Windows/Unix/Macintosh 换行格式
* 错误报告以及详细的运行日志功能
* 完全支持 Unicode

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
  * 不支持任何 32 位平台的 Mac OS X 系统

### Library
* 正则表达式支持由 C++ 11 STL 提供
* 文件 Hash 使用的算法由 [SHA-3/Keccak](http://keccak.noekeon.org) 提供
* 离散型均匀分布随机数由 C++ 11 STL 提供的梅森旋转算法引擎产生
* DNSCurve 协议使用的 Curve25519/Salsa20/Poly1305 算法由 [LibSodium](https://github.com/jedisct1/libsodium) 提供
* DNSCurve 协议加密模式使用的一次性 Nonce 亦由 [LibSodium](https://github.com/jedisct1/libsodium) 附带的随机数产生器提供

### License
GNU General Public License/GNU GPL v2
