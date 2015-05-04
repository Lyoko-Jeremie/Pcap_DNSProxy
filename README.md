Pcap_DNSProxy
=====
A local DNS server base on WinPcap and LibPcap. 

### Usage
**本分支 master 为 Pcap_DNSProxy 项目的主分支用于存放源代码，编译版本请移步 [Release 分支](https://github.com/chengr28/Pcap_DNSProxy/tree/Release)**<br />
说明文档等参见项目 [Documents 文件夹](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的内容

### Updated
* 0.4 Beta 17   on Windows   (2015-05-05)
* 0.4 Beta 3    on Linux     (2015-05-05)
* 0.1           on Mac       (2014-08-19)

### Summary
Pcap_DNSProxy 是一个基于 LibPcap/WinPcap 制作用于忽略 DNS 投毒污染的工具，包含对支持正则表达式的 Hosts 和 DNSCurve/DNSCrypt 协议以及多线程、TCP 协议请求的支持，可以提供便捷途径和更强大修改 Hosts 的方法，避免修改系统文件的麻烦。而多服务器多线程请求功能，更可提高在恶劣网络环境下域名解析的可靠性。
* Native Code 原生编译，不含任何托管代码，x64 版为原生 64 位目标平台编译
* 多线程请求模型，充分利用多线程处理器的硬件资源
* 支持 IPv4/IPv6 协议以及自定义多端口多地址监听和远程请求
* 使用 Pcap 利用系统底层驱动抓取数据包，多种过滤方式忽略接收到的伪造数据包
* 支持服务器模式，相当于小型的 DNS 服务器能为其它设备提供解析服务，并可限制可请求的范围
* 主要和备用双服务器模式，请求服务器支持多服务器多线程多次请求，提高 DNS 解析可靠性
* DNS 缓存功能，支持 EDNS0 标签和请求 DNSSEC 功能
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
    * **Windows XP SP3/2003 SP2 以及更新的版本(32位/x86版本)和 Windows Vista/2008 以及更新的版本(64位/x64版本)**
* Linux
    * 支持 [编译所需依赖包](https://github.com/chengr28/Pcap_DNSProxy/tree/master/Documents) 的 Linux 发行版
* Mac
    * **采用Intel平台处理器的 Mac OS X 10.5 Leopard 以及更新的版本**

### Library
* 正则表达式支持由 C++ STL(Windows/Linux)/系统自带的正则库(Mac) 提供
* 文件 Hash 使用的算法由 [SHA-3/Keccak](http://keccak.noekeon.org) 提供
* 离散型均匀分布随机数由 C++ STL 自带的梅森旋转算法引擎产生
* DNSCurve 协议使用的 Curve25519/Salsa20/Poly1305 算法由 [LibSodium](https://github.com/jedisct1/libsodium) 提供
* DNSCurve 协议加密模式使用的一次性 Nonce 亦由 [LibSodium](https://github.com/jedisct1/libsodium) 附带的随机数产生器提供

### License
GNU General Public License/GNU GPL v2
