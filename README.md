Pcap_DNSProxy
=====
A local DNS server base on WinPcap and LibPcap. 

### Branch
本分支 master 为 Pcap_DNSProxy 项目的主分支，用于存放源代码，**编译版本请移步 [Release 分支](https://github.com/chengr28/Pcap_DNSProxy/tree/Release)**

### Usage
* Windows [简体中文](https://github.com/chengr28/Pcap_DNSProxy/wiki/ReadMe(Chinese_Simplified))/[繁體中文](https://github.com/chengr28/Pcap_DNSProxy/wiki/ReadMe(Chinese_Traditional))
* [Linux](https://github.com/chengr28/Pcap_DNSProxy/wiki/ReadMe_Linux)
* [Mac](https://github.com/chengr28/Pcap_DNSProxy/wiki/ReadMe_Mac)

### Updated
* **Windows：0.4 Beta 13(2015-02-18)**
* **Linux：0.2(2014-08-19)**
* **Mac：0.1(2014-08-19)**

### Summary
* **Pcap_DNSProxy 是一个基于 LibPcap/WinPcap 制作的用于忽略DNS投毒污染的小工具，后期也加入了对包含正则表达式的 Hosts 和 DNSCurve/DNSCrypt 协议以及多线程请求的支持**<br />
* 本工具同时也支持使用 TCP 协议请求，在被连接重置时会自动切换到 UDP 协议，可以使请求者获得正确的域名解析。**完全支持正则表达式 Hosts 条目**，可以为使用者提供更加便捷的途径设定域名所对应的地址，避免修改系统文件的麻烦。而多线程或多服务器多线程的请求，更能提高在恶劣网络环境下域名解析的可靠性。

### Feature
* 同时支持本地 IPv4/IPv6 协议以及自定义端口的监听和远程请求
* Native Code 原生编译，不含任何托管代码，x64版为原生64位目标平台编译
* 作为服务工作于系统底层
* 多线程请求模型，充分利用多线程处理器的硬件资源
* 使用 WinPcap/LibPcap 利用系统底层驱动抓取数据包，多种过滤方式忽略接收到的伪造数据包
* 支持服务器模式，相当于小型的 DNS 服务器，能为其它设备提供解析服务，并可限制可请求的范围
* 主要和备用双服务器模式，多服务器多次请求功能，提高 DNS 解析的可靠性
* DNS 缓存功能
* 支持 EDNS0 标签
* 支持 DNSCurve/DNSCrypt 协议
* Hosts Only 模式可只使用本工具支持正则表达式的 Hosts 的直连模式
* Local Hosts 境内 DNS 服务器解析功能，可提高对境内域名的解析速度和服务器的访问速度
* 丰富的配置选项，配置文件支持 ANSI、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 编码以及 Windows/Unix/Macintosh 换行格式
* 错误报告功能
* C/C++ 编写而成，使用 Visual Studio 2013 Update 3/VC++ 进行编译，完全支持 Unicode

### Library
* 正则表达式支持由 C++ STL(Windows)/系统自带的正则库(Linux/Mac) 提供
* 文件 Hash 使用的算法由 [SHA-3/Keccak](http://keccak.noekeon.org) 提供
* 由 C++ STL 自带的梅森旋转算法引擎产生离散型均匀分布随机数，用于随机域名探测
* DNSCurve 协议使用的 Curve25519/Salsa20/Poly1305 算法由 [LibSodium](https://github.com/jedisct1/libsodium) 提供
* DNSCurve 协议加密模式使用的一次性 Nonce 亦由 [LibSodium](https://github.com/jedisct1/libsodium) 附带的随机数产生器提供

### Platform
* 本工具**抓包模块**所支持的网络类型
  * 网络设备类型为 Ethernet 的网络
  * 原生 IPv4 网络和原生 IPv6 网络
  * 基于 PPPoE 的 IPv4 网络和 PPPoEv6 的 IPv6网络
  * 如果需要支持更多网络类型，可与作者联系
* Windows
    * **Windows XP SP3/2003 SP2 以及更新的版本(32位/x86版本)和 Windows Vista/2008 以及更新的版本(64位/x64版本)**
    * 支持最新版本 [WinPcap](http://www.winpcap.org/install/default.htm)
* Linux
    * 支持 [编译所需依赖包](https://github.com/chengr28/Pcap_DNSProxy/wiki/ReadMe_Linux) 的Linux发行版
    * 支持最新版本 [Libpcap](http://www.tcpdump.org)
* Mac
    * **采用Intel平台处理器的 Mac OS X 10.5 Leopard 以及更新的版本**

### License
GNU General Public License/GNU GPL v2
