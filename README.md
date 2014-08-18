Pcap_DNSProxy
=====
A local DNS server base on WinPcap and LibPcap. 

### 关于分支
本分支 master 为 Pcap_DNSProxy 项目的主分支，用于存放源代码，**编译版本请移步 [Release 分支](https://github.com/chengr28/pcap_dnsproxy/tree/Release)**

### 使用方法
* Windows 版参见 [Wiki](https://github.com/chengr28/pcap_dnsproxy/wiki) 中 [ReadMe](https://github.com/chengr28/pcap_dnsproxy/wiki/ReadMe) 之内容
* Linux 版参见 [Wiki](https://github.com/chengr28/pcap_dnsproxy/wiki) 中 [ReadMe_Linux](https://github.com/chengr28/pcap_dnsproxy/wiki/ReadMe_Linux) 之内容
* Mac 版参见 [Wiki](https://github.com/chengr28/pcap_dnsproxy/wiki) 中 [ReadMe_Mac](https://github.com/chengr28/pcap_dnsproxy/wiki/ReadMe_Mac) 之内容

### 最新版本
* **Windows 版本：v0.4 Beta(2014-08-18)**
* **Linux 版本：v0.2(2014-03-02)**
* **Mac 版本：v0.1(2014-03-02)**

### 简介
* **Pcap_DNSProxy 是一个基于 LibPcap/WinPcap 制作的用于忽略DNS投毒污染的小工具，后期也加入了对包含正则表达式的Hosts的支持**<br />
* 很多使用TCP协议进行解析的工具，可以用于忽略DNS投毒污染。但事实上已经出现有使用TCP协议请求域名解析时被连接重置的情况，而使用UDP协议则又会被DNS投毒污染，导致其始终无法获得正确的域名解析。**本工具主要工作在UDP协议上，可以将伪造的数据包完全过滤**，同时UDP协议比起TCP协议更具有占用资源低和发送转发接收速度快等特点。**本工具同时也支持使用TCP协议进行请求，而且在被连接重置时会自动切换到UDP协议，可以使请求者获得正确的域名解析**<br />
* **完全支持正则表达式 Hosts 条目，可以为使用者提供更加便捷的途径设定域名所对应的地址，避免修改系统文件的麻烦**<br />
* 本工具使用 C/C++ 编写而成，使用 Visual Studio 2012(Update 3)/VC++ 11.0(Windows)、GCC 4.7.2/g++(Linux) 和 Xcode 5.0.1/Apple LLVM 5.0(Mac) 进行编译，完全支持 Unicode

### 特点
* 同时支持本地IPv4/IPv6协议监听和远程请求
* 普通DNS请求模式同时支持TCP/UDP协议
* Native Code 原生码编译，不含任何托管代码，x64版为原生64位目标平台编译
* 作为系统服务工作于底层
* 多线程模型，充分利用多线程处理器的硬件资源
* 使用 WinPcap/LibPcap 利用系统底层驱动抓取数据包，多种过滤方式忽略接收到的伪造数据包
* 支持服务器模式，相当于一个小型的DNS服务器，能为其它设备提供解析服务，并可限制可请求的范围
* 主要和备用双服务器模式，多个服务器多次请求功能，提高DNS解析的可靠性
* DNS缓存功能
* 支持 EDNS0 标签
* 支持 DNSCurve/DNSCrypt 协议
* Hosts Only 模式可只使用本工具支持正则表达式的 Hosts 的直连模式
* 支持 Local Hosts 境内DNS服务器解析功能，可提高对境内域名的解析速度和服务器的访问速度
* 丰富的配置选项，读取文件支持 ANSI、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 编码以及 Windows/Unix/Macintosh 换行格式
* 错误报告功能

### 使用的库
* 正则表达式支持由 C++ STL(Windows)/系统自带的正则库(Linux/Mac) 提供
* 文件 Hash 使用的算法由 [SHA-3/Keccak](http://keccak.noekeon.org) 提供
* 由 C++ STL 自带的梅森旋转算法引擎产生离散型均匀分布随机数，用于随机域名探测
* DNSCurve 协议使用的 Curve25519/Salsa20/Poly1305 算法由 [LibSodium](https://github.com/jedisct1/libsodium) 提供
* DNSCurve 协议加密模式使用的一次性 Nonce 亦由 [LibSodium](https://github.com/jedisct1/libsodium) 附带的随机数产生器提供

### 支持平台
* 本工具**抓包模块**所支持的网络类型
  * 网络设备类型为 Ethernet 的网络
  * 原生IPv4网络和原生IPv6网络**（非原生IPv6网络环境切勿开启IPv6功能）**
  * 基于PPPoE或PPPoEv6的IPv4网络和IPv6网络
  * 如果需要支持更多网络类型，可与作者联系
* Windows 平台
    * **所有 Windows XP/2003 以及更新内核的版本(32位/x86版本)和 Windows Vista/2008 以及更新的版本(64位/x64版本)**
    * 支持最新版本 [WinPcap](http://www.winpcap.org/install/default.htm)
* Linux 平台
    * 支持 [编译所需依赖包](https://github.com/chengr28/pcap_dnsproxy/wiki/ReadMe_Linux) 的Linux发行版
    * 支持最新版本 [Libpcap](http://www.tcpdump.org)
* Mac 平台
    * **采用Intel平台处理器的 Mac OS X 10.5 Leopard 以及更新的版本**

### 许可证
GNU General Public License/GNU GPL v2
