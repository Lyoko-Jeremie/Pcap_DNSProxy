特别声明：

Pcap_DNSProxy 仅供学习交流，遵循 GNU GPL 通用公共许可证 (GNU General Public License) ，切勿将其用于任何非法用途！
使用前请自行估量是否有加载 Pcap_DNSProxy 的需要，如果不能清楚判断而造成之不良后果，项目组所有成员均不承担一切责任！
使用 Pcap_DNSProxy 源代码前务必参阅 GNU-GPL-v2.0 以及 Source-License 通用公共许可证之内容！


Pcap_DNSProxy 项目的GitHub页面：
* 主分支: https://github.com/chengr28/pcap_dnsproxy
* Release_x86 分支: https://github.com/chengr28/pcap_dnsproxy/tree/Release_x86
* Release_x64 分支: https://github.com/chengr28/pcap_dnsproxy/tree/Release_x64

Pcap_DNSProxy 项目的Sourceforge页面：
http://sourceforge.net/projects/pcap-dnsproxy


-------------------------------------------------------------------------------


Pcap_DNSProxy 是一个基于 LibPcap/WinPcap 制作的用于忽略DNS投毒污染的小工具，后期也加入了对包含正则表达式的Hosts的支持
很多使用TCP协议进行解析的工具，可以用于忽略DNS投毒污染。但事实上已经出现有使用TCP协议请求域名解析时被连接重置的情况，而使用UDP协议则又会被DNS投毒污染，导致其始终无法获得正确的域名解析。本工具主要工作在UDP协议上，可以将伪造的数据包完全过滤，同时UDP协议比起TCP协议更具有占用资源低和发送转发接收速度快等特点。本工具同时也支持使用TCP协议进行请求，而且在被连接重置时会自动切换到UDP协议，可以使请求者获得正确的域名解析
完全支持正则表达式 Hosts 条目，可以为使用者提供更加便捷的途径设定域名所对应的地址，避免修改系统文件的麻烦
本工具使用 C/C++ 编写而成，使用 Visual Studio 2012(Update 3)/VC++ 11.0 进行编译，完全支持 Unicode

Pcap_DNSProxy 的特点：
* 同时支持IPv4/IPv6协议，也可单独开启
* 普通DNS请求模式同时支持TCP/UDP协议
* Native Code 原生码编译，不含任何托管代码，x64版为原生64位目标平台编译
* 作为系统服务工作于底层
* 多线程模型
* 使用 LibPcap/WinPcap 利用系统底层驱动抓取数据包，多种过滤方式忽略接收到的伪造数据包
* 支持服务器模式，相当于一个小型的DNS服务器，能为其它设备提供解析服务，并可限制可请求的范围
* 主要和备用双服务器模式，提高DNS解析的可靠性
* DNS缓存功能
* 支持 EDNS0 标签
* 支持 DNSCurve/DNSCrypt 协议
* Hosts Only 模式可只适用本工具支持正则表达式的 Hosts 的功能
* 支持 Local Hosts 境内DNS服务器解析功能，可提高对境内域名的解析速度和服务器的访问速度
* 丰富的配置选项，读取文件支持 ANSI、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 编码以及 Windows/Unix/Macintosh 换行格式
* 错误报告功能

Pcap_DNSProxy 使用的库：
* 正则表达式支持由 C++ STL(Windows)/系统自带的正则库(Linux/Mac) 提供
* 文件 Hash 使用的算法由 SHA-3/Keccak 提供：http://keccak.noekeon.org
* 由 C++ STL 自带的梅森旋转算法引擎产生离散型均匀分布随机数，用于随机域名探测
* DNSCurve 协议使用的 Curve25519/Salsa20/Poly1305 算法由 LibSodium 提供：https://github.com/jedisct1/libsodium
* DNSCurve 协议加密模式使用的一次性 Nonce 亦由 LibSodium 附带的随机数产生器提供

Pcap_DNSProxy 支持平台：
* 所有 Windows NT(4) 以及更新内核的操作系统（32位/x86版本） 和 Windows Vista 以及更新的操作系统（64位/x64版本）
* 支持最新版本 WinPcap（参见 http://www.winpcap.org/install/default.htm）
* 网络设备类型为 Ethernet 或直接使用 PPPoE 协议均可
* 本工具只支持原生IPv4/IPv6网络，非原生IPv6切勿开启IPv6功能


-------------------------------------------------------------------------------


安装方法（需要以管理员身份进行）：

1.访问 http://www.winpcap.org/install/default.htm 下载并以管理员权限安装 WinPcap
  * Release 版本压缩包中也提供有 WinPcap 的安装程序
  * WinPcap 只需要安装一次，以后更新时请从第2步开始操作
  * 安装时自启动选项对工具的运行没有影响，因为本工具直接调用 WinPcap API，不需要经过服务器程序
2.访问 https://github.com/chengr28/pcap_dnsproxy/branches 随便选择一个 Release 版本，并使用 GitHub 的 Download ZIP 功能将所有文件下载到本地
  * Windows 下批处理会自动判断 x64 和 x86 版本
3.打开下载回来的ZIP文件，将 Main 目录解压到磁盘的任意位置
  * 目录所在位置和程序文件名可以随意更改
  * 注意：配置文件/Hosts文件和IPFilter文件只能使用固定的文件名（更多详细情况参见下文 功能和技术 一节）
4.确定工具目录的名称和路径后进入目录内，右键以管理员身份(Vista以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceInstall.bat
  * 批处理会将程序注册系统服务，并进行 Windows 防火墙测试
  * 以后每次开机服务都将自动启动
5.此时 Windows 系统会询问是否同意程序访问网络，请将 "专用网络" 以及 "公用网络" 都勾上并确认
6.打开 网络和共享中心 - 更改适配器设置 选择 本地连接 或 宽带连接（取决于实际使用的网络适配器）
  * 右击 属性 - Internet协议版本4(IPv4) - 属性 - 勾选 "使用下面的DNS服务器地址"
  * 在 首选DNS服务器 内填入 "127.0.0.1"（不含引号） 确定保存并退出即可
  * 如果需要使用IPv6协议的本地服务器
    * 请先编辑配置文件的 IPv6 DNS Address 一栏，参见下文 配置文件详细参数说明 一节
    * 右击 属性 - Internet协议版本6(IPv6) - 属性 - 勾选 "使用下面的DNS服务器地址"
	* 在 首选DNS服务器 内填入 "::1"（不含引号） 确定保存并退出即可


重启服务方法（需要以管理员身份进行）：
1.右键以管理员身份(Vista以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceStop.bat
  * 批处理将直接停止服务的运行
2.右键以管理员身份(Vista以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceStart.bat 即可
  * 批处理将启动服务，完成后相当于重启服务


更新程序方法（需要以管理员身份进行）：
注意：更新程序切勿直接覆盖，否则可能会造成不可预料的错误！请按照以下的步骤进行：
1.提前下载好新版本的 Pcap_DNSProxy（亦即 安装方法 中第2步），更新过程可能会造成域名解析短暂中断
2.备份好所有配置文件/Hosts文件/IPFilter文件的自定义内容
3.右键以管理员身份(Vista以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceStop.bat 停止服务
4.将整个 Pcap_DNSProxy 程序的目录删除
  * 注意 Windows 防火墙可能会留有允许程序访问网络的信息，卸载服务后又变更了程序的目录则可能需要使用注册表清理工具清理
5.将新版本的 Pcap_DNSProxy 解压到任何位置（亦即 安装方法 中第3步）
6.将配置文件的自定义内容加回新版本配置文件里相应的区域内
7.按照 安装方法 中第4步重新部署 Pcap_DNSProxy


卸载方法（需要以管理员身份进行）：

1.按照 安装方法 中第6步还原DNS域名服务器地址配置
2.右键以管理员身份(Vista以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceUninstall.bat 即可，批处理将直接停止服务并卸载服务
  * 注意 Windows 防火墙可能会留有允许程序访问网络的信息，故卸载后可能需要使用注册表清理工具清理
  * 转移工具目录路径不需要卸载服务，先停止服务转移，转移完成后重新右键以管理员身份(Vista以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceInstall.bat 即可


正常工作查看方法：

1.打开命令提示符
  * 在开始菜单或直接 Win + R 调出 运行 ，输入 cmd 并回车
  * 开始菜单 - 程序/所有程序 - 附件 - 命令提示符
2.输入 nslookup www.google.com 并回车
3.运行结果应类似：

   >nslookup www.google.com
    服务器:  pcap-dnsproxy.localhost.server（视配置文件设置的值而定，参见下文 配置文件详细参数说明 一节）
    Address:  127.0.0.1（视所在网络环境而定，原生IPv6为 ::1）

    非权威应答:
	名称:    www.google.com
	Addresses: ……（IP地址或地址列表）

4.如非以上结果，请移步 FAQ 文档中 运行结果分析 一节


-------------------------------------------------------------------------------


注意事项：

* 如修改DNS服务器，请务必设置一个正确的、有效的、可以正常使用的境外DNS服务器！
* 如果程序启动提示丢失 wpcap.dll 请重新安装 WinPcap 或者将其更新到最新版本
* Linux/Mac 平台下读取文件名首字母大写优先级高于小写，Windows 平台下读取文件名时不存在大小写的区别
* 配置文件/Hosts文件/IPFilter文件和错误报告所在的目录以上文 安装方法 一节中第4步注册的服务信息为准
  * 注意填写时一行不要超过4096字节/4KB
* 服务启动前请先确认没有其它本地DNS服务器运行或本工具多个拷贝运行中，否则可能会导致监听冲突无法正常工作
  * 监听冲突会生成错误报告，可留意 Windows Socket 相关的错误（参见 FAQ 文档中 Error.log 详细错误报告 一节）
* 杀毒软件/第三方防火墙可能会阻止本程序的操作，请将行为全部允许或将本程序加入到白名单中
* 如果启动服务时提示 "服务没有及时响应启动或者控制请求" 请留意是否有错误报告生成，详细的错误信息参见 FAQ 文档中 Error.log 详细错误报告 一节
* 目录和程序的名称可以随意更改，但请务必在进行安装方法第4步前完成。如果服务注册后需移动工具目录的路径，参见上文 卸载方法 第2步的注意事项
* 由于本人水平有限，程序编写难免会出现差错疏漏，如有问题可至项目页面提出，望谅解 v_v


-------------------------------------------------------------------------------


功能和技术：
* 批处理的作用（运行结束会有运行结果）：
  * ServiceInstall - 将程序注册为系统服务，并启动程序进行 Windows 防火墙测试
    * 运行结束时会显示 "Done. Please confirm the PcapDNSProxyService service had been installed."
	* 具体是否成功需要留意屏幕上的提示
  * ServiceStart - 启动工具服务
    * 运行结束时会显示 "Done. Please confirm the PcapDNSProxyService service had been started."
	* 具体是否成功需要留意屏幕上的提示
  * ServiceQuery - 适用于 Windows XP/2003 以及更旧版本Windows的测试批处理，能测试工具服务是否安装成功
  * ServiceStop - 即时停止工具服务，重启服务时需要先停止服务
    * 运行结束时会显示 "Done. Please confirm the PcapDNSProxyService service had been stopped."
	* 具体是否成功需要留意屏幕上的提示
  * ServiceUninstall - 停止并卸载工具服务
    * 运行结束时会显示 "Done. Please confirm the PcapDNSProxyService service had been deleted."
	* 具体是否成功需要留意屏幕上的提示
* 配置文件支持的文件名（只会读取优先级较高者，优先级较低者将被直接忽略）：
  * Windows: Config.ini > Config.conf > Config
  * Linux/Mac: Config.conf > Config.ini > Config
* Hosts 文件支持的文件名（优先级自上而下递减）：
  * Windows: Hosts.ini > Hosts.conf > Hosts > Hosts.txt
  * Linux/Mac: Hosts.conf > Hosts.ini > Hosts > Hosts.txt
  * Hosts 文件存在即会读取，优先级高者先读取，存在相同条目时将附加到优先级高者后，请求响应时位置越前，相同的地址将会被自动合并
* IPFilter 数据库支持的文件名（优先级自上而下递减）：
  * IPFilter.dat
  * IPFilter.csv
  * IPFilter.txt
  * IPFilter
  * Guarding.P2P
  * Guarding
  * IPFilter 文件存在即会读取，相同的地址范围将会被自动合并
* 请求域名解析优先级
  * 使用系统API函数进行域名解析（大部分）：系统 Hosts > Pcap_DNSProxy 的 Hosts 条目（Whitelist/白名单条目 > Hosts/主要Hosts列表） > DNS缓存 > Local Hosts/境内DNS解析域名列表 > 远程DNS服务器
  * 直接使用网络适配器设置进行域名解析（小部分）：Pcap_DNSProxy 的 Hosts.ini（Whitelist/白名单条目 > Hosts/主要Hosts列表） > DNS缓存 > Local Hosts/境内DNS解析域名列表 > 远程DNS服务器
  * 请求远程DNS服务器的优先级：Hosts Only 模式 > TCP模式的DNSCurve 加密/非加密模式（如有） > UDP模式的DNSCurve 加密/非加密模式（如有） > TCP模式普通请求（如有） > UDP模式普通请求
* 一个含有大部分境内域名的 [Local Hosts] 如有需要可直接添加到 Pcap_DNSProxy 的 Hosts 里
  * https://xinhugo-list.googlecode.com/svn/trunk/White_List.txt
* DNS缓存类型
  * Timer/计时型：可以自定义缓存的时间长度，队列长度不限
  * Queue/队列型：默认缓存时间15分钟，可通过 Hosts 文件的 Default TTL 值自定义，同时可自定义缓存队列长度（亦即限制队列长度的 Timer/计时型）
* 本工具的 DNSCurve/DNSCrypt 协议是内置的实现，不需要安装 DNSCrypt 官方的工具！
  * DNSCurve 协议为 Streamlined/精简类型
  * 注意：DNSCrypt 官方工具会占用本地DNS端口导致 Pcap_DNSProxy 部署失败


-------------------------------------------------------------------------------


配置文件详细参数说明：

有效参数格式为 "选项名称 = 数值/数据"（不含引号，注意空格和等号的位置）
注意：配置文件只会在工具服务开始时读取，修改本文件的参数后请重启服务（参见上文 注意事项 一节中的 重启服务）

* Base - 基本参数区域
  * Version - 配置文件的版本，用于正确识别配置文件：本参数与程序版本号不相关，切勿修改，默认为发布时的最新配置文件版本
  * Print Error - 错误报告功能：开启为1/关闭为0，默认为1
  * File Refresh Time - 文件刷新间隔时间：单位为秒，最短间隔时间为5秒，默认为10秒
  * File Hash - 文件 Hash 功能，开启此功能能降低刷新文件时的CPU占用：开启为1/关闭为0，默认为1

* DNS - 域名解析参数区域
  * Protocol - 发送请求所使用的协议，分 UDP 和 TCP：默认为 UDP
    * 注意：此处所指的协议指的是程序请求远程DNS服务器时所使用的协议，而向本程序请求域名解析时可随意使用 UDP 或 TCP
  * Hosts Only - Hosts Only 模式，启用后将不进行任何数据包过滤，只适用本工具的 Hosts 功能：开启为1/关闭为0，默认为0
  * Cache Type - DNS缓存的类型：分 Timer/计时型以及 Queue/队列型
  * Cache Parameter - DNS缓存的参数：Timer/计时型 时为时间长度，Queue/队列型 时为队列长度
  * Operation Mode - 程序的监听工作模式，分 Server/服务器模式、Private/私有网络模式 和 Proxy/代理模式：默认为 Private
    * Server/服务器模式：打开DNS通用端口（TCP/UDP同时打开），可为所有其它设备提供代理域名解析请求服务
	* Private/私有网络模式：打开DNS通用端口（TCP/UDP同时打开），可为仅限于私有网络地址的设备提供代理域名解析请求服务
	* Proxy/代理模式：只打开回环地址的DNS端口（TCP/UDP同时打开），只能为本机提供代理域名解析请求服务
	* Custom/自定义模式：打开DNS通用端口（TCP/UDP同时打开），可用的地址由 IPFilter 参数决定
  * Listen Port - 监听端口，本地监听请求的端口：可填入 1-65535 之间的端口，如果留空则为53，默认为空
  * IPFilter Type - IPFilter 参数的类型：分为 Deny 禁止和 Permit 允许，对应 IPFilter 参数应用为黑名单或白名单，默认为 Deny
  * IPFilter Level - IPFilter 参数的过滤级别，级别越高过滤越严格，与 IPFilter 条目相对应：0为不启用过滤，如果留空则为0，默认为空

* Addresses - 普通模式地址区域
注意：IPv4地址格式为 "IPv4地址:端口"，IPv6地址格式为"[IPv6地址]:端口"（均不含引号）
  * IPv4 DNS Address - IPv4主要DNS服务器地址：需要输入一个带端口格式的地址，默认为 8.8.4.4:53(Google Public DNS No.2)
  * IPv4 Alternate DNS Address - IPv4备用DNS服务器地址：需要输入一个带端口格式的地址，默认为 8.8.8.8:53(Google Public DNS No.1)
  * IPv4 Local DNS Address - IPv4主要境内DNS服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，默认为 114.114.115.115:53(114 DNS No.2)
  * IPv4 Local Alternate DNS Address - IPv4备用境内DNS服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，默认为 114.114.114.114:53(114 DNS No.1)
  * IPv6 DNS Address - IPv6主要DNS服务器地址：需要输入一个带端口格式的地址，留空为不启用，默认为空
  * IPv6 Alternate DNS Address - IPv6备用DNS服务器地址：需要输入一个带端口格式的地址，留空为不启用，默认为空
  * IPv6 Local DNS Address - IPv6主要境内DNS服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用，默认为空
  * IPv6 Local Alternate DNS Address - IPv6备用境内DNS服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用，默认为空

* Values - 扩展参数值区域
  * EDNS0 Payload Size - EDNS0 标签附带使用的最大载荷长度：最小为DNS协议实现要求的512(bytes)，留空则使用 EDNS0 标签要求最短的1220(bytes)，默认为留空
  * IPv4 TTL - IPv4主要DNS服务器接受请求的远程DNS服务器数据包的TTL值：0为自动获取，取值为 1-255 之间：默认为0
  * IPv6 Hop Limits - IPv6主要DNS服务器接受请求的远程DNS服务器数据包的 Hop Limits 值：0为自动获取，取值为 1-255 之间，默认为0
  * IPv4 Alternate TTL - IPv4备用DNS服务器接受请求的远程DNS服务器数据包的TTL值：0为自动获取，取值为 1-255 之间：默认为0
  * IPv6 Alternate Hop Limits - IPv6备用DNS服务器接受请求的远程DNS服务器数据包的 Hop Limits 值：0为自动获取，取值为 1-255 之间，默认为0
  * Hop Limits Fluctuation - IPv4 TTL/IPv6 Hop Limits 可接受范围，即 IPv4 TTL/IPv6 Hop Limits 的值±数值的范围内的数据包均可被接受，用于避免网络环境短暂变化造成解析失败的问题：取值为 1-255 之间，默认为2
  * Alternate Times - 备用服务器失败次数阈值，一定周期内如超出阈值会触发服务器切换：最小为10次，默认为10次
  * Alternate Time Range - 备用服务器失败次数阈值计算周期：单位为秒，默认为60秒/1分钟
  * Alternate Reset Time - 备用服务器重置切换时间，切换产生后经过次事件会切换回主要服务器：单位为秒，默认为300秒/5分钟
  * ICMP Test - ICMP/Ping测试间隔时间：单位为秒，最短间隔时间为5秒，默认为900秒/15分钟
  * Domain Test - DNS服务器解析域名测试间隔时间：单位为秒，最短间隔时间为5秒，默认为900秒/15分钟

* Switches - 控制开关区域
  * EDNS0 Label - EDNS0 标签支持，开启后将为所有请求添加 EDNS0 标签：开启为1/关闭为0，默认为0
  * DNSSEC Request - DNSSEC 请求，开启后将尝试为所有请求添加 DNSSEC 请求：开启为1/关闭为0，默认为0
    * 注意：此功能为实验性质，本程序不具备任何验证 DNSSEC 回复的能力，单独开启此功能并不能避免DNS投毒污染的问题
  * IPv4 Data Filter - IPv4数据包头检测：开启为1/关闭为0，默认为1
  * TCP Data Filter - TCP数据包头检测；开启为1/关闭为0，默认为1
    * 注意：此选项只能在程序工作模式为TCP下才能使用，非TCP模式时此参数无效
  * DNS Data Filter - DNS数据包头检测：开启为1/关闭为0，默认为1
  * Blacklist Filter - 解析结果黑名单过滤：开启为1/关闭为0，默认为1
  
* Data - 数据区域
  * ICMP ID - ICMP/Ping数据包头部ID的值：格式为 0x**** 的十六进制字符，如果留空则获取线程的ID作为请求用ID，默认为空
  * ICMP Sequence - ICMP/Ping数据包头部Sequence/序列号的值：格式为 0x**** 的十六进制字符，如果留空则为 0x0001 ，默认为空
  * Domain Test Data - DNS服务器解析域名测试：请输入正确、确认不会被投毒污染的域名并且不要超过253字节ASCII数据，留空则会随机生成一个域名进行测试，默认为空
  * Domain Test ID - DNS数据包头部ID的值：格式为 0x**** 的十六进制字符，如果留空则为 0x0001 ，默认为空
  * ICMP PaddingData - ICMP附加数据，Ping程序发送请求时为补足数据使其达到Ethernet类型网络最低的可发送长度时添加的数据：长度介乎于 18字节 - 1512字节 ASCII数据之间，留空则使用 Microsoft Windows Ping 程序的ICMP附加数据，默认为空
  * Localhost Server Name - 本地DNS服务器名称：请输入正确的域名并且不要超过253字节ASCII数据，留空则使用 pcap-dnsproxy.localhost.server 作为本地服务器名称，默认为空

* DNSCurve - DNSCurve 协议基本参数区域
  * DNSCurve - DNSCurve 协议总开关，控制所有和 DNSCurve 协议有关的选项：开启为1/关闭为0，默认为0
  * DNSCurve Protocol - 发送请求所使用的协议，分 UDP 和 TCP：默认为 UDP
  * DNSCurve Payload Size - DNSCurve EDNS0 标签附带使用的最大载荷长度，同时亦为发送请求的总长度，并决定请求的填充长度：最小为DNS协议实现要求的512(bytes)，留空则为512(bytes)，默认为留空
  * Encryption - 启用加密，DNSCurve 协议支持加密和非加密模式：开启为1/关闭为0，默认为1
  * Encryption Only - 只使用加密模式：开启为1/关闭为0，默认为1
    * 注意：使用 只使用加密模式 时必须提供服务器的魔数和指纹用于请求和接收
  * Key Recheck Time - DNSCurve 协议DNS服务器连接信息检查间隔：单位为秒，最短为10秒，默认为3600秒/1小时
  
* DNSCurve Addresses - DNSCurve 协议地址区域
  * DNSCurve IPv4 DNS Address - DNSCurve 协议IPv4主要DNS服务器地址：需要输入一个带端口格式的地址，默认为 208.67.220.220:443(OpenDNS No.2)
  * DNSCurve IPv4 Alternate DNS Address - DNSCurve 协议IPv4备用DNS服务器地址：需要输入一个带端口格式的地址，默认为 208.67.222.222:443(OpenDNS No.1)
  * DNSCurve IPv6 DNS Address - DNSCurve 协议IPv6主要DNS服务器地址：需要输入一个带端口格式的地址，默认为空
  * DNSCurve IPv6 Alternate DNS Address - DNSCurve 协议IPv6备用DNS服务器地址：需要输入一个带端口格式的地址，默认为空
  * DNSCurve IPv4 Provider Name - DNSCurve 协议IPv4主要DNS服务器提供者，请输入正确的域名并且不要超过253字节ASCII数据，默认为 2.dnscrypt-cert.opendns.com(OpenDNS)
    * 注意：自动获取 DNSCurve 服务器连接信息时必须输入提供者的域名，不能留空
  * DNSCurve IPv4 Alternate Provider Name - DNSCurve 协议IPv4备用DNS服务器提供者，请输入正确的域名并且不要超过253字节ASCII数据，默认为 2.dnscrypt-cert.opendns.com(OpenDNS)
    * 注意：自动获取 DNSCurve 服务器连接信息时必须输入提供者的域名，不能留空
  * DNSCurve IPv6 Provider Name - DNSCurve 协议IPv6主要DNS服务器提供者，请输入正确的域名并且不要超过253字节ASCII数据，默认为空
    * 注意：自动获取 DNSCurve 服务器连接信息时必须输入提供者的域名，不能留空
  * DNSCurve IPv6 Provider Name - DNSCurve 协议IPv6备用DNS服务器提供者，请输入正确的域名并且不要超过253字节ASCII数据，默认为空
    * 注意：自动获取 DNSCurve 服务器连接信息时必须输入提供者的域名，不能留空

* DNSCurve Keys - DNSCurve 协议密钥区域
  * Client Public Key - 自定义客户端公钥：可使用 KeyPairGenerator 生成，留空则每次启动时自动生成，默认为空
  * Client Secret Key - 自定义客户端私钥：可使用 KeyPairGenerator 生成，留空则每次启动时自动生成，默认为空
  * IPv4 DNS Public Key - DNSCurve 协议IPv4主要DNS服务器验证用公钥，默认为 B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79(OpenDNS)
  * IPv4 Alternate DNS Public Key - DNSCurve 协议IPv4备用DNS服务器验证用公钥，默认为 B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79(OpenDNS)
  * IPv6 DNS Public Key - DNSCurve 协议IPv6主要DNS服务器验证用公钥，默认为空
  * IPv6 Alternate DNS Public Key - DNSCurve 协议IPv6备用DNS服务器验证用公钥，默认为空
  * IPv4 DNS Fingerprint - DNSCurve 协议IPv4主要DNS服务器传输用指纹，留空则自动通过服务器提供者和公钥获取，默认为空
  * IPv4 Alternate DNS Fingerprint - DNSCurve 协议IPv4备用DNS服务器传输用指纹，留空则自动通过服务器提供者和公钥获取，默认为空
  * IPv6 DNS Fingerprint - DNSCurve 协议IPv6备用DNS服务器传输用指纹，留空则自动通过服务器提供者和公钥获取，默认为空
  * IPv6 Alternate DNS Fingerprint - DNSCurve 协议IPv6备用DNS服务器传输用指纹，留空则自动通过服务器提供者和公钥获取，默认为空
  
* DNSCurve Magic Number - DNSCurve 协议魔数区域
  * IPv4 Receive Magic Number - DNSCurve 协议IPv4主要DNS服务器接收魔数：长度必须为8字节，留空则使用程序内置的接收魔数，默认留空
  * IPv4 Alternate Receive Magic Number - DNSCurve 协议IPv4备用DNS服务器接收魔数：长度必须为8字节，留空则使用程序内置的接收魔数，默认留空
  * IPv6 Receive Magic Number - DNSCurve 协议IPv6主要DNS服务器接收魔数：长度必须为8字节，留空则使用程序内置的接收魔数，默认留空
  * IPv6 Alternate Receive Magic Number - DNSCurve 协议IPv6备用DNS服务器接收魔数：长度必须为8字节，留空则使用程序内置的接收魔数，默认留空
  * IPv4 DNS Magic Number - DNSCurve 协议IPv4主要DNS服务器发送魔数：长度必须为8字节，留空则自动获取，默认留空
  * IPv4 Alternate DNS Magic Number - DNSCurve 协议IPv4备用DNS服务器发送魔数：长度必须为8字节，留空则自动获取，默认留空
  * IPv6 DNS Magic Number - 协议IPv6主要DNS服务器发送魔数：长度必须为8字节，留空则自动获取，默认留空
  * IPv6 Alternate DNS Magic Number - DNSCurve 协议IPv6备用DNS服务器发送魔数：长度必须为8字节，留空则自动获取，默认留空


* 默认的配置文件内容

[Base]
Version = 0.4
Print Error = 1
File Refresh Time = 10
File Hash = 1

[DNS]
Protocol = UDP
Hosts Only = 0
Cache Type = Queue
Cache Parameter = 256

[Listen]
Operation Mode = Private
Listen Port = 
IPFilter Type = Deny
IPFilter Level < 

[Addresses]
IPv4 DNS Address = 8.8.4.4:53
IPv4 Alternate DNS Address = 8.8.8.8:53
IPv4 Local DNS Address = 114.114.115.115:53
IPv4 Local Alternate DNS Address = 114.114.114.114:53
IPv6 DNS Address = 
## Format -> IPv6 DNS Address = [2001:4860:4860::8844]:53
IPv6 DNS Alternate Address = 
## Format -> IPv6 DNS Alternate Address = [2001:4860:4860::8888]:53
IPv6 Local DNS Address = 
IPv6 Local Alternate DNS Address = 

[Values]
EDNS0 Payload Size = 
IPv4 TTL = 0
IPv6 Hop Limits = 0
IPv4 Alternate TTL = 0
IPv6 Alternate Hop Limits = 0
Hop Limits Fluctuation = 2
Alternate Times = 10
Alternate Time Range = 60
Alternate Reset Time = 300
ICMP Test = 900
Domain Test = 900

[Switches]
EDNS0 Label = 0
DNSSEC Request = 0
IPv4 Data Filter = 1
TCP Data Filter = 1
DNS Data Filter = 1
Blacklist Filter = 1

[Data]
ICMP ID = 
ICMP Sequence = 
Domain Test Data = 
Domain Test ID = 
ICMP PaddingData = 
Localhost Server Name = 

[DNSCurve]
DNSCurve = 0
DNSCurve Protocol = UDP
DNSCurve Payload Size = 
Encryption = 1
Encryption Only = 0
Key Recheck Time = 3600

[DNSCurve Addresses]
DNSCurve IPv4 DNS Address = 208.67.220.220:443
DNSCurve IPv4 Alternate DNS Address = 208.67.222.222:443
DNSCurve IPv6 DNS Address = 
## DNSCurve IPv6 DNS Address = [2620:0:CCC::2]:443
DNSCurve IPv6 Alternate DNS Address = 
## DNSCurve Alternate IPv6 DNS Address = [2620:0:CCD::2]:443
DNSCurve IPv4 Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv4 Alternate Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv6 Provider Name = 
## DNSCurve IPv6 Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv6 Provider Name = 
## DNSCurve IPv6 Alternate Provider Name = 2.dnscrypt-cert.opendns.com

[DNSCurve Keys]
Client Public Key = 
Client Secret Key = 
IPv4 DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv4 Alternate DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv6 DNS Public Key = 
## IPv6 DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv6 Alternate DNS Public Key = 
## IPv6 Alternate DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv4 DNS Fingerprint = 
## IPv4 DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007
IPv4 Alternate DNS Fingerprint = 
## IPv4 Alternate DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007
IPv6 DNS Fingerprint = 
##IPv6 DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007
IPv6 Alternate DNS Fingerprint = 
##IPv6 Alternate DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007

[DNSCurve Magic Number]
IPv4 Receive Magic Number = 
IPv4 Alternate Receive Magic Number = 
IPv6 Receive Magic Number = 
IPv6 Alternate Receive Magic Number = 
IPv4 DNS Magic Number = 
## IPv4 DNS Magic Number = qe47QHHw
IPv4 Alternate DNS Magic Number = 
## IPv4 Alternate DNS Magic Number = qe47QHHw
IPv6 DNS Magic Number = 
## IPv6 DNS Magic Number = qe47QHHw
IPv6 Alternate DNS Magic Number = 
## IPv6 Alternate DNS Magic Number = qe47QHHw


-------------------------------------------------------------------------------


Hosts 文件格式说明：

Hosts配置文件分为Base/基本区域、Hosts/主要Hosts列表 和 Local Hosts/境内DNS解析域名列表 三个区域
* 部分区域通过标签识别，修改时切勿将其删除
* 优先级：Local Hosts/境内DNS解析域名列表 > Hosts/主要Hosts列表，Whitelist/白名单条目 和 Banned/黑名单条目 的优先级由位置决定，参见下文详细说明
* 一条条目的总长度切勿超过4096字节/4KB
* 需要注释请在条目开头添加 #/井号
* 优先级别自上而下递减，条目越前优先级越高
* 平行 Hosts 条目支持数量由请求域名以及 EDNS0 Payload 长度决定，建议不要超过70个A记录或40个AAAA记录


* Base - 基本参数区域
  * Version - 配置文件的版本，用于正确识别 Hosts 文件：本参数与程序版本号不相关，切勿修改，默认为发布时的最新配置文件版本
  * Default TTL - Hosts 条目默认生存时间：单位为秒，留空则为900秒/15分钟，默认为空

* Whitelist - 白名单条目
  此类型的条目列出的符合要求的域名会直接绕过 Hosts，不会使用 Hosts 功能
  直接在条目前添加 "NULL"（不含引号）即可，有效参数格式为 "NULL 正则表达式"（不含引号）
  * 注意优先级的问题，例如有一片含白名单条目的区域：
    
	NULL .*\.test.localhost
	127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost
	
    虽然 .*\.localhost 包含了 .*\.test\.localhost 但由于优先级别自上而下递减，故先命中 .*\.test\.localhost 并返回使用远程服务器解析
	从而绕过了下面的条目，不使用Hosts的功能
	
* Banned - 黑名单条目
  此类型的条目列出的符合要求的域名会直接返回域名不存在的功能，避免重定向导致的超时问题
  直接在条目前添加 "Banned"（不含引号）即可，有效参数格式为 "Banned 正则表达式"（不含引号）
  * 注意优先级的问题，例如有一片含黑名单条目的区域：
    
	Banned .*\.test.localhost
	127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost
	
    虽然 .*\.localhost 包含了 .*\.test\.localhost 但由于优先级别自上而下递减，故先命中 .*\.test\.localhost 并直接返回域名不存在
	从而绕过了下面的条目，达到屏蔽域名的目的

* Hosts - 主要Hosts列表
  有效参数格式为 "地址(|地址A|地址B) 域名的正则表达式"（不含引号，括号内为可选项目，注意间隔所在的位置）
  * 地址与正则表达式之间的间隔字符可为Space/半角空格或者HT/水平定位符号，间隔长度不限，但切勿输入全角空格
  * 一条条目只能接受一种地址类型（IPv4/IPv6），如有同一个域名需要同时进行IPv4/IPv6的Hosts，请分为两个条目输入
  * 平行地址原理为一次返回多个记录，而具体使用哪个记录则由请求者决定，一般为第1个
  * 例如有一个 [Hosts] 下有效数据区域：

    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3	.*\.test\.localhost
    ::4|::5|::6	.*\.localhost

	虽然 .*\.localhost 包含了 .*\.test\.localhost 但由于优先级别自上而下递减，故先命中 .*\.test\.localhost 并直接返回，不会再进行其它检查
    * 请求解析 xxx.localhost 的A记录（IPv4）会返回 127.0.0.4、127.0.0.5和127.0.0.6
    * 请求解析 xxx.localhost 的AAAA记录（IPv6）会返回 ::4、::5和::6
    * 请求解析 xxx.test.localhost 的A记录（IPv4）会返回 127.0.0.1、127.0.0.2和127.0.0.3
    * 请求解析 xxx.test.localhost 的AAAA记录（IPv6）会返回 ::1、::2和::3

* Local Hosts - 境内DNS解析域名列表
  本区域数据用于为域名使用境内DNS服务器解析提高访问速度，使用时请确认境内DNS服务器地址不为空（参见上文 配置文件详细参数说明 一节）
  有效参数格式为 "域名的正则表达式"（不含引号）
  * 本功能不会对境内DNS服务器回复进行任何过滤，请确认本区域填入的数据不会受到DNS投毒污染的干扰
  * 例如有一个 [Local Hosts] 下有效数据区域：

    .*\.test\.localhost
    .*\.localhost

  * 即所有符合以上正则表达式的域名请求都将使用境内DNS服务器解析


* 默认的 Hosts 文件内容

## Example:
#
# (Anywhere)
# NULL localhost
# BANNED localhost
#
# [Hosts]
# 127.0.0.1 localhost
# ::1 localhost
# 
# [Local Hosts]
# localhost
#

[Base]
Version = *.*（视所使用的版本而定，参见 ChangeLog 文档）
Default TTL = 

[Hosts]


[Local Hosts]

