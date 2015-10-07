Pcap_DNSProxy 项目的 GitHub 页面：

* 主分支: https://github.com/chengr28/Pcap_DNSProxy
* Release 分支: https://github.com/chengr28/Pcap_DNSProxy/tree/Release

Pcap_DNSProxy 项目的 Sourceforge 页面：
https://sourceforge.net/projects/pcap-dnsproxy


-------------------------------------------------------------------------------


安装方法（需要以管理员身份进行）：

1.访问 http://www.winpcap.org/install/default.htm 下载并以管理员权限安装 WinPcap
  * WinPcap 只需要安装一次，以前安装过最新版本或以后更新本工具时请从第2步开始操作
  * 如果 WinPcap 提示已安装旧版本无法继续时，参见 FAQ 中 运行结果分析 一节
  * 安装时自启动选项对工具的运行没有影响，因为本工具直接调用 WinPcap API，不需要经过服务器程序
 
2.访问 https://github.com/chengr28/Pcap_DNSProxy/tree/Release 并使用 GitHub 的 Download ZIP 功能将所有文件下载到本地
  * Windows 版本的 Pcap_DNSProxy 在 ZIP 的 Windows 目录内，可将整个目录单独抽出运行

3.打开下载回来的 ZIP 文件，将 Windows 目录解压到磁盘的任意位置
  * 目录所在位置和程序文件名可以随意更改
  * 配置文件需要使用固定的文件名（更多详细情况参见下文 功能和技术 一节）

4.确定工具目录的名称和路径后进入目录内，右键以管理员身份(Vista 以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceControl.bat
  * 输入 1 并回车，即选择 "1: Install service" 安装服务
  * 批处理会将程序注册系统服务，并进行 Windows 防火墙测试，每次开机服务都将自动启动
  * 此时 Windows 系统会询问是否同意程序访问网络，请将 "专用网络" 以及 "公用网络" 都勾上并确认

5.打开 "网络和共享中心" - "更改适配器设置" 选择 "本地连接" 或 "无线连接" 或 "宽带连接"
  * 右击 "属性" - "Internet协议(TCP/IP)"(XP/2003) 或 "Internet协议版本4(IPv4)"(Vista 以及更新版本) - "属性" - 勾选 "使用下面的 DNS 服务器地址"
  * 在 "首选DNS服务器" 内填入 "127.0.0.1"（不含引号） 确定保存并退出即可
  * 如果需要使用 IPv6 协议的本地服务器
    * 右击 "属性" - "Internet协议版本6(IPv6)" - "属性" - 勾选 "使用下面的 DNS 服务器地址"
    * 在 "首选DNS服务器" 内填入 "::1"（不含引号） 确定保存并退出即可
  * 请务必确保只填入这两个地址，填入其它地址可能会导致系统选择其它 DNS 服务器绕过程序的代理
  * 注意：建议将 "本地连接" 和 "无线连接" 以及 "宽带连接" 全部修改！

6.特别注意：
  * 如需使用境内 DNS 服务器解析境内域名加速访问 CDN 速度功能，请选择其中一种方案，配置完成后重启服务：
    * Local Main = 1 同时 Local Routing = 1 开启境内地址路由表识别功能
    * Local Hosts = 1 开启境内域名白名单功能
  * 如需让程序的流量通过系统路由级别的代理（例如 VPN 等）进行域名解析，请选择其中一种方案，配置完成后重启服务：
    * Direct Request = IPv4
    * Direct Request = IPv6
    * Direct Request = IPv4 + IPv6


重启服务方法（需要以管理员身份进行）：
1.右键以管理员身份(Vista 以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceControl.bat
2.输入 5 并回车，即选择 "5: Restart service" 立刻重启服务


更新程序方法（需要以管理员身份进行）：
* 注意：更新程序切勿直接覆盖，否则可能会造成不可预料的错误！请按照以下的步骤进行：
1.提前下载好新版本的 Pcap_DNSProxy（亦即 安装方法 中第2步），更新过程可能会造成域名解析短暂中断
2.备份好所有配置文件 Hosts 文件 IPFilter 文件的自定义内容
3.右键以管理员身份(Vista 以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceControl.bat
4.输入 2 并回车，即选择 "2: Uninstall service" 卸载服务
5.将整个 Pcap_DNSProxy 程序的目录删除。注意 Windows 防火墙可能会留有允许程序访问网络的信息，卸载服务后又变更了程序的目录则可能需要使用注册表清理工具清理
6.将新版本的 Pcap_DNSProxy 解压到任何位置（亦即 安装方法 中第3步）
7.将配置文件的自定义内容加回新版本配置文件里相应的区域内
8.按照 安装方法 中第4步重新部署 Pcap_DNSProxy


安全模式下的使用方法（需要以管理员身份进行）：
* 程序具备在安全模式下运行的能力，在安全模式下右键以管理员身份直接运行程序
* 直接运行模式有控制台窗口，关闭程序时直接关闭控制台窗口即可

卸载方法（需要以管理员身份进行）：
1.按照 安装方法 中第6步还原 DNS 域名服务器地址配置
2.右键以管理员身份(Vista 以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceControl.bat
  * 输入 2 并回车，即选择 "2: Uninstall service" 卸载服务
  * 注意：Windows 防火墙可能会留有允许程序访问网络的信息，故卸载后可能需要使用注册表清理工具清理
  * 转移工具目录路径需要重新安装服务，先卸载服务转移，转移完成后重新安装服务即可


正常工作查看方法：
1.打开命令提示符
  * 在开始菜单或直接 Win + R 调出 运行 ，输入 cmd 并回车
  * 开始菜单 - 程序/所有程序 - 附件 - 命令提示符
2.输入 nslookup www.google.com 并回车
3.运行结果应类似：

   >nslookup www.google.com
    服务器:  pcap-dnsproxy.localhost.server（视配置文件设置的值而定，参见下文 配置文件详细参数说明 一节）
    Address:  127.0.0.1（视所在网络环境而定，本地监听协议为 IPv6 时为 ::1）

    非权威应答:
    名称:    www.google.com
    Addresses: ……（IP地址或地址列表）

4.如非以上结果，请移步 FAQ 文档中 运行结果分析 一节


-------------------------------------------------------------------------------


注意事项：

* 修改 DNS 服务器时请务必设置一个正确的、有效的、可以正常使用的境外 DNS 服务器！
* Windows 平台下读取文件名时不存在大小写的区别
* 配置文件 Hosts 文件 IPFilter 文件和错误报告所在的目录以上文 安装方法 一节中第4步注册的服务信息为准
  * 填写时一行不要超过 4096字节/4KB
  * 文件读取只支持整个文本单一的编码和换行格式组合，切勿在文本文件中混合所支持的编码或换行格式！
* 服务启动前请先确认没有其它本地 DNS 服务器运行或本工具多个拷贝运行中，否则可能会导致监听冲突无法正常工作
  * 监听冲突会生成错误报告，可留意 Windows Socket 相关的错误（参见 FAQ 文档中 Error.log 详细错误报告 一节）
* 杀毒软件/第三方防火墙可能会阻止本程序的操作，请将行为全部允许或将本程序加入到白名单中
* 如果启动服务时提示 "服务没有及时响应启动或者控制请求" 请留意是否有错误报告生成，详细的错误信息参见 FAQ 文档中 Error.log 详细错误报告 一节
* 目录和程序的名称可以随意更改，但请务必在进行安装方法第4步前完成。如果服务注册后需移动工具目录的路径，参见上文 卸载方法 第2步的注意事项
* 由于本人水平有限，程序编写难免会出现差错疏漏，如有问题可至项目页面提出，望谅解 v_v


-------------------------------------------------------------------------------


功能和技术：
* 批处理的作用：
  * 运行结束会有运行结果，具体是否成功需要留意屏幕上的提示
  * 1: Install service - 将程序注册为系统服务，并启动程序进行 Windows 防火墙测试
  * 2: Uninstall service - 停止并卸载工具的服务
  * 3: Start service - 启动工具的服务
  * 4: Stop service - 停止工具的服务
  * 5: Restart service - 重启工具的服务
  * 6: Flush DNS cache in Pcap_DNSProxy - 刷新程序的内部 DNS 缓存
* 配置文件支持的文件名（只会读取优先级较高者，优先级较低者将被直接忽略）：
  * Windows: Config.ini > Config.conf > Config.cfg > Config
  * Linux/Mac: Config.conf > Config.ini > Config.cfg > Config
* 请求域名解析优先级
  * 使用系统 API函数进行域名解析（大部分）：系统 Hosts > Pcap_DNSProxy 的 Hosts 条目（Whitelist/白名单条目 > Hosts/主要 Hosts 列表） > DNS 缓存 > Local Hosts/境内 DNS 解析域名列表 > 远程 DNS 服务器
  * 直接使用网络适配器设置进行域名解析（小部分）：Pcap_DNSProxy 的 Hosts 配置文件（Whitelist/白名单条目 > Hosts/主要 Hosts 列表） > DNS 缓存 > Local Hosts/境内 DNS 解析域名列表 > 远程 DNS 服务器
  * 请求远程 DNS 服务器的优先级：Direct Request 模式 > TCP 模式的 DNSCurve 加密/非加密模式（如有） > UDP 模式的 DNSCurve 加密/非加密模式（如有） > TCP 模式普通请求（如有） > UDP 模式普通请求
* 本工具的 DNSCurve/DNSCrypt 协议是内置的实现，不需要安装 DNSCrypt 官方的工具！
  * DNSCurve 协议为 Streamlined/精简类型
  * 自动获取连接信息时必须保证系统时间的正确，否则证书验证时会出错导致连接信息获取失败！
  * DNSCrypt 官方工具会占用本地 DNS 端口导致 Pcap_DNSProxy 部署失败！


-------------------------------------------------------------------------------


特别使用技巧：
这里罗列出部分作者建议的介绍和使用技巧，供大家参考和使用。关于调整配置，参见下文 配置文件详细参数说明 一节

* DNS 缓存类型
  * Timer/计时型：可以自定义缓存的时间长度，队列长度不限
  * Queue/队列型：默认缓存时间 15 分钟，可通过 Default TTL 值自定义，同时可自定义缓存队列长度（亦即限制队列长度的 Timer/计时型）
  * 强烈建议打开 DNS 缓存功能！
* 本工具配置选项丰富，配置不同的组合会有不同的效果，介绍几个比较常用的组合：
  * 默认配置：UDP 请求 + 抓包模式
  * Protocol = ...TCP：先 TCP 请求失败后再 UDP 请求 + 抓包模式，对网络资源的占用比较高
    * 由于 TCP 请求大部分时候不会被投毒污染，此组合的过滤效果比较可靠
  * EDNS Label = 1：开启 EDNS 请求标签功能
    * 此功能开启后将有利于对伪造数据包的过滤能力，此组合的过滤效果比较可靠
  * 将目标服务器的请求端口改为非标准 DNS 端口：例如 OpenDNS 支持 53 标准端口和 5353 非标准端口的请求
    * 非标准 DNS 端口现阶段尚未被干扰，此组合的过滤效果比较可靠
  * Multi Request Times = xx 时：应用到所有除请求境内服务器外的所有请求，一个请求多次发送功能
    * 此功能用于对抗网络丢包比较严重的情况，对系统和网络资源的占用都比较高，但在网络环境恶劣的情况下能提高获得解析结果的可靠性
  * DNSCurve = 1 同时 Encryption = 0：使用 DNSCurve/DNSCrypt 非加密模式请求域名解析
    * 此组合等于使用非标准 DNS 端口请求，域名解析可靠性比较高，详细情况参见上文
  * DNSCurve = 1 同时 Encryption = 1：使用 DNSCurve/DNSCrypt 加密模式请求域名解析
    * 此组合加密传输所有域名请求，域名解析可靠性最高
  * DNSCurve = 1 同时 Encryption = 1 同时 Encryption Only = 1：只使用 DNSCurve/DNSCrypt 加密模式请求域名解析
    * 上文的加密组合并不阻止程序在请求 DNSCurve/DNSCrypt 加密模式失败是使用其它协议请求域名解析，开启 Encryption Only = 1 后将只允许使用加密传输，安全性和可靠性最高，但域名解析成功率可能会下降


-------------------------------------------------------------------------------


配置文件详细参数说明：

有效参数格式为 "选项名称 = 数值/数据"（不含引号，注意空格和等号的位置）
注意：配置文件只会在工具服务开始时读取，修改本文件的参数后请重启服务（参见上文 注意事项 一节中的 重启服务）

* Base - 基本参数区域
  * Version - 配置文件的版本，用于正确识别配置文件：本参数与程序版本号不相关，切勿修改
  * File Refresh Time - 文件刷新间隔时间：单位为秒，最短间隔时间为 5 秒
  * Additional Path - 附加的数据文件读取路径，附加在此处的目录路径下的 Hosts 文件和 IPFilter 文件会被依次读取
  * Hosts File Name - Hosts 文件的文件名，附加在此处的 Hosts 文件名将被依次读取
  * IPFilter File Name - IPFilter 文件的文件名，附加在此处的 IPFilter 文件名将被依次读取

* Log - 日志参数区域
  * Print Error - 输出错误报告功能：开启为 1 /关闭为 0
  * Log Maximum Size - 日志文件最大容量：直接填数字时单位为字节，可加上单位，支持的单位有 KB/MB/GB，可接受范围为 4KB - 1GB，如果留空则为 8MB
    * 注意：日志文件到达最大容量后将被直接删除，然后重新生成新的日志文件，原来的日志将无法找回！

* Listen - 监听参数区域
  * Pcap Capture - 抓包功能总开关，开启后抓包模块才能正常使用：开启为 1 /关闭为 0
    * 此参数关闭后程序会自动切换为直连模式
    * 直连模式下不能完全避免 DNS 投毒污染的问题，需要依赖其它的检测方式，例如 EDNS 标签等方法
  * Pcap Devices Blacklist - 指定不对含有此名称的网络适配器进行抓包，名称或简介里含有此字符串的网络适配器将被直接忽略
    * 本参数支持指定多个名称，大小写不敏感，格式为 "网络适配器的名称(|网络适配器的名称)"（不含引号）
    * 以抓包模块从系统中获取的名称或简介为准，与其它网络配置程序所显示的不一定相同
  * Pcap Reading Timeout - 抓包模块读取超时时间，数据包只会在等待超时时间后才会被读取，其余时间抓包模块处于休眠状态：单位为毫秒，最短间隔时间为10毫秒
    * 读取超时时间需要平衡需求和资源占用，时间设置太长会导致域名解析请求响应缓慢导致请求解析超时，太快则会占用过多系统处理的资源
  * Listen Protocol - 监听协议，本地监听的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只监听指定协议的本地端口
    * 注意：此处的协议指的是向本程序请求域名解析时可使用的协议，而程序请求远程 DNS 服务器时所使用的协议由 Protocol 参数决定
  * Listen Port - 监听端口，本地监听请求的端口：格式为 "端口A(|端口B)"（不含引号，括号内为可选项目）
    * 端口可填入服务名称，服务名称列表参见下文
    * 也可填入 1-65535 之间的端口，如果留空则为 53
    * 填入多个端口时，程序将会同时监听请求
    * 当相应协议的 Listen Address 生效时，相应协议的本参数将会被自动忽略
  * Operation Mode - 程序的监听工作模式：分 Server/服务器模式、Private/私有网络模式、Proxy/代理模式 和 Custom/自定义模式
    * Server/服务器模式：打开 DNS 通用端口（TCP/UDP 同时打开），可为所有其它设备提供代理域名解析请求服务
    * Private/私有网络模式：打开 DNS 通用端口（TCP/UDP 同时打开），可为仅限于私有网络地址的设备提供代理域名解析请求服务
    * Proxy/代理模式：只打开回环地址的 DNS 端口（TCP/UDP 同时打开），只能为本机提供代理域名解析请求服务
    * Custom/自定义模式：打开 DNS 通用端口（TCP/UDP 同时打开），可用的地址由 IPFilter 参数决定
    * 当相应协议的 Listen Address 生效时，相应协议的本参数将会被自动忽略
  * IPFilter Type - IPFilter 参数的类型：分为 Deny 禁止和 Permit 允许，对应 IPFilter 参数应用为黑名单或白名单
  * IPFilter Level - IPFilter 参数的过滤级别，级别越高过滤越严格，与 IPFilter 条目相对应：0 为不启用过滤，如果留空则为 0
  * Accept Type - 禁止或只允许所列 DNS 类型的请求：格式为 "Deny:DNS记录的名称或ID(|DNS记录的名称或ID)" 或 "Permit:DNS记录的名称或ID(|DNS记录的名称或ID)"（不含引号，括号内为可选项目）
    * 所有可用的 DNS 类型列表：
      * A/1
      * NS/2
      * MD/3
      * MF/4
      * CNAME/5
      * SOA/6
      * MB/7
      * MG/8
      * MR/9
      * NULL/10
      * WKS/11
      * PTR/12
      * HINFO/13
      * MINFO/14
      * MX/15
      * TXT/16
      * RP/17
      * AFSDB/18
      * X25/19
      * ISDN/20
      * RT/21
      * NSAP/22
      * NSAP_PTR/23
      * SIG/24
      * KEY/25
      * PX/26
      * GPOS/27
      * AAAA/28
      * LOC/29
      * NXT/30
      * EID/31
      * NIMLOC/32
      * SRV/33
      * ATMA/34
      * NAPTR/35
      * KX/36
      * CERT/37
      * A6/38
      * DNAME/39
      * SINK/40
      * OPT/41
      * APL/42
      * DS/43
      * SSHFP/44
      * IPSECKEY/45
      * RRSIG/46
      * NSEC/47
      * DNSKEY/48
      * DHCID/49
      * NSEC3/50
      * NSEC3PARAM/51
      * TLSA/52
      * HIP/55
      * NINFO/56
      * RKEY/57
      * TALINK/58
      * CDS/59
      * CDNSKEY/60
      * OPENPGPKEY/61
      * SPF/99
      * UINFO/100
      * UID/101
      * GID/102
      * UNSPEC/103
      * NID/104
      * L32/105
      * L64/106
      * LP/107
      * EUI48/108
      * EUI64/109
      * TKEY/249
      * TSIG/250
      * IXFR/251
      * AXFR/252
      * MAILB/253
      * MAILA/254
      * ANY/255
      * URI/256
      * CAA/257
      * TA/32768
      * DLV/32769
      * RESERVED/65535
      
* DNS - 域名解析参数区域
  * Protocol - 发送请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向远程 DNS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 TCP 因为 UDP 为 DNS 的标准网络层协议，所以即使填入 TCP 失败时也会使用 UDP 请求
  * Direct Request - 直连模式，启用后将使用系统的 API 直接请求远程服务器而启用只使用本工具的 Hosts 功能：可填入 IPv4 和 IPv6 和 0，关闭为 0
    * 建议当系统使用全局代理功能时启用，程序将除境内服务器外的所有请求直接交给系统而不作任何过滤等处理，系统会将请求自动发往远程服务器进行解析
    * 填入 IPv4 或 IPv6 时将会启用对应协议的 Direct Request 功能，填入 IPv4 + IPv6 将会启用所有协议的功能
  * Cache Type - DNS 缓存的类型：分 Timer/计时型以及 Queue/队列型
  * Cache Parameter - DNS 缓存的参数：Timer/计时型 时为时间长度（单位为秒），Queue/队列型 时为队列长度
  * Default TTL - Hosts 条目默认生存时间：单位为秒，留空则为 900秒/15分钟
  
* Local DNS - 境内域名解析参数区域
  * Local Protocol - 发送境内请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向境内 DNS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 TCP 因为 UDP 为 DNS 的标准网络层协议，所以即使填入 TCP 失败时也会使用 UDP 请求
  * Local Hosts - 白名单境内服务器请求功能：开启为 1 /关闭为 0
    * 开启后才能使用自带或自定义的 Local Hosts 白名单，且不能与 Local Hosts 和 Local Routing 同时启用
  * Local Main - 主要境内服务器请求功能：开启为 1 /关闭为 0
    * 开启后所有请求先使用 Local 的服务器进行解析，遇到遭投毒污染的解析结果时自动再向境外服务器请求
    * 本功能不能与 Local Hosts 同时启用
  * Local Routing - Local 路由表识别功能：开启为 1 /关闭为 0
    * 开启后使用 Local 请求的解析结果都会被检查，路由表命中会直接返回结果，命中失败将丢弃解析结果并向境外服务器再次发起请求
    * 本功能只能在 Local Main 为启用状态时才能启用
    
* Addresses - 普通模式地址区域
  * IPv4 Listen Address - IPv4 本地监听地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 填入此值后 IPv4 协议的 Operation Mode 和 Listen Port 参数将被自动忽略
  * IPv4 EDNS Client Subnet Address - IPv4 客户端子网地址：需要输入一个带前缀长度的本机公共网络地址，留空为不启用
    * 启用本功能前需要启用 EDNS Client Subnet 总开关，否则将直接忽略此参数
  * IPv4 DNS Address - IPv4 主要 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 支持使用服务名称代替端口号
  * IPv4 Alternate DNS Address - IPv4 备用 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 支持使用服务名称代替端口号
  * IPv4 Local DNS Address - IPv4 主要境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * IPv4 Local Alternate DNS Address - IPv4 备用境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * IPv6 Listen Address - IPv6 本地监听地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 填入此值后 IPv6 协议的 Operation Mode 和 Listen Port 参数将被自动忽略
  * IPv6 EDNS Client Subnet Address - IPv6 客户端子网地址：需要输入一个带前缀长度的本机公共网络地址，留空为不启用
    * 启用本功能前需要启用 EDNS Client Subnet 总开关，否则将直接忽略此参数
  * IPv6 DNS Address - IPv6 主要 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 支持使用服务名称代替端口号
  * IPv6 Alternate DNS Address - IPv6 备用 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 支持使用服务名称代替端口号
  * IPv6 Local DNS Address - IPv6 主要境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * IPv6 Local Alternate DNS Address - IPv6 备用境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * 注意：
    * 单个 IPv4 地址格式为 "IPv4 地址:端口"，单个 IPv6 地址格式为"[IPv6 地址]:端口"，带前缀长度地址格式为 "IP 地址/网络前缀长度"（均不含引号）
    * 多个 IPv4 地址格式为 "地址A:端口|地址B:端口|地址C:端口"，多个 IPv6 地址格式为 "[地址A]:端口|[地址B]:端口|[地址C]:端口"（均不含引号），启用同时请求多服务器后将同时向列表中的服务器请求解析域名，并采用最快回应的服务器的结果，同时请求多服务器启用后将自动启用 Alternate Multi Request 参数（参见下文）
    * 可填入的服务器数量为：填入主要/备用服务器的数量 * Multi Request Times = 总请求的数值，此数值不能超过 64
	* 指定端口时可使用服务名称代替：
      * TCPMUX/1
      * ECHO/7
      * DISCARD/9
      * SYSTAT/11
      * DAYTIME/13
      * NETSTAT/15
      * QOTD/17
      * MSP/18
      * CHARGEN/19
      * FTP_DATA/20
      * FTP_DATA/21
      * SSH/22
      * TELNET/23
      * SMTP/25
      * TIMESERVER/37
      * RAP/38
      * RLP/39
      * NAMESERVER/42
      * WHOIS/43
      * TACACS/49
      * DNS/53
      * XNSAUTH/56
      * MTP/57
      * BOOTPS/67
      * BOOTPC/68
      * TFTP/69
      * RJE/77
      * FINGER/79
      * TTYLINK/87
      * SUPDUP/95
      * SUNRPC/111
      * SQL/118
      * NTP/123
      * EPMAP/135
      * NETBIOS_NS/137
      * NETBIOS_DGM/138
      * NETBIOS_SSN/139
      * IMAP/143
      * BFTP/152
      * SGMP/153
      * SQLSRV/156
      * DMSP/158
      * SNMP/161
      * SNMP_TRAP/162
      * ATRTMP/201
      * ATHBP/202
      * QMTP/209
      * IPX/213
      * IMAP3/220
      * BGMP/246
      * TSP/318
      * IMMP/323
      * ODMR/366
      * RPC2PORTMAP/369
      * CLEARCASE/371
      * HPALARMMGR/383
      * ARNS/384
      * AURP/387
      * LDAP/389
      * UPS/401
      * SLP/427
      * HTTPS/443
      * SNPP/444
      * MICROSOFTDS/445
      * KPASSWD/464
      * TCPNETHASPSRV/475
      * RETROSPECT/497
      * ISAKMP/500
      * BIFFUDP/512
      * WHOSERVER/513
      * SYSLOG/514
      * ROUTERSERVER/520
      * NCP/524
      * COURIER/530
      * COMMERCE/542
      * RTSP/554
      * NNTP/563
      * HTTPRPCEPMAP/593
      * IPP/631
      * LDAPS/636
      * MSDP/639
      * AODV/654
      * FTPSDATA/989
      * FTPS/990
      * NAS/991
      * TELNETS/992

* Values - 扩展参数值区域
  * Buffer Queue Limits - 数据缓冲区队列数量限制：单位为个，最小为 8 最大为 1488095
    * 启用 Queue Limits Reset Time 参数时，此参数为单位时间内最多可接受请求的数量
    * 不启用 Queue Limits Reset Time 参数时为用于接收数据的缓冲区的数量，由于内存数据的复制比网络 I/O 快超过一个数量级，故此情况下不需要设置太多缓冲区
  * Queue Limits Reset Time - 数据缓冲区队列数量限制重置时间：单位为秒，设置为 0 时关闭此功能
  * EDNS Payload Size - EDNS 标签附带使用的最大载荷长度：最小为 DNS 协议实现要求的 512(bytes)，留空则使用 EDNS 标签要求最短的 1220(bytes)
  * IPv4 TTL - IPv4 主要 DNS 服务器接受请求的远程 DNS 服务器数据包的 TTL 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 TTL 值，与 IPv4 DNS Address 相对应
  * IPv4 Alternate TTL - IPv4 备用 DNS 服务器接受请求的远程 DNS 服务器数据包的 TTL 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 TTL 值，与 IPv4 Alternate DNS Address 相对应
  * IPv6 Hop Limits - IPv6 主要 DNS 服务器接受请求的远程 DNS 服务器数据包的 Hop Limits 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 Hop Limits 值，与 IPv6 DNS Address 相对应
  * IPv6 Alternate Hop Limits - IPv6 备用 DNS 服务器接受请求的远程 DNS 服务器数据包的 Hop Limits 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 Hop Limits 值，与 IPv6 Alternate DNS Address 相对应
  * Hop Limits Fluctuation - IPv4 TTL/IPv6 Hop Limits 可接受范围，即 IPv4 TTL/IPv6 Hop Limits 的值 ± 数值的范围内的数据包均可被接受，用于避免网络环境短暂变化造成解析失败的问题：取值为 1-255 之间
  * Reliable Socket Timeout - 可靠协议端口超时时间，可靠端口指 TCP 协议：最小为 500，可留空，留空时为 3000，单位为毫秒
  * Unreliable Socket Timeout - 不可靠协议端口超时时间，不可靠端口指 UDP/ICMP/ICMPv6 协议：最小为 500，可留空，留空时为 2000，单位为毫秒
  * Receive Waiting - 数据包接收等待时间，启用后程序会尝试等待一段时间以尝试接收所有数据包并返回最后到达的数据包：单位为毫秒，留空或填 0 表示关闭此功能
    * 本参数与 Pcap Reading Timeout 密切相关，由于抓包模块每隔一段读取超时时间才会返回给程序一次，当数据包接收等待时间小于读取超时时间时会导致本参数变得没有意义，在一些情况下甚至会拖慢域名解析的响应速度
    * 本参数启用后虽然本身只决定抓包模块的接收等待时间，但同时会影响到非抓包模块的请求。非抓包模块会自动切换为等待超时时间后发回最后收到的回复，默认为接受最先到达的正确的回复，而它们的超时时间由 Reliable Socket Timeout/Unreliable Socket Timeout 参数决定
    * 一般情况下，越靠后所收到的数据包，其可靠性可能会更高
  * ICMP Test - ICMP/Ping 测试间隔时间：单位为秒，最短间隔时间为5秒
  * Domain Test - DNS 服务器解析域名测试间隔时间：单位为秒，最短间隔时间为5秒
  * Alternate Times - 备用服务器失败次数阈值，一定周期内如超出阈值会触发服务器切换
  * Alternate Time Range - 备用服务器失败次数阈值计算周期：单位为秒
  * Alternate Reset Time - 备用服务器重置切换时间，切换产生后经过此事件会切换回主要服务器：单位为秒
  * Multi Request Times - 一次向同一个远程服务器发送并行域名解析请求：0 和 1 时为收到一个请求时请求 1 次，2 时为收到一个请求时请求 2 次，3 时为收到一个请求时请求 3 次……以此类推
    * 此值将应用到 Local Hosts 外对所有远程服务器所有协议的请求，因此可能会对系统以及远程服务器造成压力，请谨慎考虑开启的风险！
    * 可填入的最大数值为：填入主要/备用服务器的数量 * Multi Request Times = 总请求的数值，此数值不能超过 64
    * 一般除非丢包非常严重干扰正常使用否则不建议开启，开启也不建议将值设得太大。实际使用可以每次+1后重启服务测试效果，找到最合适的值
  * 注意：
    * IPv4 协议使用多 TTL 值的格式为 "TTL(A)|TTL(B)|TTL(C)"（不含引号），也可直接默认（即只填一个 0 不使用此格式）则所有 TTL 都将由程序自动获取
    * 使用同时请求多服务器格式为 "Hop Limits(A)|Hop Limits(B)|Hop Limits(C)"（不含引号），也可直接默认（即只填一个 0 不使用此格式）则所有 Hop Limits 都将由程序自动获取
    * 使用多 TTL/Hop Limits 值所对应的顺序与对应地址参数中的地址顺序相同

* Switches - 控制开关区域
  * TCP Fast Open - TCP 快速打开功能：开启为 1 /关闭为 0
    * 目前本功能只支持 Linux 平台，非 Linux 平台将直接忽略此参数，其中：
      * IPv4 需要 3.7 以及更新版本的内核支持
      * IPv6 需要 3.16 以及更新版本的内核支持
      * 切勿在不受支持的内核版本上开启本功能，否则可能导致程序无法正常收发数据包！
    * 开启系统对本功能的支持：
      * 临时支持：需要在拥有 ROOT 权限的终端执行 echo 3 > /proc/sys/net/ipv4/tcp_fastopen
      * 长期支持：
        * 在 /etc/rc.local 文件最下面添加 echo 3 > /proc/sys/net/ipv4/tcp_fastopen 保存，以后每次启动都将自动设置此值
        * 在 /etc/sysctl.conf 文件中添加 net.ipv4.tcp_fastopen = 3 保存
  * Domain Case Conversion - 随机转换域名请求大小写：开启为 1 /关闭为 0
  * Compression Pointer Mutation - 随机添加压缩指针：可填入 1 (+ 2 + 3)，关闭为 0
    * 随机添加压缩指针有3种不同的类型，对应 1 和 2 和 3
    * 可单独使用其中一个，即只填一个数字，或填入多个，中间使用 + 号连接
    * 填入多个时，当实际需要使用随机添加压缩指针时将随机使用其中的一种，每个请求都有可能不相同
  * EDNS Label - EDNS 标签支持，开启后将为所有请求添加 EDNS 标签：开启为 1 /关闭为 0
  * EDNS Client Subnet - EDNS 客户端子网支持，开启后将为所有请求添加 EDNS 客户端子网信息：开启为 1 /关闭为 0
    * 本功能要求启用 EDNS Label 参数
  * DNSSEC Request - DNSSEC 请求，开启后将尝试为所有请求添加 DNSSEC 请求：开启为 1 /关闭为 0
    * 本功能要求启用 EDNS Label 参数
    * 此功能不具备任何验证 DNSSEC 记录的能力，单独开启理论上并不能避免 DNS 投毒污染的问题
  * DNSSEC Validation - DNSSEC 记录验证功能，将检查所有带有 DNSSEC 记录的域名解析，验证失败将被丢弃：开启为 1 /关闭为 0
    * 本功能要求启用 EDNS Label 和 DNSSEC Request 参数
    * 此功能不具备完整的 DNSSEC 记录检验的能力，单独开启理论上不能避免 DNS 投毒污染的问题
    * 本功能不检查不存在 DNSSEC 记录的域名解析
  * DNSSEC Force Validation - 强制 DNSSEC 记录验证功能，将丢弃所有没有 DNSSEC 记录的域名解析：开启为 1 /关闭为 0
    * 本功能要求启用 EDNS Label、DNSSEC Request 和 DNSSEC Validation 参数
    * 此功能不具备完整的 DNSSEC 记录检验的能力，单独开启理论上不能避免 DNS 投毒污染的问题
    * 警告：由于现时已经部署 DNSSEC 的域名数量极少，未部署 DNSSEC 的域名解析没有 DNSSEC 记录，这将导致所有未部署 DNSSEC 的域名解析失败，现阶段切勿开启本功能！
  * Alternate Multi Request - 备用服务器同时请求参数，开启后将同时请求主要服务器和备用服务器并采用最快回应的服务器的结果：开启为 1 /关闭为 0
    * 同时请求多服务器启用后本参数将强制启用，将同时请求所有存在于列表中的服务器，并采用最快回应的服务器的结果
  * IPv4 Data Filter - IPv4 数据包头检测：开启为 1 /关闭为 0
  * TCP Data Filter - TCP 数据包头检测：开启为 1 /关闭为 0
  * DNS Data Filter - DNS 数据包头检测：开启为 1 /关闭为 0
  * Blacklist Filter - 解析结果黑名单过滤：开启为 1 /关闭为 0
  
* Data - 数据区域
  * ICMP ID - ICMP/Ping 数据包头部 ID 的值：格式为 0x**** 的十六进制字符，如果留空则获取线程的 ID 作为请求用 ID
  * ICMP Sequence - ICMP/Ping 数据包头部 Sequence/序列号 的值：格式为 0x**** 的十六进制字符，如果留空则为 0x0001
  * Domain Test Data - DNS 服务器解析域名测试：请输入正确、确认不会被投毒污染的域名并且不要超过 253 字节 ASCII 数据，留空则会随机生成一个域名进行测试
  * Domain Test ID - DNS 数据包头部 ID 的值：格式为 0x**** 的十六进制字符，如果留空则为 0x0001
  * ICMP PaddingData - ICMP 附加数据，Ping 程序发送请求时为补足数据使其达到 Ethernet 类型网络最低的可发送长度时添加的数据：长度介乎于 18字节 - 1500字节 ASCII 数据之间，留空则使用 Microsoft Windows Ping 程序的 ICMP 附加数据
  * Localhost Server Name - 本地 DNS 服务器名称：请输入正确的域名并且不要超过253字节 ASCII 数据，留空则使用 pcap-dnsproxy.localhost.server 作为本地服务器名称

* Proxy - 代理区域
  * SOCKS Proxy - SOCKS 协议总开关，控制所有和 SOCKS 协议有关的选项：开启为 1 /关闭为 0
  * SOCKS Version - SOCKS 协议所使用的版本：可填入 4 或 4A 或 5
    * SOCKS 版本 4 不支持 IPv6 地址以及域名的目标服务器，以及不支持 UDP 转发功能
    * SOCKS 版本 4a 不支持 IPv6 地址的目标服务器，以及不支持 UDP 转发功能
  * SOCKS Protocol - 发送 SOCKS 协议请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向 SOCKS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 UDP 因为 TCP 为 SOCKS 最先支持以及最普遍支持的标准网络层协议，所以即使填入 UDP 请求失败时也会使用 TCP 请求
  * SOCKS Reliable Socket Timeout - 可靠 SOCKS 协议端口超时时间，可靠端口指 TCP 协议：最小为 500，可留空，留空时为 6000，单位为毫秒
  * SOCKS Unreliable Socket Timeout - 不可靠 SOCKS 协议端口超时时间，不可靠端口指 UDP 协议：最小为 500，可留空，留空时为 3000，单位为毫秒
  * SOCKS UDP No Handshake - SOCKS UDP 不握手模式，开启后将不进行 TCP 握手直接发送 UDP 转发请求：开启为 1 /关闭为 0
    * SOCKS 协议的标准流程使用 UDP 转发功能前必须使用 TCP 连接交换握手信息，否则 SOCKS 服务器将直接丢弃转发请求
    * 部分 SOCKS 本地代理可以直接进行 UDP 转发而不需要使用 TCP 连接交换握手信息，启用前请务必确认 SOCKS 服务器的支持情况
  * SOCKS Proxy Only - 只使用 SOCKS 协议代理模式：开启为 1 /关闭为 0
  * SOCKS IPv4 Address - SOCKS 协议 IPv4 主要 SOCKS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * SOCKS IPv6 Address - SOCKS 协议 IPv6 主要 SOCKS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * SOCKS Target Server - SOCKS 最终目标服务器：需要输入一个带端口格式的 IPv4/IPv6 地址或域名
    * 不支持多个地址或域名，只能填入单个地址或域名
    * 支持使用服务名称代替端口号
  * SOCKS Username - 连接 SOCKS 服务器时所使用的用户名：最长可填入 255 个字符，留空为不启用
  * SOCKS Password - 连接 SOCKS 服务器时所使用的密码：最长可填入 255 个字符，留空为不启用

* DNSCurve - DNSCurve 协议基本参数区域
  * DNSCurve - DNSCurve 协议总开关，控制所有和 DNSCurve 协议有关的选项：开启为 1 /关闭为 0
  * DNSCurve Protocol - DNSCurve 发送请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向远程 DNS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 TCP 因为 UDP 为 DNS 的标准网络层协议，所以即使填入 TCP 失败时也会使用 UDP 请求
  * DNSCurve Payload Size - DNSCurve EDNS 标签附带使用的最大载荷长度，同时亦为发送请求的总长度，并决定请求的填充长度：最小为 DNS 协议实现要求的 512(bytes)，留空则为 512(bytes)
  * DNSCurve Reliable Socket Timeout - 可靠 SOCKS 协议端口超时时间，可靠端口指 TCP 协议：最小为 500，可留空，留空时为 3000，单位为毫秒
  * DNSCurve Unreliable Socket Timeout - 不可靠 SOCKS 协议端口超时时间，不可靠端口指 UDP 协议：最小为 500，可留空，留空时为 2000，单位为毫秒
  * Encryption - 启用加密，DNSCurve 协议支持加密和非加密模式：开启为 1 /关闭为 0
  * Encryption Only - 只使用加密模式：开启为 1 /关闭为 0
    * 注意：使用 "只使用加密模式" 时必须提供服务器的魔数和指纹用于请求和接收
  * Client Ephemeral Key - 一次性客户端密钥对模式：每次请求解析均使用随机生成的一次性客户端密钥对：开启为 1 /关闭为 0
  * Key Recheck Time - DNSCurve 协议 DNS 服务器连接信息检查间隔：单位为秒，最短为 10 秒

* DNSCurve Addresses - DNSCurve 协议地址区域
  * DNSCurve IPv4 DNS Address - DNSCurve 协议 IPv4 主要 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv4 Alternate DNS Address - DNSCurve 协议 IPv4 备用 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv6 DNS Address - DNSCurve 协议 IPv6 主要 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv6 Alternate DNS Address - DNSCurve 协议 IPv6 备用 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv4 Provider Name - DNSCurve 协议 IPv4 主要 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * DNSCurve IPv4 Alternate Provider Name - DNSCurve 协议 IPv4 备用 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * DNSCurve IPv6 Provider Name - DNSCurve 协议 IPv6 主要 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * DNSCurve IPv6 Alternate Provider Name - DNSCurve 协议 IPv6 备用 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * 注意：
    * 自动获取 DNSCurve 服务器连接信息时必须输入提供者的域名，不能留空
    * 更多支持 DNSCurve/DNSCrypt 的服务器请移步 https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv

* DNSCurve Keys - DNSCurve 协议密钥区域
  * Client Public Key - 自定义客户端公钥：可使用 KeyPairGenerator 生成，留空则每次启动时自动生成
  * Client Secret Key - 自定义客户端私钥：可使用 KeyPairGenerator 生成，留空则每次启动时自动生成
  * IPv4 DNS Public Key - DNSCurve 协议 IPv4 主要 DNS 服务器验证用公钥
  * IPv4 Alternate DNS Public Key - DNSCurve 协议 IPv4 备用 DNS 服务器验证用公钥
  * IPv6 DNS Public Key - DNSCurve 协议 IPv6 主要 DNS 服务器验证用公钥
  * IPv6 Alternate DNS Public Key - DNSCurve 协议 IPv6 备用 DNS 服务器验证用公钥
  * IPv4 DNS Fingerprint - DNSCurve 协议 IPv4 主要 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * IPv4 Alternate DNS Fingerprint - DNSCurve 协议 IPv4 备用 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * IPv6 DNS Fingerprint - DNSCurve 协议 IPv6 备用 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * IPv6 Alternate DNS Fingerprint - DNSCurve 协议 IPv6 备用 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * 注意：
    * 公开网站上的 "公钥" 普遍为验证用的公钥，用于验证与服务器通讯时使用的指纹，两者为不同性质的公钥不可混用！
  
* DNSCurve Magic Number - DNSCurve 协议魔数区域
  * IPv4 Receive Magic Number - DNSCurve 协议 IPv4 主要 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * IPv4 Alternate Receive Magic Number - DNSCurve 协议 IPv4 备用 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * IPv6 Receive Magic Number - DNSCurve 协议 IPv6 主要 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * IPv6 Alternate Receive Magic Number - DNSCurve 协议 IPv6 备用 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * IPv4 DNS Magic Number - DNSCurve 协议 IPv4 主要 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * IPv4 Alternate DNS Magic Number - DNSCurve 协议 IPv4 备用 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * IPv6 DNS Magic Number - 协议 IPv6 主要 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * IPv6 Alternate DNS Magic Number - DNSCurve 协议 IPv6 备用 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * 注意：Magic Number 参数均同时支持使用 ASCII 字符或十六进制字符串进行指定
    * 直接填入可打印 ASCII 字符串即可
    * 十六进制字符串需要在字符串前面加上 0x（大小写敏感）


-------------------------------------------------------------------------------


配置文件自动刷新支持参数列表：

* 以下列表中的参数在写入配置文件后会自动刷新而无须重新启动程序，其它参数的刷新则必须重新启动程序
* 如非必要建议不要依赖程序的自动刷新功能，强烈建议修改配置文件后重新启动程序！

* Version
* File Refresh Time
* Print Error
* Log Maximum Size
* IPFilter Type
* IPFilter Level
* Accept Type
* Direct Request
* Default TTL
* Local Protocol
* IPv4 TTL
* IPv6 HopLimits
* IPv4 AlternateTTL
* IPv6 AlternateHopLimits
* HopLimits Fluctuation
* Reliable Socket Timeout
* Unreliable Socket Timeout
* Receive Waiting
* ICMP Test
* Domain Test
* Multi Request Times
* Domain Case Conversion
* IPv4 Data Filter
* TCP Data Filter
* DNS Data Filter
* SOCKS Reliable Socket Timeout
* SOCKS Unreliable Socket Timeout
* SOCKS Target Server
* SOCKS Username
* SOCKS Password
* DNSCurve Reliable Socket Timeout
* DNSCurve Unreliable Socket Timeout
* Key Recheck Time
* Client Public Key
* Client Secret Key
* IPv4 DNS Public Key
* IPv4 Alternate DNS Public Key
* IPv6 DNS Public Key
* IPv6 Alternate DNS Public Key
* IPv4 DNS Fingerprint
* IPv4 Alternate DNS Fingerprint
* IPv6 DNS Fingerprint
* IPv6 Alternate DNS Fingerprint
* IPv4 Receive Magic Number
* IPv4 Alternate Receive Magic Number
* IPv6 Receive Magic Number
* IPv6 Alternate Receive Magic Number
* IPv4 DNS Magic Number
* IPv4 Alternate DNS Magic Number
* IPv6 DNS Magic Number
* IPv6 Alternate DNS Magic Number


-------------------------------------------------------------------------------


Hosts 文件格式说明：

Hosts 配置文件分为多个提供不同功能的区域
* 区域通过标签识别，修改时切勿将其删除
* 优先级：Local Hosts/境内DNS解析域名列表 > Hosts/主要Hosts列表，Whitelist/白名单条目 和 Banned/黑名单条目 的优先级由位置决定，参见下文详细说明
* 一条条目的总长度切勿超过 4096字节/4KB
* 需要注释请在条目开头添加 #/井号
* 优先级别自上而下递减，条目越前优先级越高
* 平行 Hosts 条目支持数量由请求域名以及 EDNS Payload 长度决定，建议不要超过75个 A 记录或43个 AAAA 记录


* Whitelist - 白名单条目
  * 此类型的条目列出的符合要求的域名会直接绕过 Hosts 不会使用 Hosts 功能
  * 有效参数格式为 "NULL 正则表达式"（不含引号）
  * 注意优先级的问题，例如有一片含白名单条目的区域：

    NULL .*\.test.localhost
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost

  * 虽然 .*\.localhost 包含了 .*\.test\.localhost 但由于优先级别自上而下递减，故先命中 .*\.test\.localhost 并返回使用远程服务器解析
  * 从而绕过了下面的条目，不使用 Hosts 的功能

* Whitelist Extended - 白名单条目扩展功能
  * 此类型的条目还支持对符合规则的特定类型域名请求直接绕过 Hosts 不会使用 Hosts 功能
  * 有效参数格式为 "NULL:DNS类型(|DNS类型) 正则表达式"（不含引号）
  * 只允许特定类型域名请求，有效参数格式为 "NULL(Permit):DNS类型(|DNS类型) 正则表达式"（不含引号）

    NULL:A|AAAA .*\.test.localhost
    NULL(Deny):NS|SOA .*\.localhost

  * 第一条即直接跳过匹配规则的 A 记录和 AAAA 记录的域名请求，其它类型的请求则被匹配规则
  * 而第二条则只匹配规则的 NS 记录和 SOA 记录的域名请求，其它类型的请求则被直接跳过

* Banned - 黑名单条目
  * 此类型的条目列出的符合要求的域名会直接返回域名不存在的功能，避免重定向导致的超时问题
  * 有效参数格式为 "BANNED 正则表达式"（不含引号）
  * 注意优先级的问题，例如有一片含黑名单条目的区域：

    BANNED .*\.test.localhost
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost

  * 虽然 .*\.localhost 包含了 .*\.test\.localhost 但由于优先级别自上而下递减，故先命中 .*\.test\.localhost 并直接返回域名不存在
  * 从而绕过了下面的条目，达到屏蔽域名的目的
  
* Banned Extended - 黑名单条目扩展功能
  * 此类型的条目还支持对符合规则的特定类型域名请求进行屏蔽或放行
  * 有效参数格式为 "BANNED:DNS类型(|DNS类型) 正则表达式"（不含引号）
  * 只允许特定类型域名请求，有效参数格式为 "BANNED(Permit):DNS类型(|DNS类型) 正则表达式"（不含引号）

    BANNED:A|AAAA .*\.test.localhost
    BANNED(Permit):NS|SOA .*\.localhost

  * 第一条即屏蔽匹配规则的 A 记录和 AAAA 记录的域名请求，其它类型的请求则被放行
  * 而第二条则只放行匹配规则的 NS 记录和 SOA 记录的域名请求，其它类型的请求则被屏蔽

* Hosts - 主要 Hosts 列表
有效参数格式为 "地址(|地址A|地址B) 域名的正则表达式"（不含引号，括号内为可选项目，注意间隔所在的位置）
  * 地址与正则表达式之间的间隔字符可为 Space/半角空格 或者 HT/水平定位符号，间隔长度不限，但切勿输入全角空格
  * 一条条目只能接受一种地址类型（IPv4/IPv6），如有同一个域名需要同时进行 IPv4/IPv6 的Hosts，请分为两个条目输入
  * 平行地址原理为一次返回多个记录，而具体使用哪个记录则由请求者决定，一般为第1个
  * 例如有一个 [Hosts] 下有效数据区域：

    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3 .*\.test\.localhost
    ::4|::5|::6 .*\.localhost

  * 虽然 .*\.localhost 包含了 .*\.test\.localhost 但由于优先级别自上而下递减，故先命中 .*\.test\.localhost 并直接返回，不会再进行其它检查
    * 请求解析 xxx.localhost 的 A 记录（IPv4）会返回 127.0.0.4、127.0.0.5 和 127.0.0.6
    * 请求解析 xxx.localhost 的 AAAA 记录（IPv6）会返回 ::4、::5 和 ::6
    * 请求解析 xxx.test.localhost 的 A 记录（IPv4）会返回 127.0.0.1、127.0.0.2 和 127.0.0.3
    * 请求解析 xxx.test.localhost 的 AAAA 记录（IPv6）会返回 ::1、::2 和 ::3

* Local Hosts - 境内 DNS 解析域名列表
本区域数据用于为域名使用境内 DNS 服务器解析提高访问速度，使用时请确认境内 DNS 服务器地址不为空（参见上文 配置文件详细参数说明 一节）
有效参数格式为 "正则表达式"（不含引号）
  * 要使用本功能，必须将配置文件内的 Local Hosts 选项打开！
  * 本功能不会对境内 DNS 服务器回复进行任何过滤，请确认本区域填入的数据不会受到 DNS 投毒污染的干扰
  * 例如有一个 [Local Hosts] 下有效数据区域：

    .*\.test\.localhost
    .*\.localhost

  * 即所有符合以上正则表达式的域名请求都将使用境内 DNS 服务器解析
  
* Address Hosts - 解析结果地址替换列表
  * 本区域数据用于替换解析结果中的地址，提供更精确的 Hosts 自定义能力
  * 例如有一个 [Address Hosts] 下有效数据区域：

    127.0.0.1|127.0.0.2 127.0.0.0-127.255.255.255
    ::1 ::-::FFFF

  * 解析结果的地址范围为 127.0.0.0 到 127.255.255.255 时将被替换为 127.0.0.1 或 127.0.0.2
  * 解析结果的地址范围为 :: 到 ::FFFF 时将被替换为 ::1

* Stop - 临时停止读取标签
  * 在需要停止读取的数据前添加 "[Stop]"（不含引号） 标签即可在中途停止对文件的读取，直到有其它标签时再重新开始读取
  * 例如有一片数据区域：

    [Hosts]
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    [Stop]
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3 .*\.test\.localhost
    ::4|::5|::6 .*\.localhost

    [Local Hosts]
    .*\.test\.localhost
    .*\.localhost

  * 则从 [Stop] 一行开始，下面到 [Local Hosts] 之间的数据都将不会被读取
  * 即实际有效的数据区域是：

    [Hosts]
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost

    [Local Hosts]
    .*\.test\.localhost
    .*\.localhost


-------------------------------------------------------------------------------


IPFilter 文件格式说明：

IPFilter 配置文件分为 Blacklist/黑名单区域 和 IPFilter/地址过滤区域 以及 Local Routing/境内路由表区域
* 区域通过标签识别，修改时切勿将其删除
* 一条条目的总长度切勿超过4096字节/4KB
* 需要注释请在条目开头添加 #/井号


* Blacklist - 黑名单区域
当 Blacklist Filter 为开启时，将检查本列表域名与解析结果，如果解析结果里含有与域名对应的黑名单地址，则会直接丢弃此解析结果
有效参数格式为 "地址(|地址A|地址B) 正则表达式"（不含引号，括号内为可选项目，注意间隔所在的位置）
  * 地址与正则表达式之间的间隔字符可为 Space/半角空格 或者 HT/水平定位符号，间隔长度不限，但切勿输入全角空格
  * 一条条目只能接受一种地址类型（IPv4/IPv6），如有同一个域名需要同时进行 IPv4/IPv6 地址的过滤，请分为两个条目输入

* IPFilter - 地址过滤区域
地址过滤黑名单或白名单由配置文件的 IPFilter Type 值决定，Deny 禁止/黑名单和 Permit 允许/白名单
有效参数格式为 "开始地址 - 结束地址, 过滤等级, 条目简介注释"（不含引号）
  * 同时支持 IPv4 和 IPv6 地址，但填写时请分开为2个条目
  * 同一类型的地址地址段有重复的条目将会被自动合并
  
* Local Routing - 境内路由表区域
当 Local Routing 为开启时，将检查本列表的路由表是否命中，检查与否与域名请求是否使用 Local 服务器有关，路由表命中后会直接返回结果，命中失败将丢弃解析结果并向境外服务器再次发起请求
有效参数格式为 "地址块/网络前缀长度"（不含引号）
  * 本路由表支持 IPv4 和 IPv6 协议
  * IPv4 时网络前缀长度范围为 1-32，IPv6 时网络前缀长度范围为 1-128
  
* Stop - 临时停止读取标签
在需要停止读取的数据前添加 "[Stop]"（不含引号） 标签即可在中途停止对文件的读取，直到有其它标签时再重新开始读取
  * 具体情况参见上文的介绍


-------------------------------------------------------------------------------


程序运行参数说明：
由于部分功能无法通过使用配置文件指定使用，故而使用程序外挂参数进行支持
所有外挂参数也可通过 -h 和 --help 参数查询

* -v 和 --version
  输出程序版本号信息到屏幕上
* -h 和 --help
  输出程序帮助信息到屏幕上
* --flush-dns
  立即清空所有程序内以及系统的 DNS 缓存
* --first-setup
  进行本地防火墙测试(Windows)
* -c Path 和 --config-file Path
  启动时指定配置文件所在的以及程序的工作目录
* --disable-daemon
  关闭守护进程模式(Linux)
