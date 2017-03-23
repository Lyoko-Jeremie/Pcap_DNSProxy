Pcap_DNSProxy 项目的 GitHub 页面：
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy 项目的 Sourceforge 页面：
https://sourceforge.net/projects/pcap-dnsproxy


-------------------------------------------------------------------------------


安装方法（需要以管理员身份进行）：

1.访问 https://www.winpcap.org/install/default.htm 下载并以管理员权限安装 WinPcap
  * WinPcap 只需要安装一次，以前安装过最新版本或以后更新本工具时请从第2步开始操作
  * 如果 WinPcap 提示已安装旧版本无法继续时，参见 FAQ 中 运行结果分析 一节
  * 安装时自启动选项对工具的运行没有影响，本工具直接调用 WinPcap API 不需要经过服务器程序
 
2.访问 https://github.com/chengr28/Pcap_DNSProxy/releases 将二进制可执行文件包下载到本地
  * Windows 版本的 Pcap_DNSProxy 在二进制可执行文件包的 Windows 目录内，可将整个目录单独抽出运行

3.打开下载回来的二进制可执行文件包，将 Windows 目录解压到磁盘的任意位置
  * 目录所在位置和程序文件名可以随意更改，建议将本项目放置在一个独立的目录内
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
  * 如需让程序的流量通过系统路由级别的代理（例如 VPN 等）进行域名解析，请选择其中一种方案，配置完成后重启服务：
    * Direct Request = IPv4
    * Direct Request = IPv6
    * Direct Request = IPv4 + IPv6
  * 配置文件 Hosts 文件 IPFilter 文件和错误报告所在的目录以上文 安装方法 一节中第4步注册的服务信息为准
    * 填写时一行不要超过 4096字节/4KB
    * 文件读取只支持整个文本单一的编码和换行格式组合，切勿在文本文件中混合所支持的编码或换行格式！
  * 服务启动前请先确认没有其它本地 DNS 服务器运行或本工具多个拷贝运行中，否则可能会导致监听冲突无法正常工作
  * 杀毒软件/第三方防火墙可能会阻止本程序的操作，请将行为全部允许或将本程序加入到白名单中
  * 如果启动服务时提示 "服务没有及时响应启动或者控制请求" 请留意是否有错误报告生成，详细的错误信息参见 FAQ 文档中 Error.log 详细错误报告 一节
  * 目录和程序的名称可以随意更改，但请务必在进行安装方法第4步前完成。如果服务注册后需移动工具目录的路径，参见上文 卸载方法 第2步的注意事项
  * Windows XP 如出现 10022 错误，需要先启用系统的 IPv6 支持（以管理员身份运行 cmd 输入 ipv6 install 并回车，一次性操作），再重新启动服务
  * 本项目仅对最新版本提供技术支持，在新版本发布后旧版本的支持会即时停止，反馈前请先务必升级到最新版本


-------------------------------------------------------------------------------


重启服务方法（需要以管理员身份进行）：
1.右键以管理员身份(Vista 以及更新版本)或直接以管理员登录双击(XP/2003)运行 ServiceControl.bat
2.输入 5 并回车，即选择 "5: Restart service" 立刻重启服务


更新程序方法（需要以管理员身份进行，切勿直接覆盖，否则可能会造成不可预料的错误）：
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


-------------------------------------------------------------------------------


正常工作查看方法：
1.打开命令提示符
  * 在开始菜单或直接 Win + R 调出 运行 ，输入 cmd 并回车
  * 开始菜单 - 程序/所有程序 - 附件 - 命令提示符
2.输入 nslookup www.google.com 并回车
3.运行结果应类似：

   >nslookup www.google.com
    服务器:  pcap-dnsproxy.server（视配置文件设置的值而定，参见下文 配置文件详细参数说明 一节）
    Address:  127.0.0.1（视所在网络环境而定，本地监听协议为 IPv6 时为 ::1）

    非权威应答:
    名称:    www.google.com
    Addresses: ……（IP地址或地址列表）

4.如非以上结果，请移步 FAQ 文档中 运行结果分析 一节


-------------------------------------------------------------------------------


特别使用技巧：
这里列出部分项目组建议的介绍和使用技巧，供大家参考和使用。关于调整配置，参见下文 配置文件详细参数说明 一节

* 本工具配置选项丰富，配置不同的组合会有不同的效果，介绍几个比较常用的组合：
  * 默认配置：UDP 请求 + 抓包模式
  * Outgoing Protocol = ...TCP：先 TCP 请求失败后再 UDP 请求 + 抓包模式，对网络资源的占用比较高
    * 由于 TCP 请求大部分时候不会被投毒污染，此组合的过滤效果比较可靠
  * EDNS Label = 1：开启 EDNS 请求标签功能
    * 此功能开启后将有利于对伪造数据包的过滤能力，此组合的过滤效果比较可靠
  * 将目标服务器的请求端口改为非标准 DNS 端口：例如 OpenDNS 支持 53 标准端口和 5353 非标准端口的请求
    * 非标准 DNS 端口现阶段尚未被干扰，此组合的过滤效果比较可靠
  * Multiple Request Times = xx 时：应用到所有除请求境内服务器外的所有请求，一个请求多次发送功能
    * 此功能用于对抗网络丢包比较严重的情况，对系统和网络资源的占用都比较高，但在网络环境恶劣的情况下能提高获得解析结果的可靠性
  * DNSCurve = 1 同时 Encryption = 0：使用 DNSCurve/DNSCrypt 非加密模式请求域名解析
    * 此组合等于使用非标准 DNS 端口请求，域名解析可靠性比较高，详细情况参见上文
  * DNSCurve = 1 同时 Encryption = 1：使用 DNSCurve/DNSCrypt 加密模式请求域名解析
    * 此组合加密传输所有域名请求，域名解析可靠性最高
  * DNSCurve = 1 同时 Encryption = 1 同时 Encryption Only = 1：只使用 DNSCurve/DNSCrypt 加密模式请求域名解析
    * 上文的加密组合并不阻止程序在请求 DNSCurve/DNSCrypt 加密模式失败是使用其它协议请求域名解析，开启 Encryption Only = 1 后将只允许使用加密传输，安全性和可靠性最高，但域名解析成功率可能会下降
* 优化大量请求下程序表现：
  * Pcap Reading Timeout 适当调低这个参数能使抓包模块以更高的频率抓取数据包，降低延迟
  * Cache Parameter/Default TTL 尽量调高这个参数能增加缓存的生存时间或者队列长度，提高缓存命中率
  * Thread Pool Maximum Number 适当调高这个参数能可以增大缓冲区最大可容纳请求的数量
  * Queue Limits Reset Time 不要开启，限制请求数量的参数
  * Multiple Request Times 非极其恶劣情况慎用，消耗大量系统资源且会些微提高延迟


-------------------------------------------------------------------------------


功能和技术：

* 批处理的作用：
  * 运行结束会有运行结果，具体是否成功需要留意屏幕上的提示
  * 1: Install service - 将程序注册为系统服务，并启动程序进行 Windows 防火墙测试
  * 2: Uninstall service - 停止并卸载工具的服务
  * 3: Start service - 启动工具的服务
  * 4: Stop service - 停止工具的服务
  * 5: Restart service - 重启工具的服务
  * 6: Flush DNS cache in Pcap_DNSProxy - 刷新程序的内部和系统 DNS 的缓存
  * 7: Flush DNS cache in system only - 刷新系统的 DNS 缓存
  * 8: Exit - 退出
* 配置文件支持的文件名（只会读取优先级较高者，优先级较低者将被直接忽略）：
  * Windows: Config.ini > Config.conf > Config.cfg > Config
  * Linux/macOS: Config.conf > Config.ini > Config.cfg > Config
* 请求域名解析优先级
  * 使用系统 API函数进行域名解析（大部分）：系统 Hosts > Pcap_DNSProxy 的 Hosts 条目（Whitelist/白名单条目 > Hosts/主要 Hosts 列表） > DNS 缓存 > Local Hosts/境内 DNS 解析域名列表 > 远程 DNS 服务器
  * 直接从网络适配器设置内读取 DNS 服务器地址进行域名解析（小部分）：Pcap_DNSProxy 的 Hosts 配置文件（Whitelist/白名单条目 > Hosts/主要 Hosts 列表） > DNS 缓存 > Local Hosts/境内 DNS 解析域名列表 > 远程 DNS 服务器
  * 请求远程 DNS 服务器的优先级：Direct Request 模式 > TCP 模式的 DNSCurve 加密/非加密模式（如有） > UDP 模式的 DNSCurve 加密/非加密模式（如有） > TCP 模式普通请求（如有） > UDP 模式普通请求
* 本工具的 DNSCurve/DNSCrypt 协议是内置的实现，不需要安装 DNSCrypt 官方的工具！
  * DNSCurve 协议为 Streamlined/精简类型
  * 自动获取连接信息时必须保证系统时间的正确，否则证书验证时会出错导致连接信息获取失败！
  * DNSCrypt 官方工具会占用本地 DNS 端口导致 Pcap_DNSProxy 部署失败！


-------------------------------------------------------------------------------


程序运行参数说明：
由于部分功能无法通过使用配置文件指定使用，故而使用程序外挂参数进行支持
所有外挂参数也可通过 -h 和 --help 参数查询

* -c Path 和 --config-file Path
  启动时指定配置文件所在的工作目录
* -h 和 --help
  输出程序帮助信息到屏幕上
* -v 和 --version
  输出程序版本号信息到屏幕上
* --flush-dns
  立即清空所有程序内以及系统内的 DNS 缓存
* --flush-dns Domain
  立即清空域名为 Domain 以及所有系统内的 DNS 缓存
* --keypair-generator
  生成 DNSCurve/DNSCrypt 协议所需使用的密钥对到 KeyPair.txt
* --lib-version
  输出程序所用库的版本号信息到屏幕上
* --disable-daemon
  关闭守护进程模式 (Linux)
* --first-setup
  进行本地防火墙测试 (Windows)


-------------------------------------------------------------------------------


配置文件详细参数说明：

有效参数格式为 "选项名称 = 数值/数据"（不含引号，注意空格和等号的位置）
注意：配置文件只会在工具服务开始时读取，修改本文件的参数后请重启服务（参见上文 注意事项 一节中的 重启服务）

* Base - 基本参数区域
  * Version - 配置文件的版本，用于正确识别配置文件：本参数与程序版本号不相关，切勿修改
  * File Refresh Time - 文件刷新间隔时间：单位为秒，最小为 5
    * 本参数同时决定监视器的时间休眠时间片的粒度，其指的是休眠一段长时间时会根据此粒度激活并检查是否需要重新运行特定监视项目，而不需要等到长时间完全过去休眠完全结束后才能重新对此进行监视，此功能对程序的网络状况适应能力会有提高
  * Large Buffer Size - 大型数据缓冲区的固定长度：单位为字节，最小为 1500
  * Additional Path - 附加的数据文件读取路径，附加在此处的目录路径下的 Hosts 文件和 IPFilter 文件会被依次读取：请填入目录的绝对路径
  * Hosts File Name - Hosts 文件的文件名，附加在此处的 Hosts 文件名将被依次读取
  * IPFilter File Name - IPFilter 文件的文件名，附加在此处的 IPFilter 文件名将被依次读取

* Log - 日志参数区域
  * Print Log Level - 指定日志输出级别：留空为 3
    * 0 为关闭日志输出功能
    * 1 为输出重大错误
    * 2 为输出一般错误
    * 3 为输出所有错误
  * Log Maximum Size - 日志文件最大容量：直接填数字时单位为字节，可加上单位，支持的单位有 KB/MB/GB，可接受范围为 4KB - 1GB，如果留空则为 8MB
    * 注意：日志文件到达最大容量后将被直接删除，然后重新生成新的日志文件，原来的日志将无法找回！

* Listen - 监听参数区域
  * Pcap Capture - 抓包功能总开关，开启后抓包模块才能正常使用：开启为 1 /关闭为 0
    * 注意：如果抓包模块被关闭，则会自动开启 Direct Request 功能，启用 Direct Request 时对 DNS 投毒污染的防御能力比较弱
  * Pcap Devices Blacklist - 指定不对含有此名称的网络适配器进行抓包，名称或简介里含有此字符串的网络适配器将被直接忽略
    * 本参数支持指定多个名称，大小写不敏感，格式为 "网络适配器的名称(|网络适配器的名称)"（不含引号，括号内为可选项目）
    * 以抓包模块从系统中获取的名称或简介为准，与其它网络配置程序所显示的不一定相同
  * Pcap Reading Timeout - 抓包模块读取超时时间，数据包只会在等待超时时间后才会被读取，其余时间抓包模块处于休眠状态：单位为毫秒，最小为 10
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
  * Accept Type - 禁止或只允许所列 DNS 类型的请求，格式为 "Deny:DNS记录的名称或ID(|DNS记录的名称或ID)" 或 "Permit:DNS记录的名称或ID(|DNS记录的名称或ID)"（不含引号，括号内为可选项目），所有可用的 DNS 类型列表：
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
    * ADDRS/248
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
  * Outgoing Protocol - 发送请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向远程 DNS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 TCP 因为 UDP 为 DNS 的标准网络层协议，所以即使填入 TCP 失败时也会使用 UDP 请求
  * Direct Request - 直连模式，启用后将使用系统的 API 直接请求远程服务器而启用只使用本工具的 Hosts 功能：可填入 IPv4 和 IPv6 和 0，关闭为 0
    * 建议当系统使用全局代理功能时启用，程序将除境内服务器外的所有请求直接交给系统而不作任何过滤等处理，系统会将请求自动发往远程服务器进行解析
    * 填入 IPv4 或 IPv6 时将会启用对应协议的 Direct Request 功能，填入 IPv4 + IPv6 将会启用所有协议的功能
  * Cache Type - DNS 缓存的类型：分 Timer/计时型、Queue/队列型以及它们的混合类型，填入 0 为关闭此功能
    * Timer/计时型：超过指定时间的 DNS 缓存将会被丢弃
    * Queue/队列型：超过队列长度时，将删除最旧的 DNS 缓存
    * 混合类型：超过指定时间时和超过队列长度时，都会删除最旧的 DNS 缓存
  * Cache Parameter - DNS 缓存的参数：分 Timer/计时型、Queue/队列型以及它们的混合类型，填入 0 为关闭此功能
    * Timer/计时型
      * 缓存时间，单位为秒
      * 如果解析结果的平均 TTL 值大于此值，则使用 [TTL + 此值] 为最终的缓存时间
      * 如果解析结果的平均 TTL 值小于等于此值，则使用 [此值] 为最终的缓存时间
      * 如果填 0 则最终的缓存时间为 TTL 值
    * Queue/队列型：队列长度
    * 混合类型
      * 队列长度
      * 此模式下最终的缓存时间由 Default TTL 参数决定
  * Default TTL - 已缓存 DNS 记录默认生存时间：单位为秒，留空则为 900秒/15分钟
    * DNS 缓存的类型为混合类型时，本参数将同时决定最终的缓存时间
      * 如果解析结果的平均 TTL 值大于此值，则使用 [TTL + 此值] 为最终的缓存时间
      * 如果解析结果的平均 TTL 值小于等于此值，则使用 [此值] 为最终的缓存时间
      * 如果填 0 则最终的缓存时间为 TTL 值

* Local DNS - 境内域名解析参数区域
  * Local Protocol - 发送境内请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向境内 DNS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 TCP 因为 UDP 为 DNS 的标准网络层协议，所以即使填入 TCP 失败时也会使用 UDP 请求
  * Local Force Request - 强制使用境内服务器进行解析：开启为 1 /关闭为 0
    * 本功能只对已经确定使用境内服务器的域名请求有效
  * Local Hosts - 白名单境内服务器请求功能：开启为 1 /关闭为 0
    * 开启后才能使用自带或自定义的 Local Hosts 白名单，且不能与 Local Main 和 Local Routing 同时启用
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
  * IPv4 EDNS Client Subnet Address - IPv4 客户端子网地址，输入后将为所有请求添加此地址的 EDNS 子网信息：需要输入一个带前缀长度的本机公共网络地址，留空为不启用
    * 本功能要求启用 EDNS Label 参数
    * EDNS Client Subnet Relay 参数优先级比此参数高，启用后将优先添加 EDNS Client Subnet Relay 参数的 EDNS 子网地址
    * RFC 标准建议 IPv4 地址的前缀长度为 24 位，IPv6 地址为 56 位
  * IPv4 Main DNS Address - IPv4 主要 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址，注意填入后将强制启用 Alternate Multiple Request 参数
    * 支持使用服务名称代替端口号
  * IPv4 Alternate DNS Address - IPv4 备用 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址，注意填入后将强制启用 Alternate Multiple Request 参数
    * 支持使用服务名称代替端口号
  * IPv4 Main Local DNS Address - IPv4 主要境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * IPv4 Local Alternate DNS Address - IPv4 备用境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * IPv6 Listen Address - IPv6 本地监听地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址
    * 填入此值后 IPv6 协议的 Operation Mode 和 Listen Port 参数将被自动忽略
  * IPv6 EDNS Client Subnet Address - IPv6 客户端子网地址，输入后将为所有请求添加此地址的 EDNS 子网信息：需要输入一个带前缀长度的本机公共网络地址，留空为不启用
    * 本功能要求启用 EDNS Label 参数
    * EDNS Client Subnet Relay 参数优先级比此参数高，启用后将优先添加 EDNS Client Subnet Relay 参数的 EDNS 子网地址
  * IPv6 Main DNS Address - IPv6 主要 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址，注意填入后将强制启用 Alternate Multiple Request 参数
    * 支持使用服务名称代替端口号
  * IPv6 Alternate DNS Address - IPv6 备用 DNS 服务器地址：需要输入一个带端口格式的地址，留空为不启用
    * 支持多个地址，注意填入后将强制启用 Alternate Multiple Request 参数
    * 支持使用服务名称代替端口号
  * IPv6 Local Main DNS Address - IPv6 主要境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * IPv6 Local Alternate DNS Address - IPv6 备用境内 DNS 服务器地址，用于境内域名解析：需要输入一个带端口格式的地址，留空为不启用
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * 注意：
    * 带端口地址的格式：
      * 单个 IPv4 为 "IPv4 地址:端口"（不含引号）
      * 单个 IPv6 为 "[IPv6 地址]:端口"（不含引号）
      * 多个 IPv4 为 "地址A:端口|地址B:端口|地址C:端口"（不含引号）
      * 多个 IPv6 为 "[地址A]:端口|[地址B]:端口|[地址C]:端口"（不含引号）
      * 启用同时请求多服务器后将同时向列表中的服务器请求解析域名，并采用最快回应的服务器的结果，同时请求多服务器启用后将自动启用 Alternate Multiple Request 参数（参见下文）
      * 可填入的服务器数量为：填入主要/备用服务器的数量
      * Multiple Request Times = 总请求的数值，此数值不能超过 64
    * 带前缀长度地址的格式：
      * IPv4 为 "IPv4 地址/掩码长度"（不含引号）
      * IPv6 为 "IPv6 地址/前缀长度"（不含引号）
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
  * Thread Pool Base Number - 线程池基础最低保持线程数量：最小为 8 设置为 0 则关闭线程池的功能
  * Thread Pool Maximum Number - 线程池最大线程数量以及缓冲区队列数量限制：最小为 8
    * 启用 Queue Limits Reset Time 参数时，此参数为单位时间内最多可接受请求的数量
    * 不启用 Queue Limits Reset Time 参数时为用于接收数据的缓冲区的数量
  * Thread Pool Reset Time - 线程池中线程数量超出 Thread Pool Base Number 所指定数量后线程将会自动退出前所驻留的时间：单位为秒
  * Queue Limits Reset Time - 数据缓冲区队列数量限制重置时间：单位为秒，最小为 5 设置为 0 时关闭此功能
  * EDNS Payload Size - EDNS 标签附带使用的最大载荷长度：最小为 DNS 协议实现要求的 512(bytes)，留空则使用 EDNS 标签要求最短的 1220(bytes)
  * IPv4 Packet TTL - 发出 IPv4 数据包头部 TTL 值：0 为由操作系统自动决定，取值为 1-255 之间
    * 本参数支持指定取值范围，每次发出数据包时实际使用的值会在此范围内随机指定，指定的范围均为闭区间
  * IPv4 Main DNS TTL - IPv4 主要 DNS 服务器接受请求的远程 DNS 服务器数据包的 TTL 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 TTL 值，与 IPv4 DNS Address 相对应
  * IPv4 Alternate DNS TTL - IPv4 备用 DNS 服务器接受请求的远程 DNS 服务器数据包的 TTL 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 TTL 值，与 IPv4 Alternate DNS Address 相对应
  * IPv6 Packet Hop Limits - 发出 IPv6 数据包头部 HopLimits 值：0 为由操作系统自动决定，取值为 1-255 之间
    * 本参数支持指定取值范围，每次发出数据包时实际使用的值会在此范围内随机指定，指定的范围均为闭区间
  * IPv6 Main DNS Hop Limits - IPv6 主要 DNS 服务器接受请求的远程 DNS 服务器数据包的 Hop Limits 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 Hop Limits 值，与 IPv6 DNS Address 相对应
  * IPv6 Alternate DNS Hop Limits - IPv6 备用 DNS 服务器接受请求的远程 DNS 服务器数据包的 Hop Limits 值：0 为自动获取，取值为 1-255 之间
    * 支持多个 Hop Limits 值，与 IPv6 Alternate DNS Address 相对应
  * Hop Limits Fluctuation - IPv4 TTL/IPv6 Hop Limits 可接受范围，即 IPv4 TTL/IPv6 Hop Limits 的值 ± 数值的范围内的数据包均可被接受，用于避免网络环境短暂变化造成解析失败的问题：取值为 1-255 之间
  * Reliable Once Socket Timeout - 一次性可靠协议端口超时时间：单位为毫秒，最小为 500 可留空，留空时为 3000
    * 一次性是指请求在一次 RTT 往返网络传输内即可完成，例如标准 DNS 和 DNSCurve/DNSCrypt 协议
    * 可靠端口是指 TCP 协议
  * Reliable Serial Socket Timeout - 串行可靠协议端口超时时间：单位为毫秒，最小为 500 可留空，留空时为 1500
    * 串行是指此操作需要多次交互网络传输才能完成，例如 SOCKS 和 HTTP CONNECT 协议
    * 可靠端口是指 TCP 协议
  * Unreliable Once Socket Timeout - 一次性不可靠协议端口超时时间：单位为毫秒，最小为 500 可留空，留空时为 2000
    * 一次性是指请求在一次 RTT 往返网络传输内即可完成，例如标准 DNS 和 DNSCurve/DNSCrypt 协议
    * 不可靠端口指 UDP/ICMP/ICMPv6 协议
  * Unreliable Serial Socket Timeout - 串行可靠协议端口超时时间：单位为毫秒，最小为 500 可留空，留空时为 1000
    * 串行是指此操作需要多次交互网络传输才能完成，例如 SOCKS 和 HTTP CONNECT 协议
    * 不可靠端口指 UDP/ICMP/ICMPv6 协议
  * TCP Fast Open - TCP 快速打开功能：
    * 本功能的支持情况：
      * Windows 平台
        * 开启为 1 /关闭为 0
        * 服务器端支持，客户端由于不同类型 I/O 的问题暂时无法进行支持
        * 需要 Windows 10 Version 1607 以及更新版本的支持
      * Linux 平台：
        * 此参数可同时指定支持 TCP Fast Open 监听队列长度，直接填入大于 0 的值即为队列长度，关闭为 0
        * 服务器端和客户端完全支持
        * IPv4 协议需要 Linux Kernel 3.7 以及更新版本的支持，IPv6 协议需要 Linux Kernel 3.16 以及更新版本的内核支持
      * macOS 平台：
        * 开启为 1 /关闭为 0
        * 服务器端和客户端完全支持
        * 需要 macOS 10.11 Sierra 以及更新版本的支持
    * 警告：切勿在不受支持的版本上开启本功能，否则可能导致程序无法正常收发数据包！
  * Receive Waiting - 数据包接收等待时间，启用后程序会尝试等待一段时间以尝试接收所有数据包并返回最后到达的数据包：单位为毫秒，留空或设置为 0 表示关闭此功能
    * 本参数与 Pcap Reading Timeout 密切相关，由于抓包模块每隔一段读取超时时间才会返回给程序一次，当数据包接收等待时间小于读取超时时间时会导致本参数变得没有意义，在一些情况下甚至会拖慢域名解析的响应速度
    * 本参数启用后虽然本身只决定抓包模块的接收等待时间，但同时会影响到非抓包模块的请求。非抓包模块会自动切换为等待超时时间后发回最后收到的回复，默认为接受最先到达的正确的回复，而它们的超时时间由 Reliable Once Socket Timeout/Unreliable Once Socket Timeout 参数决定
    * 一般情况下，越靠后所收到的数据包，其可靠性可能会更高
  * ICMP Test - ICMP/Ping 测试间隔时间：单位为秒，最小为 5 设置为 0 表示关闭此功能
  * Domain Test - DNS 服务器解析域名测试间隔时间：单位为秒，最小为 5 设置为 0 表示关闭此功能
  * Alternate Times - 备用服务器失败次数阈值，一定周期内如超出阈值会触发服务器切换：单位为次
  * Alternate Time Range - 备用服务器失败次数阈值计算周期：单位为秒，最小为 5
  * Alternate Reset Time - 备用服务器重置切换时间，切换产生后经过此事件会切换回主要服务器：单位为秒，最小为 5
  * Multiple Request Times - 一次向同一个远程服务器发送并行域名解析请求：0 和 1 时为收到一个请求时请求 1 次，2 时为收到一个请求时请求 2 次，3 时为收到一个请求时请求 3 次……以此类推
    * 此值将应用到 Local Hosts 外对所有远程服务器所有协议的请求，因此可能会对系统以及远程服务器造成压力，请谨慎考虑开启的风险！
    * 可填入的最大数值为：填入主要/备用服务器的数量
  * Multiple Request Times = 总请求的数值，此数值不能超过 64
    * 一般除非丢包非常严重干扰正常使用否则不建议开启，开启也不建议将值设得太大。实际使用可以每次+1后重启服务测试效果，找到最合适的值
  * 注意：
    * IPv4 协议使用多 TTL 值的格式为 "TTL(A)|TTL(B)|TTL(C)"（不含引号），也可直接默认（即只填一个 0 不使用此格式）则所有 TTL 都将由程序自动获取
    * 使用同时请求多服务器格式为 "Hop Limits(A)|Hop Limits(B)|Hop Limits(C)"（不含引号），也可直接默认（即只填一个 0 不使用此格式）则所有 Hop Limits 都将由程序自动获取
    * 使用多 TTL/Hop Limits 值所对应的顺序与对应地址参数中的地址顺序相同

* Switches - 控制开关区域
  * Domain Case Conversion - 随机转换域名请求大小写：开启为 1 /关闭为 0
  * Compression Pointer Mutation - 随机添加压缩指针：可填入 1 (+ 2 + 3)，关闭为 0
    * 随机添加压缩指针有3种不同的类型，对应 1 和 2 和 3
    * 可单独使用其中一个，即只填一个数字，或填入多个，中间使用 + 号连接
    * 填入多个时，当实际需要使用随机添加压缩指针时将随机使用其中的一种，每个请求都有可能不相同
  * EDNS Label - EDNS 标签支持，开启后将为请求添加 EDNS 标签：全部开启为 1 /关闭为 0
    * 本参数可只指定部分的请求过程使用 EDNS 标签，分为指定模式和排除模式：
    * 指定列表模式，列出的过程才启用此功能：EDNS Label = Local + SOCKS Proxy + HTTP CONNECT Proxy + Direct Request + DNSCurve + TCP + UDP
    * 排除列表模式，列出的过程不启用此功能：EDNS Label = 1 - Local - SOCKS Proxy - HTTP CONNECT Proxy - Direct Request - DNSCurve - TCP - UDP
  * EDNS Client Subnet Relay - EDNS 客户端子网转发功能，开启后将为来自非私有网络地址的所有请求添加其请求时所使用的地址的 EDNS 子网地址：开启为 1 /关闭为 0
    * 本功能要求启用 EDNS Label 参数
    * 本参数优先级比 IPv4/IPv6 EDNS Client Subnet Address 参数高，故需要添加 EDNS 子网地址时将优先添加本参数的地址
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
  * Alternate Multiple Request - 备用服务器同时请求参数，开启后将同时请求主要服务器和备用服务器并采用最快回应的服务器的结果：开启为 1 /关闭为 0
    * 同时请求多服务器启用后本参数将强制启用，将同时请求所有存在于列表中的服务器，并采用最快回应的服务器的结果
  * IPv4 Do Not Fragment - IPv4 数据包头部 Do Not Fragment 标志：开启为 1 /关闭为 0
    * 本功能不支持 macOS 平台，此平台将直接忽略此参数
  * IPv4 Data Filter - IPv4 数据包头检测：开启为 1 /关闭为 0
  * TCP Data Filter - TCP 数据包头检测：开启为 1 /关闭为 0
  * DNS Data Filter - DNS 数据包头检测：开启为 1 /关闭为 0
  * Blacklist Filter - 解析结果黑名单过滤：开启为 1 /关闭为 0
  * Strict Resource Record TTL Filter - 严格的资源记录生存时间过滤，标准要求同一名称和类型的资源记录必须具有相同的生存时间：开启为 1/关闭为 0
  
* Data - 数据区域
  * ICMP ID - ICMP/Ping 数据包头部 ID 的值：格式为 0x**** 的十六进制字符，如果留空则获取线程的 ID 作为请求用 ID
  * ICMP Sequence - ICMP/Ping 数据包头部 Sequence/序列号 的值：格式为 0x**** 的十六进制字符，如果留空则为 0x0001
  * Domain Test Data - DNS 服务器解析域名测试：请输入正确、确认不会被投毒污染的域名并且不要超过 253 字节 ASCII 数据，留空则会随机生成一个域名进行测试
  * Domain Test ID - DNS 数据包头部 ID 的值：格式为 0x**** 的十六进制字符，如果留空则为 0x0001
  * ICMP PaddingData - ICMP 附加数据，Ping 程序发送请求时为补足数据使其达到 Ethernet 类型网络最低的可发送长度时添加的数据：长度介乎于 18字节 - 1500字节 ASCII 数据之间，留空则使用 Microsoft Windows Ping 程序的 ICMP 附加数据
  * Local Machine Server Name - 本地 DNS 服务器名称：请输入正确的域名并且不要超过253字节 ASCII 数据，留空则使用 pcap-dnsproxy.server 作为本地服务器名称

* Proxy - 代理区域
  * SOCKS Proxy - SOCKS 协议总开关，控制所有和 SOCKS 协议有关的选项：开启为 1 /关闭为 0
  * SOCKS Version - SOCKS 协议所使用的版本：可填入 4 或 4A 或 5
    * SOCKS 版本 4 不支持 IPv6 地址以及域名的目标服务器，以及不支持 UDP 转发功能
    * SOCKS 版本 4a 不支持 IPv6 地址的目标服务器，以及不支持 UDP 转发功能
  * SOCKS Protocol - 发送 SOCKS 协议请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向 SOCKS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 UDP 因为 TCP 为 SOCKS 最先支持以及最普遍支持的标准网络层协议，所以即使填入 UDP 请求失败时也会使用 TCP 请求
  * SOCKS UDP No Handshake - SOCKS UDP 不握手模式，开启后将不进行 TCP 握手直接发送 UDP 转发请求：开启为 1 /关闭为 0
    * SOCKS 协议的标准流程使用 UDP 转发功能前必须使用 TCP 连接交换握手信息，否则 SOCKS 服务器将直接丢弃转发请求
    * 部分 SOCKS 本地代理可以直接进行 UDP 转发而不需要使用 TCP 连接交换握手信息，启用前请务必确认 SOCKS 服务器的支持情况
  * SOCKS Proxy Only - 只使用 SOCKS 协议代理模式，所有请求将只通过 SOCKS 协议进行：开启为 1 /关闭为 0
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
  * HTTP CONNECT Proxy - HTTP CONNECT 协议总开关，控制所有和 HTTP CONNECT 协议有关的选项：开启为 1 /关闭为 0
  * HTTP CONNECT Protocol - 发送 HTTP CONNECT 协议请求所使用的协议：可填入 IPv4 和 IPv6
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 时，只使用指定协议向 HTTP CONNECT 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
  * HTTP CONNECT Proxy Only - 只使用 HTTP CONNECT 协议代理模式，所有请求将只通过 HTTP CONNECT 协议进行：开启为 1 /关闭为 0
  * HTTP CONNECT IPv4 Address - HTTP CONNECT 协议 IPv4 主要 HTTP CONNECT 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * HTTP CONNECT IPv6 Address - HTTP CONNECT 协议 IPv6 主要 HTTP CONNECT 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * HTTP CONNECT Target Server - HTTP CONNECT 最终目标服务器：需要输入一个带端口格式的 IPv4/IPv6 地址或域名
    * 不支持多个地址或域名，只能填入单个地址或域名
    * 支持使用服务名称代替端口号
  * HTTP CONNECT TLS Handshake - HTTP CONNECT 协议 TLS 握手和加密传输总开关：开启为 1 /关闭为 0
  * HTTP CONNECT TLS Version - HTTP CONNECT 协议启用 TLS 握手和加密传输时所指定使用的版本：设置为 0 则自动选择
    * 现阶段可填入 1.0 或 1.1 或 1.2
    * Windows XP/2003 和 Windows Vista 不支持高于 1.0 的版本
    * OpenSSL 1.0.0 以及更旧的版本不支持高于 1.0 的版本
  * HTTP CONNECT TLS Validation - HTTP CONNECT 协议启用 TLS 握手时服务器证书链检查：开启为 1 /关闭为 0
    * 警告：关闭此功能将可能导致加密连接被中间人攻击，强烈建议开启！
    * 警告：OpenSSL 1.0.2 之前的版本不支持检查服务器证书的域名匹配情况，敬请留意！
  * HTTP CONNECT TLS Server Name Indication - HTTP CONNECT 协议用于指定 TLS 握手时所指定使用的域名服务器：请输入正确的域名并且不要超过253字节 ASCII 数据，留空则不启用此功能
  * HTTP CONNECT Version - 附带在 HTTP CONNECT Header 的 HTTP CONNECT 协议版本号
  * HTTP CONNECT Header Field - 附带在 HTTP CONNECT Header 的信息：所输入的信息将被直接添加到 HTTP CONNECT Header
    * 本参数可重复多次出现，所有有内容的 HTTP CONNECT Header 的信息都将被记录并在请求时按顺序添加到 HTTP CONNECT Header 里
  * HTTP CONNECT Proxy Authorization - 连接 HTTP CONNECT Proxy 服务器时所使用的认证信息：需要输入 "用户名:密码"（不含引号），留空为不启用
    * 只支持 Base 方式的认证

* DNSCurve - DNSCurve 协议基本参数区域
  * DNSCurve - DNSCurve 协议总开关，控制所有和 DNSCurve 协议有关的选项：开启为 1 /关闭为 0
  * DNSCurve Protocol - DNSCurve 发送请求所使用的协议：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的协议可随意组合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 时，只使用指定协议向远程 DNS 服务器发出请求
    * 同时填入 IPv4 和 IPv6 或直接不填任何网络层协议时，程序将根据网络环境自动选择所使用的协议
    * 同时填入 TCP 和 UDP 等于只填入 TCP 因为 UDP 为 DNS 的标准网络层协议，所以即使填入 TCP 失败时也会使用 UDP 请求
  * DNSCurve Payload Size - DNSCurve 标签附带使用的最大载荷长度，同时亦为发送请求的总长度，并决定请求的填充长度：单位为字节
    * 最小为 DNS 协议实现要求的 512，留空则为 512
    * 最大为 1500 减去 DNSCurve 头长度，建议不要超过 1220
    * DNSCurve 协议要求此值必须为 64 的倍数
  * DNSCurve Reliable Socket Timeout - 可靠 DNSCurve 协议端口超时时间，可靠端口指 TCP 协议：单位为毫秒，最小为 500 可留空，留空时为 3000
  * DNSCurve Unreliable Socket Timeout - 不可靠 DNSCurve 协议端口超时时间，不可靠端口指 UDP 协议：单位为毫秒，最小为 500 可留空，留空时为 2000
  * DNSCurve Encryption - 启用加密，DNSCurve 协议支持加密和非加密模式：开启为 1 /关闭为 0
  * DNSCurve Encryption Only - 只使用加密模式，所有请求将只通过 DNCurve 加密模式进行：开启为 1 /关闭为 0
    * 注意：使用 "只使用加密模式" 时必须提供服务器的魔数和指纹用于请求和接收
  * DNSCurve Client Ephemeral Key - 一次性客户端密钥对模式，每次请求解析均使用随机生成的一次性客户端密钥对，提供前向安全性：开启为 1 /关闭为 0
  * DNSCurve Key Recheck Time - DNSCurve 协议 DNS 服务器连接信息检查间隔：单位为秒，最小为 10

* DNSCurve Addresses - DNSCurve 协议地址区域
  * DNSCurve IPv4 Main DNS Address - DNSCurve 协议 IPv4 主要 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv4 Alternate DNS Address - DNSCurve 协议 IPv4 备用 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv6 Main DNS Address - DNSCurve 协议 IPv6 主要 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv6 Alternate DNS Address - DNSCurve 协议 IPv6 备用 DNS 服务器地址：需要输入一个带端口格式的地址
    * 不支持多个地址，只能填入单个地址
    * 支持使用服务名称代替端口号
  * DNSCurve IPv4 Main Provider Name - DNSCurve 协议 IPv4 主要 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * DNSCurve IPv4 Alternate Provider Name - DNSCurve 协议 IPv4 备用 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * DNSCurve IPv6 Main Provider Name - DNSCurve 协议 IPv6 主要 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * DNSCurve IPv6 Alternate Provider Name - DNSCurve 协议 IPv6 备用 DNS 服务器提供者，请输入正确的域名并且不要超过 253 字节 ASCII 数据
  * 注意：
    * 自动获取 DNSCurve 服务器连接信息时必须输入提供者的域名，不能留空
    * 更多支持 DNSCurve/DNSCrypt 的服务器请移步 https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv

* DNSCurve Keys - DNSCurve 协议密钥区域
  * DNSCurve Client Public Key - 自定义客户端公钥：可使用 KeyPairGenerator 生成，留空则每次启动时自动生成
  * DNSCurve Client Secret Key - 自定义客户端私钥：可使用 KeyPairGenerator 生成，留空则每次启动时自动生成
  * DNSCurve IPv4 Main DNS Public Key - DNSCurve 协议 IPv4 主要 DNS 服务器验证用公钥
  * DNSCurve IPv4 Alternate DNS Public Key - DNSCurve 协议 IPv4 备用 DNS 服务器验证用公钥
  * DNSCurve IPv6 Main DNS Public Key - DNSCurve 协议 IPv6 主要 DNS 服务器验证用公钥
  * DNSCurve IPv6 Alternate DNS Public Key - DNSCurve 协议 IPv6 备用 DNS 服务器验证用公钥
  * DNSCurve IPv4 Main DNS Fingerprint - DNSCurve 协议 IPv4 主要 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * DNSCurve IPv4 Alternate DNS Fingerprint - DNSCurve 协议 IPv4 备用 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * DNSCurve IPv6 Main DNS Fingerprint - DNSCurve 协议 IPv6 备用 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * DNSCurve IPv6 Alternate DNS Fingerprint - DNSCurve 协议 IPv6 备用 DNS 服务器传输用指纹，留空则自动通过服务器提供者和公钥获取
  * 注意：
    * 公开网站上的 "公钥" 普遍为验证用的公钥，用于验证与服务器通讯时使用的指纹，两者为不同性质的公钥不可混用！
  
* DNSCurve Magic Number - DNSCurve 协议魔数区域
  * DNSCurve IPv4 Main Receive Magic Number - DNSCurve 协议 IPv4 主要 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * DNSCurve IPv4 Alternate Receive Magic Number - DNSCurve 协议 IPv4 备用 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * DNSCurve IPv6 Main Receive Magic Number - DNSCurve 协议 IPv6 主要 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * DNSCurve IPv6 Alternate Receive Magic Number - DNSCurve 协议 IPv6 备用 DNS 服务器接收魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则使用程序内置的接收魔数
  * DNSCurve IPv4 Main DNS Magic Number - DNSCurve 协议 IPv4 主要 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * DNSCurve IPv4 Alternate DNS Magic Number - DNSCurve 协议 IPv4 备用 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * DNSCurve IPv6 Main DNS Magic Number - 协议 IPv6 主要 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * DNSCurve IPv6 Alternate DNS Magic Number - DNSCurve 协议 IPv6 备用 DNS 服务器发送魔数：长度必须为 8 字节（ASCII）或 18 字节（十六进制），留空则自动获取
  * 注意：Magic Number 参数均同时支持使用 ASCII 字符或十六进制字符串进行指定
    * 直接填入可打印 ASCII 字符串即可
    * 十六进制字符串需要在字符串前面加上 0x（大小写敏感）


-------------------------------------------------------------------------------


Hosts 文件格式说明：

Hosts 配置文件分为多个提供不同功能的区域
* 区域通过标签识别，修改时切勿将其删除
* 一条条目的总长度切勿超过 4096字节/4KB
* 需要注释请在条目开头添加 #/井号
* 优先级别自上而下递减，条目越前优先级越高
* 平行 Hosts 条目支持数量由请求域名以及 EDNS Payload 长度决定，建议不要超过75个 A 记录或43个 AAAA 记录


* Whitelist - 白名单条目
  * 此类型的条目列出的符合要求的域名会直接绕过 Hosts 不会使用 Hosts 功能
  * 有效参数格式为 "NULL 正则表达式"（不含引号）
  * 注意优先级的问题，例如有一片含白名单条目的区域：

    NULL .*\.test\.test
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test

  * 虽然 .*\.test 包含了 .*\.test\.test 但由于优先级别自上而下递减，故先命中 .*\.test\.test 并返回使用远程服务器解析
  * 从而绕过了下面的条目，不使用 Hosts 的功能


* Whitelist Extended - 白名单条目扩展功能
  * 此类型的条目还支持对符合规则的特定类型域名请求直接绕过 Hosts 不会使用 Hosts 功能
  * 有效参数格式为 "NULL:DNS类型(|DNS类型) 正则表达式"（不含引号，括号内为可选项目）
  * 只允许特定类型域名请求，有效参数格式为 "NULL(Permit):DNS类型(|DNS类型) 正则表达式"（不含引号，括号内为可选项目）

    NULL:A|AAAA .*\.test\.test
    NULL(Deny):NS|SOA .*\.test

  * 第一条即直接跳过匹配规则的 A 记录和 AAAA 记录的域名请求，其它类型的请求则被匹配规则
  * 而第二条则只匹配规则的 NS 记录和 SOA 记录的域名请求，其它类型的请求则被直接跳过


* Banned - 黑名单条目
  * 此类型的条目列出的符合要求的域名会直接返回域名不存在的功能，避免重定向导致的超时问题
  * 有效参数格式为 "BANNED 正则表达式"（不含引号）
  * 注意优先级的问题，例如有一片含黑名单条目的区域：

    BANNED .*\.test\.test
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test

  * 虽然 .*\.test 包含了 .*\.test\.test 但由于优先级别自上而下递减，故先命中 .*\.test\.test 并直接返回域名不存在
  * 从而绕过了下面的条目，达到屏蔽域名的目的


* Banned Extended - 黑名单条目扩展功能
  * 此类型的条目还支持对符合规则的特定类型域名请求进行屏蔽或放行
  * 有效参数格式为 "BANNED:DNS类型(|DNS类型) 正则表达式"（不含引号，括号内为可选项目）
  * 只允许特定类型域名请求，有效参数格式为 "BANNED(Permit):DNS类型(|DNS类型) 正则表达式"（不含引号，括号内为可选项目）

    BANNED:A|AAAA .*\.test\.test
    BANNED(Permit):NS|SOA .*\.test

  * 第一条即屏蔽匹配规则的 A 记录和 AAAA 记录的域名请求，其它类型的请求则被放行
  * 而第二条则只放行匹配规则的 NS 记录和 SOA 记录的域名请求，其它类型的请求则被屏蔽


* Hosts/CNAME Hosts/Source Hosts - 主要 Hosts 列表/CNAME Hosts 列表/根据来源地址 Hosts 列表
  * 主要 Hosts 列表和 CNAME Hosts 列表主要区别是作用范围不相同，前者的作用范围为接收到的域名解析请求，后者的作用范围为接收到的域名解析结果
    * 有效参数格式为 "地址(|地址A|地址B) 域名的正则表达式"（不含引号，括号内为可选项目，注意间隔所在的位置）
  * 根据来源地址 Hosts 列表，根据接收到的域名解析请求的来源地址判断是否需要进行 Hosts
    * 有效参数格式为 "来源地址/前缀长度(|来源地址A/前缀长度A|来源地址B/前缀长度B)->地址(|地址A|地址B) 域名的正则表达式"（不含引号，括号内为可选项目，注意间隔所在的位置）
  * 地址与正则表达式之间的间隔字符可为 Space/半角空格 或者 HT/水平定位符号，间隔长度不限，但切勿输入全角空格
  * 一条条目只能接受一种地址类型（IPv4/IPv6），如有同一个域名需要同时进行 IPv4/IPv6 的 Hosts，请分为两个条目输入
  * 平行地址原理为一次返回多个记录，而具体使用哪个记录则由请求者决定，一般为第1个
  * 例如有一个 [Hosts] 下有效数据区域：

    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.test
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.test
    ::1|::2|::3 .*\.test\.test
    ::4|::5|::6 .*\.test

  * 虽然 .*\.test 包含了 .*\.test\.test 但由于优先级别自上而下递减，故先命中 .*\.test\.test 并直接返回，不会再进行其它检查
    * 请求解析 xxx.test 的 A 记录（IPv4）会返回 127.0.0.4、127.0.0.5 和 127.0.0.6
    * 请求解析 xxx.test 的 AAAA 记录（IPv6）会返回 ::4、::5 和 ::6
    * 请求解析 xxx.test.test 的 A 记录（IPv4）会返回 127.0.0.1、127.0.0.2 和 127.0.0.3
    * 请求解析 xxx.test.test 的 AAAA 记录（IPv6）会返回 ::1、::2 和 ::3


* Local Hosts - 境内 DNS 解析域名列表
本区域数据用于为域名使用境内 DNS 服务器解析提高访问速度，使用时请确认境内 DNS 服务器地址不为空（参见上文 配置文件详细参数说明 一节）
有效参数格式为 "正则表达式"（不含引号）
  * 要使用本功能，必须将配置文件内的 Local Hosts 选项打开！
  * 本功能不会对境内 DNS 服务器回复进行任何过滤，请确认本区域填入的数据不会受到 DNS 投毒污染的干扰
  * 例如有一个 [Local Hosts] 下有效数据区域：

    .*\.test\.test
    .*\.test

  * 即所有符合以上正则表达式的域名请求都将使用境内 DNS 服务器解析


* Address Hosts - 解析结果地址替换列表
  * 本区域数据用于替换解析结果中的地址，提供更精确的 Hosts 自定义能力
  * 目标地址区域支持使用网络前缀格式，可根据指定的前缀长度替换解析结果中地址的前缀数据
    * 使用网络前缀格式时第一个目标地址条目必须指定前缀长度，其它目标地址可省略不写也可全部写上
    * 网络前缀格式指定后将应用到所有目标地址上，注意整个条目只能指定同一个前缀长度
  * 例如有一个 [Address Hosts] 下有效数据区域：

    127.0.0.1|127.0.0.2 127.0.0.0-127.255.255.255
    255.255.255.255/24 255.254.253.252
    ::1 ::-::FFFF
    FFFF:EEEE::/64|FFFF:EEEE:: FFFF::EEEE|FFFF::EEEF-FFFF::FFFF

  * 解析结果的地址范围为 127.0.0.0 到 127.255.255.255 时将被替换为 127.0.0.1 或 127.0.0.2
  * 解析结果的地址为 255.254.253.252 时将被替换为 255.255.255.252
  * 解析结果的地址范围为 :: 到 ::FFFF 时将被替换为 ::1
  * 解析结果的地址范围为 FFFF::EEEE 或 FFFF::EEEF 到 FFFF::FFFF 时将被替换为 FFFF:FFFF::EEEE 或 FFFF:FFFF::xxxx:xxxx:xxxx:xxxx 或 FFFF:EEEE::EEEE 或 FFFF:EEEE::xxxx:xxxx:xxxx:xxxx


* Stop - 临时停止读取标签
  * 在需要停止读取的数据前添加 "[Stop]" 和数据后添加 "[Stop End]"（均不含引号）标签即可在中途停止对文件的读取
  * 临时停止读取生效后需要遇到临时停止读取终止标签或其它标签时才会重新开始读取
  * 例如有一片数据区域：

    [Hosts]
    [Stop]
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.test
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.test
    [Stop End]
    ::1|::2|::3 .*\.test\.test
    ::4|::5|::6 .*\.test

    [Local Hosts]
    .*\.test\.test
    .*\.test

  * 则从 [Stop] 一行开始，下面到 [Stop End] 之间的数据都将不会被读取
  * 即实际有效的数据区域是：

    [Hosts]
    ::1|::2|::3 .*\.test\.test
    ::4|::5|::6 .*\.test

    [Local Hosts]
    .*\.test\.test
    .*\.test


* Dnsmasq Address - Dnsmasq 兼容地址格式
  * Address 兼容格式适用于 Hosts/CNAME Hosts - 主要 Hosts 列表/CNAME Hosts 列表
  * 有效参数格式：
    * 前缀支持 --ADDRESS=/ 或 --Address=/ 或 --address=/ 或 ADDRESS=/ 或 Address=/ 或 address=/
    * 普通域名字符串匹配模式为 "Address=/域名后缀/(地址)"（不含引号，括号内为可选项目），域名后缀如果只填入 "#" 则表示匹配所有域名
    * 正则表达式模式为 "Address=/:正则表达式:/(地址)"（不含引号，括号内为可选项目）
    * 地址部分如果留空不填，则相当于 Banned - 黑名单条目
  * 例如以下 [Hosts] 条目是完全等价的：

    Address=/:.*\btest:/127.0.0.1
    Address=/test/127.0.0.1

  * 匹配所有域名的解析结果到 ::1

    Address=/#/::1

  * 对符合规则的域名返回域名不存在信息

    Address=/test/


* Dnsmasq Server - Dnsmasq 兼容服务器格式
  * 要使用本功能，必须将配置文件内的 Local Hosts 选项打开！
  * Server 兼容格式适用于 Local Hosts - 境内 DNS 解析域名列表
  * 有效参数格式：
    * 前缀支持 --SERVER=/ 或 --Server=/ 或 --server=/ 或 SERVER=/ 或 Server=/ 或 server=/
    * 普通域名字符串匹配模式为 "Server=/(域名后缀)/(指定进行解析的 DNS 地址(#端口))"（不含引号，括号内为可选项目）
    * 正则表达式模式为 "Server=/(:正则表达式:)/(指定进行解析的 DNS 地址(#端口))"（不含引号，括号内为可选项目）
    * 域名后缀或者 :正则表达式: 部分留空不填，相当于匹配不符合标准的域名，例如没有任何 . 的域名
    * 指定进行解析的 DNS 地址如果留空不填，则相当于使用程序配置文件指定的默认 DNS 服务器进行解析
    * 指定进行解析的 DNS 地址部分只填入 "#" 相当于 Whitelist - 白名单条目
  * 例如以下 [Local Hosts] 条目是完全等价的：

    Server=/:.*\btest:/::1#53
    Server=/test/::1

  * 对符合规则的域名使用程序配置文件指定的默认 DNS 服务器进行解析

    Server=/test/

  * 不符合标准的域名全部发往 127.0.0.1 进行解析

    Server=//127.0.0.1


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


* Local Routing - 境内路由表区域
当 Local Routing 为开启时，将检查本列表的路由表是否命中，检查与否与域名请求是否使用 Local 服务器有关，路由表命中后会直接返回结果，命中失败将丢弃解析结果并向境外服务器再次发起请求
有效参数格式为 "地址块/网络前缀长度"（不含引号）
  * 本路由表支持 IPv4 和 IPv6 协议
  * IPv4 时网络前缀长度范围为 1-32，IPv6 时网络前缀长度范围为 1-128


* Stop - 临时停止读取标签
  * 详细介绍参见上文对本功能的介绍


-------------------------------------------------------------------------------


配置文件自动刷新支持参数列表：

* 以下列表中的参数在写入配置文件后会自动刷新而无须重新启动程序，其它参数的刷新则必须重新启动程序
* 如非必要建议不要依赖程序的自动刷新功能，强烈建议修改配置文件后重新启动程序！

* Version
* File Refresh Time
* Print Log Level
* Log Maximum Size
* IPFilter Type
* IPFilter Level
* Accept Type
* Direct Request
* Default TTL
* Local Protocol
* Local Force Request
* Thread Pool Reset Time
* IPv4 Packet TTL
* IPv4 Main DNS TTL
* IPv4 Alternate DNS TTL
* IPv6 Packet Hop Limits
* IPv6 Main DNS Hop Limits
* IPv6 Alternate DNS Hop Limits
* HopLimits Fluctuation
* Reliable Once Socket Timeout
* Reliable Serial Socket Timeout
* Unreliable Once Socket Timeout
* Unreliable Serial Socket Timeout
* Receive Waiting
* ICMP Test
* Domain Test
* Multiple Request Times
* Domain Case Conversion
* IPv4 Do Not Fragment
* IPv4 Data Filter
* TCP Data Filter
* DNS Data Filter
* Strict Resource Record TTL Filter
* SOCKS Target Server
* SOCKS Username
* SOCKS Password
* HTTP CONNECT Target Server
* HTTP CONNECT TLS Version
* HTTP CONNECT TLS Validation
* HTTP CONNECT Version
* HTTP CONNECT Header Field
* HTTP CONNECT Proxy Authorization
* DNSCurve Reliable Socket Timeout
* DNSCurve Unreliable Socket Timeout
* DNSCurve Key Recheck Time
* DNSCurve Client Public Key
* DNSCurve Client Secret Key
* DNSCurve IPv4 Main DNS Public Key
* DNSCurve IPv4 Alternate DNS Public Key
* DNSCurve IPv6 Main DNS Public Key
* DNSCurve IPv6 Alternate DNS Public Key
* DNSCurve IPv4 Main DNS Fingerprint
* DNSCurve IPv4 Alternate DNS Fingerprint
* DNSCurve IPv6 Main DNS Fingerprint
* DNSCurve IPv6 Alternate DNS Fingerprint
* DNSCurve IPv4 Main Receive Magic Number
* DNSCurve IPv4 Alternate Receive Magic Number
* DNSCurve IPv6 Main Receive Magic Number
* DNSCurve IPv6 Alternate Receive Magic Number
* DNSCurve IPv4 Main DNS Magic Number
* DNSCurve IPv4 Alternate DNS Magic Number
* DNSCurve IPv6 Main DNS Magic Number
* DNSCurve IPv6 Alternate DNS Magic Number
