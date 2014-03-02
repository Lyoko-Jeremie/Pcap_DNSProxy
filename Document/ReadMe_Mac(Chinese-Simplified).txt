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


Pcap_DNSProxy(Mac) 是一个基于LibPcap制作的用于忽略DNS投毒污染的小工具，后期也加入了对包含正则表达式的Hosts的支持
现在网络上有很多使用TCP协议进行解析的工具，以此来躲避DNS投毒污染。但事实上已经出现有使用TCP协议请求域名解析时被RESET/连接重置的情况，而使用UDP协议则又会被DNS投毒污染，导致始终无法获得正确的域名解析。本工具主要工作在UDP协议上，可以将伪造的数据包完全过滤，同时UDP协议比起TCP协议更具有占用资源低和发送转发接收速度快等特点。本工具同时也支持使用TCP协议进行请求，而且在被连接重置时会自动切换到UDP协议，可以使请求者获得正确的域名解析
而支持正则表达式的Hosts，则可以为使用者提供更加便捷的途径设定域名所对应的地址，避免修改系统文件的麻烦
本工具使用 C/C++ 编写而成，使用 Xcode 5.0.1/Apple LLVM 5.0 进行编译，完全支持 Unicode

Pcap_DNSProxy 的特点：
* 同时支持IPv4/IPv6协议，也可单独开启
* 同时支持TCP/UDP协议
* 作为服务工作于系统底层
* 多线程模型
* 正则表达式支持由系统自带的正则库提供
* 使用LibPcap利用系统底层驱动抓取数据包，多种过滤方式忽略接收到的伪造数据包
* 支持服务器模式，相当于搭建了一个小型的DNS服务器，能为其他设备提供解析服务
* 支持境内DNS服务器解析，可提高境内服务器的访问速度
* 丰富的配置选项，配置和Hosts文件支持 ANSI、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 编码以及 Windows/Unix/Macintosh 换行格式
* 错误报告功能

Pcap_DNSProxy(Linux) 支持平台：
* 采用Intel平台处理器的 Mac OS X 10.5 Leopard 以及更新的版本
* 网络设备类型为 Ethernet 或直接使用 PPPoE 协议均可
* 本工具只支持原生IPv4/IPv6网络，非原生IPv6切勿开启IPv6功能


-------------------------------------------------------------------------------


安装方法：

1.访问 https://github.com/chengr28/pcap_dnsproxy/branches 随便选择一个Release版本，并使用GitHub的 Download ZIP 功能将所有文件下载到本地
  * Mac的Release版本为 Intel x86/x64 Universal 格式，32位和64位系统均可直接使用
2.打开下载回来的ZIP文件，将 Mac 目录解压到磁盘的任意位置
  * 目录和程序的名称可以随意更改
3.打开 PcapDNSProxyService.plist
  * 在 <key>Program</key> 下面的 <string> </string> 标签内填入程序所在的完整路径+程序名称（不含空格）
  * 在 <key>WorkingDirectory</key> 下面的 <string> </string> 标签内填入程序所在的完整路径（不含空格）
4.将 PcapDNSProxyService.plist 复制到 /Library/LaunchDaemons 目录内（需要 root 权限）
5.打开终端：
  * 使用 sudo -i 获得 root 权限，然后使用 cd /Library/LaunchDaemons 进入自启动守护进程目录
  * 使用 chown root PcapDNSProxyService.plist 将其所有者更改为 root
  * 使用 launchctl load PcapDNSProxyService.plist 装载并启动守护进程
  * 以后每次开机在登录前守护进程都将自动启动
6.打开 系统偏好设置 窗口
  * 进入 网络 部分
  * 选中使用的网络适配器，点击 高级 按钮
  * 切换到 DNS 选项卡，并点击 DNS服务器 下的 + 号
  * 输入 127.0.0.1(IPv4)/::1(IPv6)
  * 按 好 再按 应用 即可


-------------------------------------------------------------------------------


卸载方法（整个过程均需以 root 权限进行）：

1.还原系统网络配置
2.打开终端
3.使用 sudo -i 命令获得 root 权限，然后使用 cd /Library/LaunchDaemons 进入自启动守护进程目录
4.使用 launchctl unload PcapDNSProxyService.plist 停止并卸载守护进程
5.使用 rm PcapDNSProxyService.plist 命令或直接将 PcapDNSProxyService.plist 拖入废纸篓删除（需要 root 权限）
6.删除所有 Pcap_DNSProxy(Mac) 相关文件


-------------------------------------------------------------------------------


正常工作查看方法：

1.打开终端
2.输入 dig www.google.com 并回车
3.运行结果应类似：

   >dig www.google.com
   ; (1 server found)
   ;; global options: +cmd
   ;; Got answer:
   ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
   ;; flags: ...; QUERY: ..., ANSWER: ..., AUTHORITY: ..., ADDITIONAL: ...

   ;; QUESTION SECTION:
   ;www.google.com.            IN    A

   ;; ANSWER SECTION:
   ...

   ;; Query time: ... msec
   ;; SERVER: 127.0.0.1#53(127.0.0.1)（IPv4，IPv6下为 ::1 ）
   ;; WHEN: ...
   ;; MSG SIZE  rcvd: ...

4.如非以上结果，请移步 Mac 版 FAQ 文档中 运行结果分析 一节


-------------------------------------------------------------------------------


注意事项：

* 请务必设置一个正确的、有效的、可以正常使用的境外DNS服务器！
* 配置文件和错误报告所在的目录以上文 安装方法 一节中第3步注册的服务信息为准，注意填写时一行不要超过2048字节/2KB
* 服务启动前请先确认没有其它本地DNS服务器运行或本工具多个拷贝在运行中，否则可能会导致监听冲突无法正常工作
  * 监听冲突会生成错误报告，可留意 Socket 相关的错误（参见 Mac 版 FAQ 文档 Error.log 详细错误报告 一节）
* 杀毒软件/第三方防火墙可能会阻止本程序的操作，请将行为全部允许或将本程序加入到白名单中
* 重启服务
  * 打开终端，使用 sudo -i 命令获得 root 权限
  * 使用 cd /Library/LaunchDaemons 进入自启动守护进程目录
  * 使用 launchctl unload PcapDNSProxyService.plist 停止守护进程
  * 使用 launchctl load PcapDNSProxyService.plist 启动守护进程
* 更新程序
  * 如非更新日志有需要更新配置文件/Hosts文件的提示，否则更新程序均仅需重新编译可执行程序
    * 如更新日志有需要更新配置文件/Hosts文件的提示，请将这2个文件内的运行参数/Hosts记录下来并填入新的配置文件/Hosts文件内
	* 注意切勿直接覆盖，否则可能会造成错误
  * 先停止服务，并将旧版可执行文件删除
    * 打开终端，使用 sudo -i 命令获得 root 权限
    * 使用 cd /Library/LaunchDaemons 进入自启动守护进程目录
    * 使用 launchctl unload PcapDNSProxyService.plist 停止守护进程
  * 将新版本的 可执行文件 放入相同的位置
  * 启动服务
    * 打开终端，使用 sudo -i 命令获得 root 权限
    * 使用 cd /Library/LaunchDaemons 进入自启动守护进程目录
    * 使用 launchctl load PcapDNSProxyService.plist 启动守护进程
* 文件夹和程序的名称可以随意更改，但请务必在进行安装方法第3步前完成。如果服务注册后需移动工具文件夹的路径，则需要:
  * 停止服务
  * 移动工具文件夹
  * 重复 安装方法 中的第3步操作
* 安装/卸载某些软件可能会导致网络设配器离线使LibPcap模块返回，网络设配器离线又重新启动后请重启服务
* 关于请求域名解析的优先级
  * 使用系统API函数进行域名解析（大部分）：系统 Hosts > Pcap_DNSProxy 的 Hosts.ini（Whitelist/白名单条目 > Local Hosts/境内DNS解析域名列表 > Hosts/主要Hosts列表） > 远程DNS服务器
  * 直接使用网络适配器设置进行域名解析（小部分）：Pcap_DNSProxy 的 Hosts.ini（Whitelist/白名单条目 > Local Hosts/境内DNS解析域名列表 > Hosts/主要Hosts列表） > 远程DNS服务器
* Config.conf 详细参数 和 Hosts.conf 格式说明 和Windows版一样，参见主 ReadMe 文档
