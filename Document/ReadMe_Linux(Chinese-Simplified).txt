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


Pcap_DNSProxy(Linux) 是一个基于LibPcap制作的用于忽略DNS投毒污染的小工具，后期也加入了对包含正则表达式的Hosts的支持
现在网络上有很多使用TCP协议进行解析的工具，以此来躲避DNS投毒污染。但事实上已经出现有使用TCP协议请求域名解析时被RESET/连接重置的情况，而使用UDP协议则又会被DNS投毒污染，导致始终无法获得正确的域名解析。本工具主要工作在UDP协议上，可以将伪造的数据包完全过滤，同时UDP协议比起TCP协议更具有占用资源低和发送转发接收速度快等特点。本工具同时也支持使用TCP协议进行请求，而且在被连接重置时会自动切换到UDP协议，可以使请求者获得正确的域名解析
而支持正则表达式的Hosts，则可以为使用者提供更加便捷的途径设定域名所对应的地址，避免修改系统文件的麻烦
本工具使用 C/C++ 编写而成，使用 GCC 4.7.2/g++ 进行编译，完全支持 Unicode

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
* 支持编译所需依赖包的Linux发行版
* 支持最新版本 Libpcap (http://www.tcpdump.org)
* 网络设备类型为 Ethernet 或直接使用 PPPoE 协议均可
* 本工具只支持原生IPv4/IPv6网络，非原生IPv6切勿开启IPv6功能


-------------------------------------------------------------------------------


安装方法（整个过程均需以 root 权限进行）：
安装过程比较漫长而且操作比较复杂，请给予一定的耐心同时严格按照说明操作！

1.预备程序编译环境：编译前需要先编译和安装依赖的库
  * 访问 http://www.tcpdump.org/#latest-release 下载最新的 LibPcap 库源代码，或者可以直接使用本项目提供的源代码压缩包
  * 访问 https://github.com/chengr28/pcap_dnsproxy/branches 随便选择一个 Release 分支（两个分支的Linux版压缩包都是相同的文件）
    * 使用 Download ZIP 并解压，Linux目录内即为 LibPcap 库和 Pcap_DNSProxy(Linux) 源代码的压缩包
  * Pcap_DNSProxy(Linux) 依赖于 GCC(C++/g++，需要支持 C++ 11 标准的版本) 和 LibPcap 库，编译前需要先安装依赖库
  * LibPcap 库依赖于GCC库、bison库、m4库、flex库和 libpcap-dev 库，可使用发行版自带包管理系统自动安装或手动前往官方网站下载编译安装
  * 编译安装 LibPcap 库（当然也可以使用系统自带的包管理系统安装，更多详情可参见所使用Linux发行版的说明），Release(_x86/_x64)分支内含 LibPcap 源代码的压缩包，安装过程：
    * 使用 su/sudo 命令获得 root 权限，并使用 root 权限解压压缩包到任何位置，进入解压生成的文件夹
    * 使用 ./configure 生成 Makefile，使用 make 编译 LibPcap 库，使用 make install 安装 LibPcap 库
	* 使用 man pcap 确认 LibPcap 库安装成功。如果安装成功，应该会显示类似：

	  PCAP(3PCAP)               ...               PCAP(3PCAP)
	  NAME
	  pcap - Packet Capture library
	  SYNOPSIS
	  #include <pcap/pcap.h>
	  ...
	
	* 即为安装成功。如果出现无法找到命令等情况，请检查系统平台是否受 LibPcap 库支持或依赖包安装是否成功
  * LibPcap 库安装成功后解压出来的文件夹/文件即可删除

2.编译 Pcap_DNSProxy(Linux) 程序（如果是下载的可执行文件可跳过这步）
  * 切勿更改源代码的编码(UTF-8/without BOM)和换行格式(UNIX/LF)
  * 使用 su/sudo 命令获得 root 权限，解压 Pcap_DNSProxy(Linux) 源代码压缩包并进入 Pcap_DNSProxy 目录
  * 直接使用 make 命令编译即可。Makefile 所进行的操作：
    * 为目标文件创建文件夹
	* 编译源代码并链接生成程序
	* 将 PcapDNSProxyService 脚本所有者更改为 root 同时赋予 777/rwxrwxrwx 权限
	* 清理所有目标文件

3.调整可执行程序的属性（如果是自行编译的程序可跳过这步）
  * 使用 su/sudo 命令获得 root 权限，解压 Pcap_DNSProxy(Linux) 的Release压缩包并进入 Pcap_DNSProxy 目录
  * 使用 chmod 777 PcapDNSProxyService 赋予脚本 777/rwxrwxrwx 权限
  * 使用 chown root:root PcapDNSProxyService 将脚本所有者更改为 root


4.配置 Pcap_DNSProxy(Linux) 服务
注意：由于不同的Linux发行版对系统服务和守护进程的处理方式不同，本部分仅供参考，更多详情可参见所使用Linux发行版的说明
  * 附带的脚本适用于 Linux Debian 6.0 官方发行版以及更新版本系统环境，测试通过可以直接使用
  * Linux Debian 系列：官方发行版 6.0 以上版本使用 insserv 管理系统服务，6.0 以下版本需要使用 update-rc.d 管理系统服务，参见 https://wiki.debian.org/Daemon
  * Linux Red Hat 和 openSUSE 系列：使用 chkconfig 管理系统服务，参见 https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/s2-services-chkconfig.html
  * 如果需要自己编写服务启动脚本，请注意 Pcap_DNSProxy(Linux) 服务需要在以下模块初始化之后才能正常使用，建议尽量将优先级降低，否则将生成错误报告并直接退出：
	  * 需要在挂载所有文件系统后
	  * 需要初始化系统日志后
	  * 需要在启动网络服务以及网络设备器初始化完毕后
	  * 需要在系统时间被设置后
	  * 需要在本机名称被设置后
  * 直接使用脚本配置的步骤：
    * 首先需要编辑 PcapDNSProxyService 脚本，其中 NAME 项为程序的名称，PATH 项为程序的路径
    * 使用 su/sudo 命令获得 root 权限，进入 Pcap_DNSProxy 目录
	* 使用 "ln -s 脚本所在目录/PcapDNSProxyService /etc/init.d"（不含引号和括号，注意空格）在系统启动服务目录创建脚本的软链接
	* 将终端切换到 /etc/init.d 目录下，使用 insserv PcapDNSProxyService 注册服务
	* 运行 sh PcapDNSProxyService start 或直接使用 service PcapDNSProxyService start 启动 Pcap_DNSProxy(Linux) 服务
	* 以后每次系统启动都将自动运行脚本启动服务
	* 可直接输入 sh PcapDNSProxyService 不带参数查询用法
	  * start - 启动服务
	  * stop - 停止服务
	  * force-reload/restart - 重启服务
	  * status - 服务状态。如果PID为空则服务未启动

5.配置系统DNS服务器设置
  * 可参见 https://developers.google.com/speed/public-dns/docs/using 中 Changing your DNS servers settings 中 Linux 一节
  * 图形界面以 GNOME 为例：
    * 进入 系统设置 - 网络 或直接点击 网络 打开设置界面
	* 选中需要设置的网络连接，打开 选项 - IPv4/IPv6设置
	* 在 DNS服务器 填入 127.0.0.1(IPv4)/::1(IPv6) 保存即可
	* 如果使用了DHCP自动获取网络信息，则需要将 方法 选为 自动(DHCP)仅地址(IPv4)/自动，仅地址(IPv6) 才能填入 DNS服务器
  * 直接修改系统文件修改DNS服务器设置：
    * 自动获取地址(DHCP)时：
	  * 使用 su/sudo 命令获得 root 权限，进入 /etc/dhcp 或 /etc/dhcp3 目录（看具体哪个目录存在 dhclient.conf 文件）
	  * 直接修改 dhclient.conf 文件，修改或添加 prepend domain-name-servers 一项即可
	  * 如果 prepend domain-name-servers 一项被 # 注释则需要把注释去掉以使配置生效，不需要添加新的条目
	  * dhclient.conf 文件可能存在多个 prepend domain-name-servers 项，是各个网络接口的配置项目，直接修改总的配置项目即可
	  * 使用 service network(/networking) restart 或 ipdown/ipup 或 ifcondig stop/start 重启网络服务/网络端口
    * 非自动获取地址(DHCP)时：
	  * 使用 su/sudo 命令获得 root 权限，进入 /etc 目录
	  * 直接修改 resolv.conf 文件里的 nameserver 即可
	  * 如果重启后配置被覆盖，则需要修改或新建 /etc/resolvconf/resolv.conf.d 文件，内容和 resolv.conf 一样
	  * 使用 service network(/networking) restart 或 ipdown/ipup 或 ifcondig stop/start 重启网络服务/网络端口


-------------------------------------------------------------------------------


卸载方法（整个过程均需以 root 权限进行）：
注意：由于不同的Linux发行版对系统服务和守护进程的处理方式不同，本部分仅供参考，更多详情可参见所使用Linux发行版的说明

1.还原系统网络配置
  * 将所有修改过的文件恢复原状即可，参见 安装方法 一节
2.停止服务
  * 使用 su/sudo 命令获得 root 权限，然后使用 service PcapDNSProxyService stop 停止服务
3.删除服务
  * 切换到 /etc/init.d 目录，使用 insserv -r PcapDNSProxyService 删除服务
  * 使用 rm PcapDNSProxyService 删除脚本的软链接
4.删除所有 Pcap_DNSProxy(Linux) 相关文件


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

4.如非以上结果，请移步 Linux 版 FAQ 文档中 运行结果分析 一节


-------------------------------------------------------------------------------


注意事项：

* 请务必设置一个正确的、有效的、可以正常使用的境外DNS服务器！
* 配置文件和错误报告所在的目录以上文 安装方法 一节中第3步注册的服务信息为准，注意填写时一行不要超过2048字节/2KB
* 服务启动前请先确认没有其它本地DNS服务器运行或本工具多个拷贝在运行中，否则可能会导致监听冲突无法正常工作
  * 监听冲突会生成错误报告，可留意 Socket 相关的错误（参见 Linux 版 FAQ 文档 Error.log 详细错误报告 一节）
* 杀毒软件/第三方防火墙可能会阻止本程序的操作，请将行为全部允许或将本程序加入到白名单中
* 重启服务，以 root 权限使用 service PcapDNSProxyService force-reload 或 service PcapDNSProxyService restart 即可
* 更新程序
  * 如非更新日志有需要更新配置文件/Hosts文件的提示，否则更新程序均仅需重新编译可执行程序
    * 如更新日志有需要更新配置文件/Hosts文件的提示，请将这2个文件内的运行参数/Hosts记录下来并填入新的配置文件/Hosts文件内
	* 注意切勿直接覆盖，否则可能会造成错误
  * 先停止服务，并将旧版本的 Source 目录和可执行文件删除
  * 将新版本的 Source 放入相同的位置，按照 安装方法 一节中 编译 Pcap_DNSProxy(Linux) 程序 重新编译可执行程序
  * 以 root 权限使用 service PcapDNSProxyService start 启动服务即可
* 文件夹和程序的名称可以随意更改，但请务必在进行安装方法第3步前完成。如果服务注册后需移动工具文件夹的路径，则需要:
  * 停止服务
  * 移动工具文件夹
  * 重复 安装方法 中的第3步操作
* 安装/卸载某些软件可能会导致网络设配器离线使LibPcap模块返回，网络设配器离线又重新启动后请重启服务
* 关于请求域名解析的优先级
  * 使用系统API函数进行域名解析（大部分）：系统 Hosts > Pcap_DNSProxy 的 Hosts.ini（Whitelist/白名单条目 > Local Hosts/境内DNS解析域名列表 > Hosts/主要Hosts列表） > 远程DNS服务器
  * 直接使用网络适配器设置进行域名解析（小部分）：Pcap_DNSProxy 的 Hosts.ini（Whitelist/白名单条目 > Local Hosts/境内DNS解析域名列表 > Hosts/主要Hosts列表） > 远程DNS服务器
* Config.conf 详细参数 和 Hosts.conf 格式说明 和Windows版一样，参见主 ReadMe 文档
