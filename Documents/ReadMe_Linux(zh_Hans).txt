Pcap_DNSProxy 项目的 GitHub 页面：

* 主分支: https://github.com/chengr28/Pcap_DNSProxy
* Release 分支: https://github.com/chengr28/Pcap_DNSProxy/tree/Release

Pcap_DNSProxy 项目的 Sourceforge 页面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程序以及配置的详细情况，参见 ReadMe(...).txt


-------------------------------------------------------------------------------


安装方法：
安装过程比较漫长而且操作比较复杂，请给予一定的耐心按照说明操作！

1.准备程序编译环境：编译前需要使用包管理工具安装，或者需要自行编译和安装依赖库
  * 依赖工具/库列表：
    * GCC/g++ 可访问 https://gcc.gnu.org 获取
      * GCC 最低版本要求为 4.9 从此版本开始 GCC 完整支持 C++ 11 标准，4.9 之前的版本对 C++ 11 标准的实现有问题
      * GCC 当前版本可使用 gcc --version 查看，使用旧版本 GCC 强行编译可能会出现无法预料的问题！
    * Bison 可访问 https://www.gnu.org/software/bison 获取
    * M4 可访问 https://www.gnu.org/software/m4 获取
    * Flex 可访问 http://flex.sourceforge.net 获取
    * CMake 可访问 http://www.cmake.org 获取
    * LibPcap 可访问 http://www.tcpdump.org/#latest-release 获取
      * 获得 root 权限后使用 ./configure -> make -> make install 即可
      * 部分 Linux 发行版可能还需要 LibPcap-Dev 工具的支持
    * Libsodium 可访问 https://github.com/jedisct1/libsodium 获取
      * 编译时如果剥离 Libsodium 的依赖则可跳过编译和安装下表的依赖库和工具，具体参见下文的介绍，不建议使用
      * Libsodium 的编译和安装依赖 Automake/Autoconf 套装工具：
        * aclocal
        * autoscan
        * autoconf 可访问 https://www.gnu.org/software/autoconf 获取
        * autoheader
        * automake 可访问 https://www.gnu.org/software/automake 获取
        * libtool 可访问 https://www.gnu.org/software/libtool 获取
      * 获得 root 权限后进入目录，运行 ./autogen.sh -> ./configure -> make -> make install 即可
      * 部分 Linux 发行版可能还需要 Libsodium-Dev 工具的支持
      * 部分 Linux 发行版可能还需要运行 ldconfig 刷新系统的库缓存

2.编译 Pcap_DNSProxy 程序并配置程序属性
  * 切勿更改脚本的换行格式 (UNIX/LF)
  * 使用终端进入 Source/Scripts 目录，使用 chmod 755 Linux_Build.sh 使脚本获得执行权限
  * 使用 ./Linux_Build.sh 执行编译程序
    * 添加参数 --enable-static 即 ./Linux_Build.sh --enable-static 可启用静态编译
    * 脚本所进行的操作：
      * CMake 将编译并在 Release 目录生成 Pcap_DNSProxy 和 KeyPairGenerator 程序
      * 设置 Pcap_DNSProxy 和 KeyPairGenerator 程序以及 PcapDNSProxyService 和 Pcap_DNSProxy.service 服务控制脚本的基本读写可执行权限
      * 设置 Linux_(Un)Install.Systemd.sh 以及 Linux_(Un)Install.SysV.sh 服务控制安装脚本的基本读写可执行权限
      * 从 ExampleConfig 复制默认配置文件到 Release 目录
    * 执行时使用 ./Linux_Build.sh --disable-libsodium 可剥离 Libsodium 的依赖，不建议使用
      * 剥离后编译时将不需要 Libsodium 库的支持
      * 剥离后程序将完全失去支持 DNSCurve/DNSCrypt 协议的功能，且运行时将不会产生任何错误提示，慎用！

3.配置系统守护进程服务
  * 由于不同的 Linux 发行版对系统服务和守护进程的处理方式不同，本步仅供参考
    * 附带的 Linux_Install.Systemd.sh 脚本适用于默认使用 Systemd Init 的系统
      * Linux Debian 8.x 官方发行版以及更新版本系统环境，经测试可直接使用
    * 附带的 Linux_Install.SysV.sh 脚本适用于默认使用 System V Init 的系统
      * Linux Debian 6.x - 7.x 官方发行版系统环境，经测试可直接使用
    * 更多详情可参见下文其它 Linux 发行版服务的说明，以及所使用 Linux 发行版的官方说明
  * 使用 Systemd Init 时：
    * 进入 Release 目录并编辑 Pcap_DNSProxy.service 文件，编辑完成后保存： 
      * WorkingDirectory= 项为程序所在目录的绝对路径
      * ExecStart= 项为程序所在目录的绝对路径，并在最后加上程序的名称
    * 在 root 权限下使用 ./Linux_Install.Systemd.sh 执行服务安装脚本，脚本所进行的操作：
      * 将 Pcap_DNSProxy.service 服务控制脚本的所有者更改为 root
      * 安装服务控制脚本到 /etc/systemd/system 目录中
      * 尝试启动 Pcap_DNSProxy 服务，并显示执行操作后服务的状态
      * 以后每次系统启动都将自动启动服务
    * 更多 Systemd 服务控制的方法，参见各 Linux 发行版官方文档的说明
  * 使用 System V Init 时：
    * 进入 Release 目录并编辑 PcapDNSProxyService 文件，编辑完成后保存：
      * NAME 项为程序的名称
      * PATH 项为程序的绝对路径
    * 在 root 权限下使用 ./Linux_Install.SysV.sh 执行服务安装脚本，脚本所进行的操作：
      * 将 PcapDNSProxyService 服务控制脚本的所有者更改为 root
      * 安装服务控制脚本到 /etc/init.d 目录中
      * 尝试启动 PcapDNSProxyService 服务，并显示执行操作后服务的状态
      * 以后每次系统启动都将自动运行脚本启动服务
    * 可直接输入 sh PcapDNSProxyService 不带参数查询用法
      * start - 启动服务
      * stop - 停止服务
      * force-reload/restart - 重启服务
      * status - 服务状态，如果 PID 为空则服务未启动

4.配置系统 DNS 服务器设置
  * 可参见 https://developers.google.com/speed/public-dns/docs/using 中 Changing your DNS servers settings 中 Linux 一节
  * 图形界面以 GNOME 3 为例：
    * 打开所有程序列表，并 -> 设置 - 硬件分类 - 网络
    * 如果要对当前的网络配置进行编辑 -> 单击齿轮按钮
    * 选中 IPv4
      * DNS 栏目中，将自动拨向关闭
      * 在服务器中填入 127.0.0.1 并应用
    * 选中 IPv6
      * DNS 栏目中，将自动拨向关闭
      * 在服务器中填入 ::1 并应用
    * 请务必确保只填入这两个地址，填入其它地址可能会导致系统选择其它 DNS 服务器绕过程序的代理
    * 重启网络连接
  * 直接修改系统文件修改 DNS 服务器设置：
    * 自动获取地址(DHCP)时：
      * 以 root 权限进入 /etc/dhcp 或 /etc/dhcp3 目录（视乎 dhclient.conf 文件位置）
      * 直接修改 dhclient.conf 文件，修改或添加 prepend domain-name-servers 一项即可
      * 如果 prepend domain-name-servers 一项被 # 注释则需要把注释去掉以使配置生效，不需要添加新的条目
      * dhclient.conf 文件可能存在多个 prepend domain-name-servers 项，是各个网络接口的配置项目，直接修改总的配置项目即可
      * 使用 service network(/networking) restart 或 ipdown/ipup 或 ifcondig stop/start 重启网络服务/网络端口
    * 非自动获取地址(DHCP)时：
      * 以 root 权限进入 /etc 目录
      * 直接修改 resolv.conf 文件里的 nameserver 即可
      * 如果重启后配置被覆盖，则需要修改或新建 /etc/resolvconf/resolv.conf.d 文件，内容和 resolv.conf 一样
      * 使用 service network(/networking) restart 或 ipdown/ipup 或 ifcondig stop/start 重启网络服务/网络端口


-------------------------------------------------------------------------------


卸载方法：
* 由于不同的 Linux 发行版对系统服务和守护进程的处理方式不同，本步仅供参考

1.还原系统网络配置
2.以 root 权限进入 Release 目录，执行 ./Linux_Uninstall.Systemd.sh 或 ./Linux_Uninstall.SysV.sh
3.删除所有 Pcap_DNSProxy 相关文件


-------------------------------------------------------------------------------


建议的升级方法：

* Systemd 部分：
  1.打开终端，使用 sudo -i 获得 root 权限并进入 Release 目录内
  2.使用 ./Linux_Uninstall.Systemd.sh 执行服务卸载脚本
  3.备份所有配置文件，删除所有 Pcap_DNSProxy 相关文件
  4.按照安装方法重新部署 Pcap_DNSProxy
    * 进行第4步前先将备份的配置文件还原到 Release 目录内
    * Config.conf 文件建议按照备份的配置文件重新设置一次，如直接覆盖可能会导致没有新功能的选项
* SysV 部分：
  1.打开终端，使用 sudo -i 获得 root 权限并进入 Release 目录内
  2.使用 ./Linux_Uninstall.SysV.sh 执行服务卸载脚本
  3.备份所有配置文件，删除所有 Pcap_DNSProxy 相关文件
  4.按照安装方法重新部署 Pcap_DNSProxy
    * 进行第4步前先将备份的配置文件还原到 Release 目录内
    * Config.conf 文件建议按照备份的配置文件重新设置一次，如直接覆盖可能会导致没有新功能的选项


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
   ;; SERVER: ::1#53(::1)（IPv6，IPv4 下为 127.0.0.1）
   ;; WHEN: ...
   ;; MSG SIZE  rcvd: ...

4.如非以上结果，请移步 Linux 版 FAQ 文档中 运行结果分析 一节


-------------------------------------------------------------------------------


其它 Linux 发行版服务的说明：

* Linux Debian 系列：
  * 官方发行版 8.x 以及更新版本默认需要使用 Systemd 管理系统服务
  * 官方发行版 6.x - 7.x 版本默认需要使用 insserv 管理系统服务
  * 官方发行版 6.x 以下版本默认需要使用 update-rc.d 管理系统服务，参见 https://wiki.debian.org/Daemon
* Linux Red Hat 和 openSUSE 系列：
  * 使用 chkconfig 管理系统服务
  * 参见 https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/s2-services-chkconfig.html
* 如果需要自己编写服务启动脚本，请注意 Pcap_DNSProxyService 服务需要在以下模块初始化之后才能正常使用，建议尽量将优先级降低，否则将生成错误报告并直接退出：
  * 需要在挂载所有文件系统后
  * 需要初始化系统日志后
  * 需要在启动网络服务以及网络设备器初始化完毕后
  * 需要在系统时间被设置后
  * 需要在本机名称被设置后
* 也可直接将本程序加入启动项中，注意必须以 root 权限启动否则无法打开本地监听端口
  * 程序内置了设置守护进程的代码，启动后不会阻塞系统的运行
