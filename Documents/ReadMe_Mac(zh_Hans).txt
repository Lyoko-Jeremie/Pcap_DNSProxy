Pcap_DNSProxy 项目的 GitHub 页面：
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy 项目的 Sourceforge 页面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程序以及配置的详细情况，参见 ReadMe(...).txt

  
-------------------------------------------------------------------------------


安装方法（使用已编译好的二进制可执行文件）：

1.访问 https://github.com/chengr28/Pcap_DNSProxy/releases 将二进制可执行文件包下载到本地
2.打开下载回来的二进制可执行文件包，将 Mac 目录解压到磁盘的任意位置
3.编辑 pcap_dnsproxy.service.plist 文件
  * 清空 <string>/usr/local/opt/pcap_dnsproxy/bin/Pcap_DNSProxy</string> 标签内的内容，改为 "<string>程序所在的完整路径/程序名称</string>"（不含引号）
  * 清空 <string>/usr/local/etc/pcap_dnsproxy/</string> 标签内的内容，改为 "<string>程序所在的完整路径</string>"（不含引号）
4.打开终端，使用 sudo -i 获得 root 权限并进入 Mac 目录内：
  * 使用 chmod 755 Mac_Install.sh 使服务安装脚本获得可执行权限
  * 使用 ./Mac_Install.sh 执行服务安装脚本
    * 脚本所进行的操作：
      * 设置程序、脚本以及 plist 配置文件的基本读写执行权限
      * 装载并启动守护进程服务
  * 以后每次开机在登录前守护进程服务都将自动启动
5.打开 "系统偏好设置" 窗口
  * 进入 "网络" 部分
  * 选中使用的网络适配器，点击 "高级" 按钮
  * 切换到 "DNS" 选项卡，并点击 "DNS服务器" 下的 "+" 号
  * 输入 127.0.0.1(IPv4)/::1(IPv6)
    * 请务必确保只填入这两个地址，填入其它地址可能会导致系统选择其它 DNS 服务器绕过程序的代理
  * 按 "好" 再按 "应用" 即可


-------------------------------------------------------------------------------


安装方法（编译二进制可执行文件）：

1.准备程序编译环境
  * Homebrew 可访问 http://brew.sh 获取
  * CMake 可访问 https://cmake.org 或通过 Homebrew 获取
  * Libsodium 可访问 https://github.com/jedisct1/libsodium 获取
    * 编译时如果剥离 Libsodium 的依赖则可跳过编译和安装下表的依赖库和工具，具体参见下文的介绍，不建议使用
    * 获得 root 权限后进入目录，运行 ./autogen.sh -> ./configure -> make -> make install 即可

2.编译 Pcap_DNSProxy 程序并配置程序属性
  * 切勿更改脚本的换行格式 (UNIX/LF)
  * 使用终端进入 Source/Scripts 目录，使用 chmod 755 CMake_Build.sh 使脚本获得执行权限
  * 使用 ./CMake_Build.sh 执行编译程序
    * 添加参数 --enable-static 即 ./CMake_Build.sh --enable-static 可启用静态编译
    * 脚本所进行的操作：
      * CMake 将编译并在 Release 目录生成 Pcap_DNSProxy 程序
      * 设置 Pcap_DNSProxy 程序以及 pcap_dnsproxy.service.plist 服务控制脚本的基本读写可执行权限
      * 设置 Mac_(Un)Install.sh 服务控制安装脚本的基本读写可执行权
      * 从 ExampleConfig 复制默认配置文件到 Release 目录
    * 执行时使用 ./CMake_Build.sh --disable-libsodium 可剥离对 Libsodium 的依赖，不建议使用
      * 剥离后编译时将不需要 Libsodium 库的支持
      * 剥离后程序将完全失去支持 DNSCurve/DNSCrypt 协议的功能，且运行时将不会产生任何错误提示，慎用！

3.按照安装方法（使用已编译好的二进制可执行文件）中第3步的操作继续进行即可


-------------------------------------------------------------------------------


卸载方法：

1.还原系统网络配置
2.打开终端，使用 sudo -i 获得 root 权限并进入 Mac 目录内
3.使用 ./Mac_Uninstall.sh 执行服务卸载脚本
  * 脚本所进行的操作：停止并卸载守护进程服务，删除 plist 配置文件
4.删除所有 Pcap_DNSProxy 相关文件


-------------------------------------------------------------------------------


建议的升级方法：

1.打开终端，使用 sudo -i 获得 root 权限并进入 Mac 目录内
2.使用 ./Mac_Uninstall.sh 执行服务卸载脚本
3.备份所有配置文件，删除所有 Pcap_DNSProxy 相关文件
4.按照安装方法重新部署 Pcap_DNSProxy
  * 进行第4步前先将备份的配置文件还原到 Mac 目录内
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

4.如非以上结果，请移步 Mac 版 FAQ 文档中 运行结果分析 一节
