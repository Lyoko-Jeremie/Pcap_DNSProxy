Pcap_DNSProxy 项目的 GitHub 页面：

* 主分支: https://github.com/chengr28/Pcap_DNSProxy
* Release 分支: https://github.com/chengr28/Pcap_DNSProxy/tree/Release

Pcap_DNSProxy 项目的 Sourceforge 页面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程序以及配置的详细情况，参见 ReadMe(...).txt

  
-------------------------------------------------------------------------------


安装方法：

1.访问 https://github.com/chengr28/Pcap_DNSProxy/tree/Release 使用 GitHub 的 Download ZIP 功能将所有文件下载到本地
2.打开下载回来的 ZIP 文件，将 Mac 目录解压到磁盘的任意位置
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


卸载方法：

1.还原系统网络配置
2.打开终端，使用 sudo -i 获得 root 权限并进入 Mac 目录内
3.使用 ./Mac_Uninstall.sh 执行服务卸载脚本
  * 脚本所进行的操作：
    * 停止并卸载守护进程服务
    * 删除 plist 配置文件
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
