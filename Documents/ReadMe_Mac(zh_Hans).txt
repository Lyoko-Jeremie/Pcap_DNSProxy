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
3.编辑 PcapDNSProxyService.plist
  * 在 <key>Program</key> 下方 <string></string> 标签内填入 "程序所在的完整路径/程序名称"（不含引号）
  * 在 <key>WorkingDirectory</key> 下方 <string></string> 标签内填入 "程序所在的完整路径"（不含引号）
5.打开终端，使用 sudo -i 获得 root 权限并进入 Mac 目录内：
  * 使用 chmod 777 Build_Mac.sh 使服务安装脚本获得可执行权限
  * 使用 ./Build_Mac.sh 执行服务安装脚本
    * 脚本所进行的操作：
      * 将位于 /Library/LaunchDaemons 目录的 PcapDNSProxyService.plist 所有者更改为 root
      * 装载并启动守护进程服务
  * 以后每次开机在登录前守护进程服务都将自动启动
6.打开 "系统偏好设置" 窗口
  * 进入 "网络" 部分
  * 选中使用的网络适配器，点击 "高级" 按钮
  * 切换到 "DNS" 选项卡，并点击 "DNS服务器" 下的 "+" 号
  * 输入 127.0.0.1(IPv4)/::1(IPv6)
  * 按 "好" 再按 "应用" 即可


-------------------------------------------------------------------------------


卸载方法（整个过程均需以 root 权限进行）：

1.还原系统网络配置
2.打开终端
3.使用 sudo -i 命令获得 root 权限，然后使用 cd /Library/LaunchDaemons 进入自启动守护进程目录
4.使用 launchctl unload PcapDNSProxyService.plist 停止并卸载守护进程
5.使用 rm -rf PcapDNSProxyService.plist 命令或直接将 PcapDNSProxyService.plist 拖入废纸篓删除
6.删除所有 Pcap_DNSProxy 相关文件


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
