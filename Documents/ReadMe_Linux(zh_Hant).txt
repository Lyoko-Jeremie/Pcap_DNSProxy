Pcap_DNSProxy 專案的 GitHub 頁面：
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy 專案的 Sourceforge 頁面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程式以及配置的詳細情況，參見 ReadMe(...).txt


-------------------------------------------------------------------------------


安裝方法：
安裝過程比較漫長而且操作比較複雜，請給予一定的耐心按照說明操作！

1.準備程式編譯環境：編譯前需要使用包管理工具安裝，或者需要自行編譯和安裝依賴庫
  * 依賴工具/庫清單：
    * GCC/g++ 可訪問 https://gcc.gnu.org 獲取
      * GCC 建議最低版本為 4.9 從此版本開始 GCC 完整支援 C++ 11 標準，4.9 之前的版本對 C++ 11 標準的實現有問題
      * GCC 當前版本可使用 gcc --version 查看，使用舊版本 GCC 強行編譯可能會出現無法預料的問題！
    * Bison 可訪問 https://www.gnu.org/software/bison 獲取
    * M4 可訪問 https://www.gnu.org/software/m4 獲取
    * Flex 可訪問 http://flex.sourceforge.net 獲取
    * CMake 可訪問 https://cmake.org 獲取
    * LibPcap 可訪問 http://www.tcpdump.org/#latest-release 獲取
      * 獲得 root 許可權後使用 ./configure -> make -> make install 即可
      * 部分 Linux 發行版本可能還需要 LibPcap-Dev 工具的支援
    * Libsodium 可訪問 https://github.com/jedisct1/libsodium 獲取
      * 編譯時如果剝離 Libsodium 的依賴則可跳過編譯和安裝下表的依賴庫和工具，具體參見下文的介紹，不建議使用
      * Libsodium 的編譯和安裝依賴 Automake/Autoconf 套裝工具：
        * aclocal
        * autoscan
        * autoconf 可訪問 https://www.gnu.org/software/autoconf 獲取
        * autoheader
        * automake 可訪問 https://www.gnu.org/software/automake 獲取
        * libtool 可訪問 https://www.gnu.org/software/libtool 獲取
      * 獲得 root 許可權後進入目錄，運行 ./autogen.sh -> ./configure -> make -> make install 即可
      * 部分 Linux 發行版本可能還需要 Libsodium-Dev 工具的支援，以及運行 ldconfig 刷新系統庫緩存

2.編譯 Pcap_DNSProxy 程式並配置程式屬性
  * 切勿更改腳本的換行格式 (UNIX/LF)
  * 使用終端進入 Source/Scripts 目錄，使用 chmod 755 CMake_Build.sh 使腳本獲得執行許可權
  * 使用 ./CMake_Build.sh 執行編譯器
    * 添加參數 --enable-static 即 ./CMake_Build.sh --enable-static 可啟用靜態編譯
    * 腳本所進行的操作：
      * CMake 將編譯並在 Release 目錄生成 Pcap_DNSProxy 程式
      * 設置 Pcap_DNSProxy 程式以及 PcapDNSProxyService 和 Pcap_DNSProxy.service 服務控制腳本的基本讀寫可執行許可權
      * 設置 Linux_(Un)Install.Systemd.sh 以及 Linux_(Un)Install.SysV.sh 服務控制安裝腳本的基本讀寫可執行許可權
      * 從 ExampleConfig 複製預設設定檔到 Release 目錄
    * 執行時使用 ./CMake_Build.sh --disable-libsodium 可剝離對 Libsodium 的依賴，不建議使用
      * 剝離後編譯時將不需要 Libsodium 庫的支援
      * 剝離後程式將完全失去支援 DNSCurve/DNSCrypt 協定的功能，且運行時將不會產生任何錯誤提示，慎用！

3.配置系統守護進程服務
  * 由於不同的 Linux 發行版本對系統服務和守護進程的處理方式不同，本步僅供參考
    * 附帶的 Linux_Install.Systemd.sh 腳本適用于預設使用 Systemd Init 的系統
      * Linux Debian 8.x 官方發行版本以及更新版本系統內容，經測試可直接使用
    * 附帶的 Linux_Install.SysV.sh 腳本適用于預設使用 System V Init 的系統
      * Linux Debian 6.x - 7.x 官方發行版本系統內容，經測試可直接使用
    * 更多詳情可參見下文其它 Linux 發行版本服務的說明，以及所使用 Linux 發行版本的官方說明
  * 使用 Systemd Init 時：
    * 進入 Release 目錄並編輯 Pcap_DNSProxy.service 檔，編輯完成後保存：
      * WorkingDirectory= 項為程式所在目錄的絕對路徑
      * ExecStart= 項為程式所在目錄的絕對路徑，並在最後加上程式的名稱
    * 在 root 許可權下使用 ./Linux_Install.Systemd.sh 執行服務安裝腳本，腳本所進行的操作：
      * 將 Pcap_DNSProxy.service 服務控制腳本的擁有者更改為 root
      * 安裝服務控制腳本到 /etc/systemd/system 目錄中
      * 嘗試啟動 Pcap_DNSProxy 服務，並顯示執行操作後服務的狀態
      * 以後每次系統啟動都將自動啟動服務
    * 更多 Systemd 服務控制的方法，參見各 Linux 發行版本官方文檔的說明
  * 使用 System V Init 時：
    * 進入 Release 目錄並編輯 PcapDNSProxyService 檔，編輯完成後保存：
      * NAME 項為程式的名稱
      * PATH 項為程式的絕對路徑
    * 在 root 許可權下使用 ./Linux_Install.SysV.sh 執行服務安裝腳本，腳本所進行的操作：
      * 將 PcapDNSProxyService 服務控制腳本的擁有者更改為 root
      * 安裝服務控制腳本到 /etc/init.d 目錄中
      * 嘗試啟動 PcapDNSProxyService 服務，並顯示執行操作後服務的狀態
      * 以後每次系統啟動都將自動運行腳本啟動服務
    * 可直接輸入 sh PcapDNSProxyService 不帶參數查詢用法
      * start - 啟動服務
      * stop - 停止服務
      * force-reload/restart - 重啟服務
      * status - 服務狀態，如果 PID 為空則服務未啟動

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

4.配置系統 DNS 伺服器設置
  * 可參見 https://developers.google.com/speed/public-dns/docs/using 中 Changing your DNS servers settings 中 Linux 一節
  * 圖形介面以 GNOME 3 為例：
    * 打開所有程式清單，並 -> 設置 - 硬體分類 - 網路
    * 如果要對當前的網路設定進行編輯 -> 按一下齒輪按鈕
    * 選中 IPv4
      * DNS 欄目中，將自動撥向關閉
      * 在伺服器中填入 127.0.0.1 並應用
    * 選中 IPv6
      * DNS 欄目中，將自動撥向關閉
      * 在伺服器中填入 ::1 並應用
    * 請務必確保只填入這兩個地址，填入其它地址可能會導致系統選擇其它 DNS 服務器繞過程序的代理
    * 重啟網路連接
  * 直接修改系統檔修改 DNS 伺服器設置：
    * 自動獲取位址(DHCP)時：
      * 以 root 許可權進入 /etc/dhcp 或 /etc/dhcp3 目錄（視乎 dhclient.conf 檔位置）
      * 直接修改 dhclient.conf 檔，修改或添加 prepend domain-name-servers 一項即可
      * 如果 prepend domain-name-servers 一項被 # 注釋則需要把注釋去掉以使配置生效，不需要添加新的條目
      * dhclient.conf 檔可能存在多個 prepend domain-name-servers 項，是各個網路介面的設定項目，直接修改總的設定項目即可
    * 使用 service network(/networking) restart 或 ifdown/ifup 或 ifconfig stop/start 重啟網路服務/網路埠
      * 非自動獲取位址(DHCP)時：
      * 以 root 許可權進入 /etc 目錄
      * 直接修改 resolv.conf 檔裡的 nameserver 即可
      * 如果重啟後配置被覆蓋，則需要修改或新建 /etc/resolvconf/resolv.conf.d 檔，內容和 resolv.conf 一樣
      * 使用 service network(/networking) restart 或 ifdown/ifup 或 ifconfig stop/start 重啟網路服務/網路埠


-------------------------------------------------------------------------------


卸載方法：
* 由於不同的 Linux 發行版本對系統服務和守護進程的處理方式不同，本節僅供參考

1.還原系統網路設定
2.以 root 許可權進入 Release 目錄，執行 ./Linux_Uninstall.Systemd.sh 或 ./Linux_Uninstall.SysV.sh
3.刪除所有 Pcap_DNSProxy 相關檔


-------------------------------------------------------------------------------


建議的升級方法：

* Systemd 部分：
  1.打開終端，使用 sudo -i 獲得 root 許可權並進入 Release 目錄內
  2.使用 ./Linux_Uninstall.Systemd.sh 執行服務卸載腳本
  3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
  4.按照安裝方法重新部署 Pcap_DNSProxy
    * 進行第4步前先將備份的配置檔案還原到 Release 目錄內
    * Config.conf 檔建議按照備份的設定檔重新設置一次，如直接覆蓋可能會導致沒有新功能的選項
* SysV 部分：
  1.打開終端，使用 sudo -i 獲得 root 許可權並進入 Release 目錄內
  2.使用 ./Linux_Uninstall.SysV.sh 執行服務卸載腳本
  3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
  4.按照安裝方法重新部署 Pcap_DNSProxy
    * 進行第4步前先將備份的配置檔案還原到 Release 目錄內
    * Config.conf 檔建議按照備份的設定檔重新設置一次，如直接覆蓋可能會導致沒有新功能的選項


-------------------------------------------------------------------------------


正常工作查看方法：

1.打開終端
2.輸入 dig www.google.com 並回車
3.運行結果應類似：

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

4.如非以上結果，請移步 Linux 版 FAQ 文檔中 運行結果分析 一節


-------------------------------------------------------------------------------


其它 Linux 發行版本服務的說明：

* Linux Debian 系列：
  * 官方發行版本 8.x 以及更新版本預設需要使用 Systemd 管理系統服務
  * 官方發行版本 6.x - 7.x 版本預設需要使用 insserv 管理系統服務
  * 官方發行版本 6.x 以下版本預設需要使用 update-rc.d 管理系統服務，參見 https://wiki.debian.org/Daemon
* Linux Red Hat 和 openSUSE 系列：
  * 使用 chkconfig 管理系統服務
  * 參見 https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/html/Deployment_Guide/s2-services-chkconfig.html
* 如果需要自己編寫服務啟動腳本，請注意 Pcap_DNSProxyService 服務需要在以下模組初始化之後才能正常使用，建議儘量將優先順序降低，否則將建置錯誤報告並直接退出：
  * 需要在掛載所有檔案系統後
  * 需要初始化系統日誌後
  * 需要在啟動網路服務以及網路設備器初始化完畢後
  * 需要在系統時間被設置後
  * 需要在本機名稱被設置後
* 也可直接將本程式加入啟動項中，注意必須以 root 許可權啟動否則無法打開本地監聽埠
  * 程式內置了設置守護進程的代碼，啟動後不會阻塞系統的運行
