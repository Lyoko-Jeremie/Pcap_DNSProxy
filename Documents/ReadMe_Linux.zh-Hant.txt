Pcap_DNSProxy 專案的 GitHub 頁面：
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy 專案的 Sourceforge 頁面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程式以及配置的詳細情況，參見 ReadMe(..).txt


-------------------------------------------------------------------------------


安裝方法：
安裝過程比較漫長而且操作比較複雜，請給予一定的耐心按照說明操作！

1.準備程式編譯環境：編譯前需要使用包管理工具安裝，或者需要自行編譯和安裝依賴庫
  * 依賴工具/庫清單：
    * 原始程式碼編譯器，必須完整支援 C++ 14 標準，可任選其一：
      * GCC/g++ 最低版本要求為 5.0
      * Clang/LLVM 最低版本要求為 3.4
    * CMake
    * LibEvent
    * LibPcap
      * 編譯時如果剝離 LibPcap 的依賴則可跳過編譯和安裝下表的依賴庫和工具，具體參見下文的介紹，不建議使用
    * Libsodium 
      * 編譯時如果剝離 Libsodium 的依賴則可跳過編譯和安裝下表的依賴庫和工具，具體參見下文的介紹，不建議使用
    * OpenSSL
      * 編譯時如果剝離 OpenSSL 的依賴則可跳過編譯和安裝下表的依賴庫和工具，具體參見下文的介紹，不建議使用

2.編譯 Pcap_DNSProxy 程式並配置程式屬性
  * 使用終端進入 Source/Auxiliary/Scripts 目錄，使用 chmod 755 CMake_Build.sh 使腳本獲得執行許可權
  * 使用 ./CMake_Build.sh 執行編譯器
    * 腳本所進行的操作：
      * CMake 將編譯並在 Release 目錄生成 Pcap_DNSProxy 程式
      * 從 ExampleConfig 目錄和 Scripts 目錄複寫所需的腳本和預設設定檔到 Release 目錄，並設置基本讀寫可執行許可權
    * 添加參數 --enable-static 即 ./CMake_Build.sh --enable-static 可啟用靜態編譯
  * 使用 ./CMake_Build.sh 腳本時可提供的參數：
    * 執行時使用 ./CMake_Build.sh --disable-libpcap --disable-libsodium --disable-tls 可剝離對對應庫的依賴，不建議使用
    * 剝離後編譯時將不再需要該庫的支援，但同時將完全失去使用該庫所支援的功能，且運行時將不會產生任何提示，慎用！

3.配置系統守護進程服務
  * 由於不同的 Linux 發行版本對系統服務和守護進程的處理方式不同，本步僅供參考
    * 附帶的 Linux_Install.Systemd.sh 腳本適用于預設使用 Systemd Init 的系統
      * Linux Debian 8.x 官方發行版本以及更新版本系統內容，經測試可直接使用
    * 附帶的 Linux_Install.SysV.sh 腳本適用于預設使用 System V Init 的系統
    * 更多詳情可參見下文其它 Linux 發行版本服務的說明，以及所使用 Linux 發行版本的官方說明
  * 使用 Systemd Init 時：
    * 進入 Release 目錄並編輯 Pcap_DNSProxy.service 檔，編輯完成後保存：
      * WorkingDirectory= 項為程式所在目錄的絕對路徑
      * ExecStart= 項為程式所在目錄的絕對路徑，並在最後加上程式的名稱
    * 在 root 許可權下使用 ./Linux_Install.Systemd.sh 執行服務安裝腳本，腳本所進行的操作：
      * 設置服務控制腳本基本讀寫可執行許可權
      * 安裝服務控制腳本到 /etc/systemd/system 目錄中
      * 嘗試啟動 Pcap_DNSProxy 服務，並顯示執行操作後服務的狀態
      * 以後每次系統啟動都將自動啟動服務
    * 更多 Systemd 服務控制的方法，參見各 Linux 發行版本官方文檔的說明
  * 使用 System V Init 時：
    * 進入 Release 目錄並編輯 PcapDNSProxyService 檔，編輯完成後保存：
      * NAME 項為程式的名稱
      * PATH 項為程式的絕對路徑
    * 在 root 許可權下使用 ./Linux_Install.SysV.sh 執行服務安裝腳本，腳本所進行的操作：
      * 設置服務控制腳本基本讀寫可執行許可權
      * 安裝服務控制腳本到 /etc/init.d 目錄中
      * 嘗試啟動 PcapDNSProxyService 服務，並顯示執行操作後服務的狀態
      * 以後每次系統啟動都將自動運行腳本啟動服務
    * 可直接輸入 sh PcapDNSProxyService 不帶參數查詢用法
      * start - 啟動服務
      * stop - 停止服務
      * force-reload/restart - 重啟服務
      * status - 服務狀態，如果 PID 為空則服務未啟動

4.請按照下文 正常工作查看方法 一節，先對程式是否在正常工作進行測試再修改網路設定！

5.配置系統 DNS 伺服器設置
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


重啟服務方法：
* Systemd 部分：
  1.打開終端，使用 su 獲得 root 許可權
  2.使用 systemctl restart Pcap_DNSProxy 直接重啟服務即可
  3.也可以先 systemctl stop Pcap_DNSProxy 停止服務，稍等一段時間再 systemctl start Pcap_DNSProxy 啟動服務即可
* SysV 部分：
  1.打開終端，使用 su 獲得 root 許可權
  2.使用 service PcapDNSProxyService restart 直接重啟服務即可
  3.也可以先 service PcapDNSProxyService stop 停止服務，稍等一段時間再 service PcapDNSProxyService start 啟動服務即可


小更新的方法（需要以管理員身份進行，如果設定檔的 Version 有更新需要進行大更新）：
* Systemd 部分：
  1.打開終端，使用 su 獲得 root 許可權
  2.使用 systemctl stop Pcap_DNSProxy 停止服務
  3.將目錄內的所有可執行檔刪除
  4.將新版本的 Pcap_DNSProxy 的所有可執行檔解壓到相同位置
  5.使用 systemctl start Pcap_DNSProxy 啟動服務
* SysV 部分：
  1.打開終端，使用 su 獲得 root 許可權
  2.使用 service PcapDNSProxyService stop 停止服務
  3.將目錄內的所有可執行檔刪除
  4.將新版本的 Pcap_DNSProxy 的所有可執行檔解壓到相同位置
  5.使用 service PcapDNSProxyService start 啟動服務


大更新的方法（需要以管理員身份進行，切勿直接覆蓋，否則可能會造成不可預料的錯誤）：
* Systemd 部分：
  1.打開終端，使用 su 獲得 root 許可權並進入 Release 目錄內
  2.使用 ./Linux_Uninstall.Systemd.sh 執行服務卸載腳本
  3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
  4.按照安裝方法重新部署 Pcap_DNSProxy
    * 進行第 4 步前先將備份的配置檔案還原到 Release 目錄內
    * Config.conf 檔建議按照備份的設定檔重新設置一次，如直接覆蓋可能會導致沒有新功能的選項
* SysV 部分：
  1.打開終端，使用 su 獲得 root 許可權並進入 Release 目錄內
  2.使用 ./Linux_Uninstall.SysV.sh 執行服務卸載腳本
  3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
  4.按照安裝方法重新部署 Pcap_DNSProxy
    * 進行第 4 步前先將備份的配置檔案還原到 Release 目錄內
    * Config.conf 檔建議按照備份的設定檔重新設置一次，如直接覆蓋可能會導致沒有新功能的選項


卸載方法：
* 由於不同的 Linux 發行版本對系統服務和守護進程的處理方式不同，本節僅供參考
1.還原系統網路設定
2.以 root 許可權進入 Release 目錄，執行 ./Linux_Uninstall.Systemd.sh 或 ./Linux_Uninstall.SysV.sh
3.刪除所有 Pcap_DNSProxy 相關檔


-------------------------------------------------------------------------------


正常工作查看方法：

1.打開終端
2.輸入 dig @127.0.0.1 www.google.com 或者 dig @::1 www.google.com 並回車
3.運行結果應類似：

   >dig www.google.com
   ; (1 server found)
   ;; global options: +cmd
   ;; Got answer:
   ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ..
   ;; flags: ..; QUERY: .., ANSWER: .., AUTHORITY: .., ADDITIONAL: ..

   ;; QUESTION SECTION:
   ;www.google.com.            IN    A

   ;; ANSWER SECTION:
   ..

   ;; Query time: .. msec
   ;; SERVER: ::1#53(::1)（視所在網路環境而定，本地監聽協定為 IPv4 時為 127.0.0.1）
   ;; WHEN: ..
   ;; MSG SIZE  rcvd: ..

4.如非以上結果，請移步 Linux 版 FAQ 文檔中 運行結果分析 一節


-------------------------------------------------------------------------------


其它 Linux 發行版本服務的說明：

* Linux Debian 系列：
  * 官方發行版本 8.x 以及更新版本預設需要使用 Systemd 管理系統服務
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
