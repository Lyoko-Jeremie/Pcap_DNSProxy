Pcap_DNSProxy 專案的 GitHub 頁面：
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy 專案的 Sourceforge 頁面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程式以及配置的詳細情況，參見 ReadMe(...).txt

  
-------------------------------------------------------------------------------


安裝方法（使用已編譯好的二進位可執行檔）：

1.訪問 https://github.com/chengr28/Pcap_DNSProxy/releases 將二進位可執行檔包下載到本地
2.打開下載回來的二進位可執行檔包，將 Mac 目錄解壓到磁片的任意位置
3.編輯 pcap_dnsproxy.service.plist 檔案
  * 清空 <string>/usr/local/opt/pcap_dnsproxy/bin/Pcap_DNSProxy</string> 標籤內的內容，改為 "<string>程式所在的完整路徑/程式名稱</string>"（不含引號）
  * 清空 <string>/usr/local/etc/pcap_dnsproxy/</string> 標籤內的內容，改為 "<string>程式所在的完整路徑</string>"（不含引號）
4.打開終端，使用 sudo -i 獲得 root 許可權並進入 Mac 目錄內：
  * 使用 chmod 755 Mac_Install.sh 使服務安裝腳本獲得可執行許可權
  * 使用 ./Mac_Install.sh 執行服務安裝腳本
  * 腳本所進行的操作：
    * 设置程序、脚本以及 plist 配置文件的基本读写执行权限
    * 装载并启动守护进程服务
  * 以後每次開機在登錄前守護進程服務都將自動啟動
5.打開 "系統偏好設置" 視窗
  * 進入 "網路" 部分
  * 選中使用的網路介面卡，點擊 "高級" 按鈕
  * 切換到 "DNS" 選項卡，並點擊 "DNS伺服器" 下的 "+" 號
  * 輸入 127.0.0.1(IPv4)/::1(IPv6)
    * 請務必確保只填入這兩個地址，填入其它地址可能會導致系統選擇其它 DNS 服務器繞過程序的代理
  * 按 "好" 再按 "應用" 即可


-------------------------------------------------------------------------------


安裝方法（編譯二進位可執行檔）：

1.準備程式編譯環境
  * Homebrew 可訪問 http://brew.sh 獲取
  * CMake 可訪問 https://cmake.org 或通過 Homebrew 獲取
  * Libsodium 可訪問 https://github.com/jedisct1/libsodium 獲取
    * 編譯時如果剝離 Libsodium 的依賴則可跳過編譯和安裝下表的依賴庫和工具，具體參見下文的介紹，不建議使用
    * 獲得 root 許可權後進入目錄，運行 ./autogen.sh -> ./configure -> make -> make install 即可

2.編譯 Pcap_DNSProxy 程式並配置程式屬性
  * 切勿更改腳本的換行格式 (UNIX/LF)
  * 使用終端進入 Source/Scripts 目錄，使用 chmod 755 CMake_Build.sh 使腳本獲得執行許可權
  * 使用 ./CMake_Build.sh 執行編譯器
    * 添加參數 --enable-static 即 ./CMake_Build.sh --enable-static 可啟用靜態編譯
    * 腳本所進行的操作：
      * CMake 將編譯並在 Release 目錄生成 Pcap_DNSProxy 程式
      * 設置 Pcap_DNSProxy 程式以及 pcap_dnsproxy.service.plist 服務控制腳本的基本讀寫可執行許可權
      * 設置 Mac_(Un)Install.sh 服務控制安裝腳本的基本讀寫可執行權
      * 從 ExampleConfig 複製預設設定檔到 Release 目錄
    * 執行時使用 ./CMake_Build.sh --disable-libsodium 可剝離對 Libsodium 的依賴，不建議使用
      * 剝離後編譯時將不需要 Libsodium 庫的支援
      * 剝離後程式將完全失去支援 DNSCurve/DNSCrypt 協定的功能，且運行時將不會產生任何錯誤提示，慎用！

3.按照安裝方法（使用已編譯好的二進位可執行檔）中第3步的操作繼續進行即可


-------------------------------------------------------------------------------


卸載方法：

1.還原系統網路設定
2.打開終端，使用 sudo -i 獲得 root 許可權並進入 Mac 目錄內
3.使用 ./Mac_Uninstall.sh 執行服務卸載腳本
  * 腳本所進行的操作：停止並卸載守護進程服務，刪除 plist 設定檔
4.刪除所有 Pcap_DNSProxy 相關檔


-------------------------------------------------------------------------------


建議的升級方法：

1.打開終端，使用 sudo -i 獲得 root 許可權並進入 Mac 目錄內
2.使用 ./Mac_Uninstall.sh 執行服務卸載腳本
3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
4.按照安裝方法重新部署 Pcap_DNSProxy
  * 進行第4步前先將備份的配置檔案還原到 Mac 目錄內
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

4.如非以上結果，請移步 Mac 版 FAQ 文檔中 運行結果分析 一節
