Pcap_DNSProxy 專案的 GitHub 頁面：
https://github.com/chengr28/Pcap_DNSProxy

Pcap_DNSProxy 專案的 Sourceforge 頁面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程式以及配置的詳細情況，參見 ReadMe(..).txt


-------------------------------------------------------------------------------


安裝方法（使用已編譯好的二進位可執行檔）：

1.打開下載的二進位可執行檔包，將 macOS 目錄解壓到磁片的任意位置
2.編輯 pcap_dnsproxy.service.plist 檔
  * 清空 <string>/usr/local/opt/pcap_dnsproxy/bin/Pcap_DNSProxy</string> 標籤內的內容
  * 改為 "<string>程式所在的完整路徑/程式名稱</string>"（不含引號）
  * 清空 <string>/usr/local/etc/pcap_dnsproxy</string> 標籤內的內容
  * 改為 "<string>程式所在的完整路徑</string>"（不含引號）
3.打開終端，使用 sudo -i 獲得 root 許可權並進入 macOS 目錄內：
  * 使用 cd 切換回程序所在目錄
  * 使用 chmod 755 macOS_Install.sh 使服務安裝腳本獲得可執行許可權
  * 使用 ./macOS_Install.sh 執行服務安裝腳本
  * 腳本所進行的操作：
    * 設置程式、腳本以及 plist 設定檔的基本讀寫執行許可權
    * 裝載並啟動守護進程服務
    * 每次開機在登錄前守護進程服務都將自動啟動
4.請按照下文 正常工作查看方法 一節，先對程式是否在正常工作進行測試再修改網路設定！
5.打開 "系統偏好設置" 視窗
  * 進入 "網路" 部分
  * 選中使用的網路介面卡，點擊 "高級" 按鈕
  * 切換到 "DNS" 選項卡，並點擊 "DNS 伺服器" 下的 "+" 號
  * 輸入 127.0.0.1(IPv4)/::1(IPv6)
    * 請務必確保只填入這兩個位址，填入其它位址可能會導致系統選擇其它 DNS 伺服器繞過程式的代理
  * 按 "好" 再按 "應用" 即可


-------------------------------------------------------------------------------


安裝方法（編譯二進位可執行檔）：

1.準備程式編譯環境
  * 完整的協力廠商依賴清單：
    * CMake
    * LibEvent
    * LibPcap
      * 本依賴可根據編譯參數剝離
    * LibSodium
      * 本依賴可根據編譯參數剝離
    * OpenSSL
      * 本依賴可根據編譯參數剝離

2.編譯 Pcap_DNSProxy 程式並配置程式屬性
  * 使用終端進入 Source/Auxiliary/Scripts 目錄，使用 chmod 755 CMake_Build.sh 使腳本獲得執行許可權
  * 使用 ./CMake_Build.sh 執行編譯器
    * 腳本所進行的操作：
      * CMake 將編譯並在 Release 目錄生成 Pcap_DNSProxy 程式
      * 從 ExampleConfig 目錄和 Scripts 目錄複寫所需的腳本和預設設定檔到 Release 目錄，並設置基本讀寫可執行許可權
  * 使用 ./CMake_Build.sh 腳本時可提供的參數：
    * 執行時使用 ./CMake_Build.sh --disable-libpcap --disable-libsodium --disable-tls 可剝離對對應庫的依賴，不建議使用
    * 剝離後編譯時將不再需要該庫的支援，但同時將完全失去使用該庫所支援的功能，且運行時將不會產生任何提示，慎用！

3.按照安裝方法（使用已編譯好的二進位可執行檔）中第 3 步的操作繼續進行即可


-------------------------------------------------------------------------------


有關 OpenSSL 庫的特別說明：

* 安裝新版本 OpenSSL 庫後，在開啟 TLS/SSL 功能進行編譯時如果出現 undef: OPENSSL.. 錯誤：
  * 原因是 macOS 自帶的 OpenSSL 系列版本非常老舊(0.9.8)不支援新版本特性，連結器在連結時使用了系統自帶庫導致錯誤
  * 此時先查看編譯過程的記錄，將 Found OpenSSL 指示的 CMake 找到的 OpenSSL 庫檔目錄記下，並確認所使用的版本
    * 可編輯 Pcap_DNSProxy 目錄下的 CMakeLists.txt 檔：
    * 編輯時請務必注意引號的問題，必須使用 ASCII 的標準引號
    * 尋找 find_package(OpenSSL REQUIRED) 語句，並另開一行
    * 在新開的一行填入 set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L剛才記下的目錄") 優先指定連結器所查找的庫檔
    * 例如 set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -L/usr/local/lib")
    * 保存檔並重新運行 ./CMake_Build.sh 即可
* 預設情況下 OpenSSL 庫沒有附帶任何的可根信任證書庫，首次使用時需要使用者自行添加：
  * 打開公用程式 - 鑰匙串訪問 - 系統根憑證，選中清單中所有的證書以 cert.pem 的 PEM 格式匯出到任何位置
  * 打開終端，使用 sudo -i 獲得 root 許可權並進入剛才匯出位置的目錄內
  * 使用 mv cert.pem 證書目標目錄/cert.pem 移動該系統根憑證儲存檔到 OpenSSL 的證書目錄中
  * 此處的證書目標目錄，位於上文提到的 Found OpenSSL 指示的 CMake 找到的 OpenSSL 庫部署目錄附近，該目錄內應該存在名為 certs 的子目錄
  * 例如 mv cert.pem /usr/local/ssl


-------------------------------------------------------------------------------


重啟服務方法：
1.打開終端，使用 sudo -i 獲得 root 許可權並進入 /Library/LaunchDaemons 目錄內
2.使用 launchctl unload pcap_dnsproxy.service.plist 停止服務，稍等一段時間
3.使用 launchctl load pcap_dnsproxy.service.plist 啟動服務即可


小更新的方法（需要以管理員身份進行，如果設定檔的 Version 有更新需要進行大更新）：
1.打開終端，使用 sudo -i 獲得 root 許可權並進入 macOS 目錄內
2.使用 ./macOS_Uninstall.sh 執行服務卸載腳本
3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
  * 進行第 4 步前先將備份的配置檔案還原到 macOS 目錄內
4.按照安裝方法重新部署 Pcap_DNSProxy
  * Config.conf 檔建議按照備份的設定檔重新設置，如直接覆蓋可能會導致沒有新功能的選項


大更新的方法（需要以管理員身份進行，切勿直接覆蓋，否則可能會造成不可預料的錯誤）：
1.打開終端，使用 sudo -i 獲得 root 許可權並進入 macOS 目錄內
2.使用 ./macOS_Uninstall.sh 執行服務卸載腳本
3.備份所有設定檔，刪除所有 Pcap_DNSProxy 相關檔
  * 進行第 4 步前先將備份的配置檔案還原到 macOS 目錄內
4.按照安裝方法重新部署 Pcap_DNSProxy
  * Config.conf 檔建議按照備份的設定檔重新設置，如直接覆蓋可能會導致沒有新功能的選項


卸載方法：
1.還原系統網路設定
2.打開終端，使用 sudo -i 獲得 root 許可權並進入 macOS 目錄內
3.使用 ./macOS_Uninstall.sh 執行服務卸載腳本
  * 腳本所進行的操作：停止並卸載守護進程服務，刪除 plist 設定檔
4.刪除所有 Pcap_DNSProxy 相關檔


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

4.如非以上結果，請移步 macOS 版 FAQ 文檔中 運行結果分析 一節
