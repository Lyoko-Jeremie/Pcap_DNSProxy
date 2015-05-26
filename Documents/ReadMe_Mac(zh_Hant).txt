Pcap_DNSProxy 專案的 GitHub 頁面：

* 主分支: https://github.com/chengr28/Pcap_DNSProxy
* Release 分支: https://github.com/chengr28/Pcap_DNSProxy/tree/Release

Pcap_DNSProxy 專案的 Sourceforge 頁面：
https://sourceforge.net/projects/pcap-dnsproxy


* 更多程式以及配置的詳細情況，參見 ReadMe(...).txt

  
-------------------------------------------------------------------------------


安裝方法：

1.訪問 https://github.com/chengr28/Pcap_DNSProxy/tree/Release 使用 GitHub 的 Download ZIP 功能將所有檔下載到本地
2.打開下載回來的 ZIP 檔，將 Mac 目錄解壓到磁片的任意位置
3.編輯 pcap_dnsproxy.service.plist 檔案
  * 清空 <string>/usr/local/opt/pcap_dnsproxy/bin/Pcap_DNSProxy</string> 標籤內的內容，改為 "<string>程式所在的完整路徑/程式名稱</string>"（不含引號）
  * 清空 <string>/usr/local/etc/pcap_dnsproxy/</string> 標籤內的內容，改為 "<string>程式所在的完整路徑</string>"（不含引號）
4.打開終端，使用 sudo -i 獲得 root 許可權並進入 Mac 目錄內：
  * 使用 chmod 777 Build_Mac.sh 使服務安裝腳本獲得可執行許可權
  * 使用 ./Build_Mac.sh 執行服務安裝腳本
  * 腳本所進行的操作：
    * 將位於 /Library/LaunchDaemons 目錄的 pcap_dnsproxy.service.plist 擁有者更改為 root
    * 裝載並啟動守護進程服務
  * 以後每次開機在登錄前守護進程服務都將自動啟動
5.打開 "系統偏好設置" 視窗
  * 進入 "網路" 部分
  * 選中使用的網路介面卡，點擊 "高級" 按鈕
  * 切換到 "DNS" 選項卡，並點擊 "DNS伺服器" 下的 "+" 號
  * 輸入 127.0.0.1(IPv4)/::1(IPv6)
    * 請務必確保只填入這兩個地址，填入其它地址可能會導致系統選擇其它 DNS 服務器繞過程序的代理
  * 按 "好" 再按 "應用" 即可


-------------------------------------------------------------------------------


卸載方法：

1.還原系統網路設定
2.打開終端
3.使用 sudo -i 命令獲得 root 許可權，然後使用 cd /Library/LaunchDaemons 進入自啟動守護進程目錄
4.使用 launchctl unload PcapDNSProxyService.plist 停止並卸載守護進程
5.使用 rm -rf PcapDNSProxyService.plist 命令或直接將 PcapDNSProxyService.plist 拖入廢紙簍刪除
6.刪除所有 Pcap_DNSProxy 相關檔


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
   ;; SERVER: 127.0.0.1#53(127.0.0.1)（IPv4，IPv6下为 ::1 ）
   ;; WHEN: ...
   ;; MSG SIZE  rcvd: ...

4.如非以上結果，請移步 Mac 版 FAQ 文檔中 運行結果分析 一節
