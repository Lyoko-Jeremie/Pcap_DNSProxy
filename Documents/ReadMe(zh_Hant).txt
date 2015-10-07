Pcap_DNSProxy 專案的 GitHub 頁面：

* 主分支: https://github.com/chengr28/Pcap_DNSProxy
* Release 分支: https://github.com/chengr28/Pcap_DNSProxy/tree/Release

Pcap_DNSProxy 專案的 Sourceforge 頁面：
https://sourceforge.net/projects/pcap-dnsproxy


-------------------------------------------------------------------------------


安裝方法（需要以管理員身份進行）：

1.訪問 http://www.winpcap.org/install/default.htm 下載並以管理員許可權安裝 WinPcap
  * WinPcap 只需要安裝一次，以前安裝過最新版本或以後更新本工具時請從第2步開始操作
  * 如果 WinPcap 提示已安裝舊版本無法繼續時，參見 FAQ 中 運行結果分析 一節
  * 安裝時自啟動選項對工具的運行沒有影響，因為本工具直接調用 WinPcap API，不需要經過伺服器程式

2.訪問 https://github.com/chengr28/Pcap_DNSProxy/tree/Release 並使用 GitHub 的 Download ZIP 功能將所有檔下載到本地
  * Windows 版本的 Pcap_DNSProxy 在 ZIP 的 Windows 目錄內，可將整個目錄單獨抽出運行

3.打開下載回來的 ZIP 檔，將 Windows 目錄解壓到磁片的任意位置
  * 目錄所在位置和程式檔案名可以隨意更改
  * 設定檔需要使用固定的檔案名（更多詳細情況參見下文 功能和技術 一節）

4.確定工具目錄的名稱和路徑後進入目錄內，右鍵以管理員身份(Vista 以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceControl.bat
  * 輸入 1 並回車，即選擇 "1: Install service" 安裝服務
  * 批次處理會將程式註冊系統服務，並進行 Windows 防火牆測試，每次開機服務都將自動啟動
  * 此時 Windows 系統會詢問是否同意程式訪問網路，請將 "私人網路絡" 以及 "公用網路" 都勾上並確認

5.打開 "網路和共用中心" - "更改配接器設置" 選擇 "本地連接" 或 "無線連接" 或 "寬頻連線"
  * 右擊 "屬性" - "Internet協定(TCP/IP)"(XP/2003) 或 "Internet協定版本4(IPv4)"(Vista 以及更新版本) - "屬性" - 勾選 "使用下面的 DNS 伺服器位址"
  * 在 "首選DNS伺服器" 內填入 "127.0.0.1"（不含引號） 確定保存並退出即可
  * 如果需要使用 IPv6 協定的本機伺服器
    * 右擊 "屬性" - "Internet協定版本6(IPv6)" - "屬性" - 勾選 "使用下面的 DNS 伺服器位址"
    * 在 "首選DNS伺服器" 內填入 "::1"（不含引號） 確定保存並退出即可
  * 請務必確保只填入這兩個地址，填入其它地址可能會導致系統選擇其它 DNS 服務器繞過程序的代理
  * 注意：建議將 "本地連接" 和 "無線連接" 以及 "寬頻連線" 全部修改！

6.特別注意：
  * 如需使用境內 DNS 伺服器解析境內功能變數名稱加速訪問 CDN 速度功能，請選擇其中一種方案，配置完成後重啟服務：
    * Local Main = 1 同時 Local Routing = 1 開啟境內位址路由表識別功能
    * Local Hosts = 1 開啟境內功能變數名稱白名單功能
  * 如需讓程式的流量通過系統路由級別的代理（例如 VPN 等）進行變數名稱解析，請選擇其中一種方案，配置完成後重啟服務：
    * Direct Request = IPv4
    * Direct Request = IPv6
    * Direct Request = IPv4 + IPv6


重啟服務方法（需要以管理員身份進行）：
1.右鍵以管理員身份(Vista 以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceControl.bat
2.輸入 5 並回車，即選擇 "5: Restart service" 立刻重啟服務


更新程式方法（需要以管理員身份進行）：
* 注意：更新程式切勿直接覆蓋，否則可能會造成不可預料的錯誤！請按照以下的步驟進行：
1.提前下載好新版本的 Pcap_DNSProxy（亦即 安裝方法 中第2步），更新過程可能會造成功能變數名稱解析短暫中斷
2.備份好所有設定檔 Hosts 檔 IPFilter 檔的自訂內容
3.右鍵以管理員身份(Vista 以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceControl.bat
4.輸入 2 並回車，即選擇 "2: Uninstall service" 卸載服務
4.將整個 Pcap_DNSProxy 程式的目錄刪除。注意 Windows 防火牆可能會留有允許程式訪問網路的資訊，卸載服務後又變更了程式的目錄則可能需要使用註冊表清理工具清理
5.將新版本的 Pcap_DNSProxy 解壓到任何位置（亦即 安裝方法 中第3步）
6.將設定檔的自訂內容加回新版本設定檔裡相應的區域內
7.按照 安裝方法 中第4步重新部署 Pcap_DNSProxy


安全模式下的使用方法（需要以管理員身份進行）：
* 程式具備在安全模式下運行的能力，在安全模式下右鍵以管理員身份直接運行程式
* 直接運行模式有主控台視窗，關閉程式時直接關閉主控台視窗即可

卸載方法（需要以管理員身份進行）：
1.按照 安裝方法 中第6步還原 DNS 功能變數名稱伺服器位址配置
2.右鍵以管理員身份(Vista 以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceControl.bat
  * 輸入 2 並回車，即選擇 "2: Uninstall service" 卸載服務
  * 注意：Windows 防火牆可能會留有允許程式訪問網路的資訊，故卸載後可能需要使用註冊表清理工具清理
  * 轉移工具目錄路徑不需要卸載服務，先停止服務轉移，轉移完成後重新開機服務即可


正常工作查看方法：

1.打開命令提示符
  * 在開始功能表或直接 Win + R 調出 運行 ，輸入 cmd 並回車
  * 開始功能表 - 程式/所有程式 - 附件 - 命令提示符
2.輸入 nslookup www.google.com 並回車
3.運行結果應類似：

   >nslookup www.google.com
    服务器:  pcap-dnsproxy.localhost.server（視設定檔設置的值而定，參見下文 設定檔詳細參數說明 一節）
    Address:  127.0.0.1（視所在網路環境而定，原生 IPv6 為 ::1）

    非权威应答:
    名称:    www.google.com
    Addresses: ……（IP位址或地址清單）


4.如非以上結果，請移步 FAQ 文檔中 運行結果分析 一節


-------------------------------------------------------------------------------


注意事項：

* 修改 DNS 伺服器時請務必設置一個正確的、有效的、可以正常使用的境外 DNS 伺服器！
* Windows 平臺下讀取檔案名時不存在大小寫的區別
* 設定檔 Hosts 檔 IPFilter 檔和錯誤報表所在的目錄以上文 安裝方法 一節中第4步註冊的服務資訊為准
  * 填寫時一行不要超過 4096位元組/4KB
  * 檔讀取只支援整個文本單一的編碼和換行格式組合，切勿在文字檔中混合所支援的編碼或換行格式！
* 服務啟動前請先確認沒有其它本地 DNS 伺服器運行或本工具多個拷貝運行中，否則可能會導致監聽衝突無法正常工作
  * 監聽衝突會建置錯誤報告，可留意 Windows Socket 相關的錯誤（參見 FAQ 文檔中 Error.log 詳細錯誤報表 一節）
* 殺毒軟體/協力廠商防火牆可能會阻止本程式的操作，請將行為全部允許或將本程式加入到白名單中
* 如果啟動服務時提示 "服務沒有及時回應啟動或者控制請求" 請留意是否有錯誤報表生成，詳細的錯誤資訊參見 FAQ 文檔中 Error.log 詳細錯誤報表 一節
* 目錄和程式的名稱可以隨意更改，但請務必在進行安裝方法第4步前完成。如果服務註冊後需移動工具目錄的路徑，參見上文 卸載方法 第2步的注意事項
* 由於本人水準有限，程式編寫難免會出現差錯疏漏，如有問題可至專案頁面提出，望諒解 v_v


-------------------------------------------------------------------------------


功能和技術：
* 批次處理的作用：
  * 運行結束會有運行結果，具體是否成功需要留意螢幕上的提示
  * 1: Install service - 將程式註冊為系統服務，並啟動程式進行 Windows 防火牆測試
  * 2: Uninstall service - 停止並卸載工具的服務
  * 3: Start service - 啟動工具的服務
  * 4: Stop service - 停止工具的服務
  * 5: Restart service - 重啟工具的服務
  * 6: Flush DNS cache in Pcap_DNSProxy - 刷新程序的内部 DNS 缓存
* 設定檔支援的檔案名（只會讀取優先順序較高者，優先順序較低者將被直接忽略）：
  * Windows: Config.ini > Config.conf > Config.cfg > Config
  * Linux/Mac: Config.conf > Config.ini > Config.cfg > Config
* 請求功能變數名稱解析優先順序
  * 使用系統API函數進行功能變數名稱解析（大部分）：系統 Hosts > Pcap_DNSProxy 的 Hosts 條目（Whitelist/白名單條目 > Hosts/主要Hosts清單） > DNS緩存 > Local Hosts/境內DNS解析功能變數名稱清單 > 遠端DNS伺服器
  * 直接使用網路介面卡設置進行功能變數名稱解析（小部分）：Pcap_DNSProxy 的 Hosts 配置檔案（Whitelist/白名單條目 > Hosts/主要Hosts清單） > DNS緩存 > Local Hosts/境內DNS解析功能變數名稱清單 > 遠端DNS伺服器
  * 請求遠端DNS伺服器的優先順序：Direct Request 模式 > TCP 模式的 DNSCurve 加密/非加密模式（如有） > UDP 模式的 DNSCurve 加密/非加密模式（如有） > TCP模式普通請求（如有） > UDP模式普通請求
* 本工具的 DNSCurve/DNSCrypt 協定是內置的實現，不需要安裝 DNSCrypt 官方的工具！
  * DNSCurve 協定為 Streamlined/精簡類型
  * 自動獲取連接資訊時必須保證系統時間的正確，否則證書驗證時會出錯導致連接資訊獲取失敗！
  * DNSCrypt 官方工具會佔用本地 DNS 埠導致 Pcap_DNSProxy 部署失敗！


-------------------------------------------------------------------------------


特別使用技巧：
這裡羅列出部分作者建議的介紹和使用技巧，供大家參考和使用。關於調整配置，參見下文 設定檔詳細參數說明 一節

* DNS 緩存類型
  * Timer/計時型：可以自訂緩存的時間長度，佇列長度不限
  * Queue/佇列型：預設緩存時間 15 分鐘，可通過 Default TTL 值自訂，同時可自訂緩存佇列長度（亦即限制佇列長度的 Timer/計時型）
  * 強烈建議打開DNS緩存功能！
* 本工具配置選項豐富，配置不同的組合會有不同的效果，介紹幾個比較常用的組合：
  * 預設配置：UDP 請求 + 抓包模式
  * Protocol = ...TCP：先 TCP 請求失敗後再 UDP 請求 + 抓包模式，對網路資源的佔用比較高
    * 由於 TCP 請求大部分時候不會被投毒污染，此組合的過濾效果比較可靠
  * EDNS Label = 1：開啟 EDNS 請求標籤功能
    * 此功能開啟後將有利於對偽造資料包的過濾能力，此組合的過濾效果比較可靠
  * 將目標伺服器的請求埠改為非標準 DNS 埠：例如 OpenDNS 支援 53 標準埠和 5353 非標準埠的請求
    * 非標準 DNS 埠現階段尚未被干擾，此組合的過濾效果比較可靠
  * Multi Request Times = xx 時：應用到所有除請求境內伺服器外的所有請求，一個請求多次發送功能
    * 此功能用於對抗網路丟包比較嚴重的情況，對系統和網路資源的佔用都比較高，但在網路環境惡劣的情況下能提高獲得解析結果的可靠性
  * DNSCurve = 1 同時 Encryption = 0：使用 DNSCurve/DNSCrypt 非加密模式請求功能變數名稱解析
    * 此組合等於使用非標準DNS埠請求，功能變數名稱解析可靠性比較高，詳細情況參見上文
  * DNSCurve = 1 同時 Encryption = 1：使用 DNSCurve/DNSCrypt 加密模式請求功能變數名稱解析
    * 此組合加密傳輸所有功能變數名稱請求，功能變數名稱解析可靠性最高
  * DNSCurve = 1 同時 Encryption = 1 同時 Encryption Only = 1：只使用 DNSCurve/DNSCrypt 加密模式請求功能變數名稱解析
    * 上文的加密組合並不阻止程式在請求 DNSCurve/DNSCrypt 加密模式失敗是使用其它協定請求功能變數名稱解析，開啟 Encryption Only = 1 後將只允許使用加密傳輸，安全性和可靠性最高，但功能變數名稱解析成功率可能會下降


-------------------------------------------------------------------------------


設定檔詳細參數說明：

有效參數格式為 "選項名稱 = 數值/資料"（不含引號，注意空格和等號的位置）
注意：設定檔只會在工具服務開始時讀取，修改本檔的參數後請重啟服務（參見上文 注意事項 一節中的 重啟服務）

* Base - 基本參數區域
  * Version - 設定檔的版本，用於正確識別設定檔：本參數與程式版本號不相關，切勿修改
  * File Refresh Time - 檔刷新間隔時間：單位為秒，最短間隔時間為 5 秒
  * Additional Path - 附加的資料檔案讀取路徑，附加在此處的目錄路徑下的 Hosts 檔和 IPFilter 檔會被依次讀取
  * Hosts File Name - Hosts 檔的檔案名，附加在此處的 Hosts 檔案名將被依次讀取
  * IPFilter File Name - IPFilter 檔的檔案名，附加在此處的 IPFilter 檔案名將被依次讀取

* Log - 日誌參數區域
  * Print Error - 輸出錯誤報表功能：開啟為 1 /關閉為 0
  * Log Maximum Size - 日誌檔最大容量：直接填數位時單位為位元組，可加上單位，支援的單位有 KB/MB/GB，可接受範圍為 4KB - 1GB，如果留空則為 8MB，預設為 8MB
    * 注意：日誌檔到達最大容量後將被直接刪除，然後重新生成新的日誌檔，原來的日誌將無法找回！

* Listen - 監聽參數區域
  * Pcap Capture - 抓包功能總開關，開啟後抓包模組才能正常使用：開啟為 1 /關閉為 0
    * 此參數關閉後程式會自動切換為直連模式
    * 直連模式下不能完全避免 DNS 投毒污染的問題，需要依賴其它的檢測方式，例如 EDNS 標籤等方法
  * Pcap Devices Blacklist - 指定不對含有此名稱的網路介面卡進行抓包，名稱或簡介裡含有此字串的網路介面卡將被直接忽略
    * 本參數支援指定多個名稱，大小寫不敏感，格式為 "網路介面卡的名稱(|網路介面卡的名稱)"（不含引號）
    * 以抓包模組從系統中獲取的名稱或簡介為准，與其它網路設定程式所顯示的不一定相同
  * Pcap Reading Timeout - 抓包模塊讀取超時時間，數據包只會在等待超時時間後才會被讀取，其餘時間抓包模塊處於休眠狀態：單位為毫秒，最短間隔時間為10毫秒
    * 讀取超時時間需要平衡需求和資源佔用，時間設置太長會導致域名解析請求響應緩慢導致請求解析超時，太快則會佔用過多系統處理的資源
  * Listen Protocol - 監聽協定，本地監聽的協定：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的協定可隨意組合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 時，只監聽指定協定的本地埠
    * 注意：此處的協定指的是向本程式請求功能變數名稱解析時可使用的協定，而程式請求遠端 DNS 伺服器時所使用的協定由 Protocol 參數決定
  * Listen Port - 監聽埠，本地監聽請求的埠：格式為 "埠A(|埠B)"（不含引號，括弧內為可選項目）
    * 埠可填入服務名稱，服務名稱清單參見下文
    * 也可填入 1-65535 之間的埠，如果留空則為 53
    * 填入多個埠時，程式將會同時監聽請求
    * 當相應協定的 Listen Address 生效時，相應協定的本參數將會被自動忽略
  * Operation Mode - 程式的監聽工作模式：分 Server/伺服器模式、Private/私有網路模式 和 Proxy/代理模式
    * Server/伺服器模式：打開 DNS 通用埠（TCP/UDP 同時打開），可為所有其它設備提供代理功能變數名稱解析請求服務
    * Private/私有網路模式：打開 DNS 通用埠（TCP/UDP 同時打開），可為僅限於私有網路位址的設備提供代理功能變數名稱解析請求服務
    * Proxy/代理模式：只打開回環位址的 DNS 埠（TCP/UDP 同時打開），只能為本機提供代理功能變數名稱解析請求服務
    * Custom/自訂模式：打開 DNS 通用埠（TCP/UDP 同時打開），可用的位址由 IPFilter 參數決定
    * 當相應協定的 Listen Address 生效時，相應協定的本參數將會被自動忽略
  * IPFilter Type - IPFilter 參數的類型：分為 Deny 禁止和 Permit 允許，對應 IPFilter 參數應用為黑名單或白名單
  * IPFilter Level - IPFilter 參數的過濾級別，級別越高過濾越嚴格，與 IPFilter 條目相對應：0 為不啟用過濾，如果留空則為 0
  * Accept Type - 禁止或只允許所列 DNS 類型的請求：格式為 "Deny:DNS記錄的名稱或ID(|DNS記錄的名稱或ID)" 或 "Permit:DNS記錄的名稱或ID(|DNS記錄的名稱或ID)"（不含引號，括弧內為可選項目）
    * 所有可用的 DNS 類型清單：
      * A/1
      * NS/2
      * MD/3
      * MF/4
      * CNAME/5
      * SOA/6
      * MB/7
      * MG/8
      * MR/9
      * NULL/10
      * WKS/11
      * PTR/12
      * HINFO/13
      * MINFO/14
      * MX/15
      * TXT/16
      * RP/17
      * AFSDB/18
      * X25/19
      * ISDN/20
      * RT/21
      * NSAP/22
      * NSAP_PTR/23
      * SIG/24
      * KEY/25
      * PX/26
      * GPOS/27
      * AAAA/28
      * LOC/29
      * NXT/30
      * EID/31
      * NIMLOC/32
      * SRV/33
      * ATMA/34
      * NAPTR/35
      * KX/36
      * CERT/37
      * A6/38
      * DNAME/39
      * SINK/40
      * OPT/41
      * APL/42
      * DS/43
      * SSHFP/44
      * IPSECKEY/45
      * RRSIG/46
      * NSEC/47
      * DNSKEY/48
      * DHCID/49
      * NSEC3/50
      * NSEC3PARAM/51
      * TLSA/52
      * HIP/55
      * NINFO/56
      * RKEY/57
      * TALINK/58
      * CDS/59
      * CDNSKEY/60
      * OPENPGPKEY/61
      * SPF/99
      * UINFO/100
      * UID/101
      * GID/102
      * UNSPEC/103
      * NID/104
      * L32/105
      * L64/106
      * LP/107
      * EUI48/108
      * EUI64/109
      * TKEY/249
      * TSIG/250
      * IXFR/251
      * AXFR/252
      * MAILB/253
      * MAILA/254
      * ANY/255
      * URI/256
      * CAA/257
      * TA/32768
      * DLV/32769
      * RESERVED/65535

* DNS - 功能變數名稱解析參數區域
  * Protocol - 發送請求所使用的協定：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的協定可隨意組合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 時，只使用指定協定向遠端 DNS 伺服器發出請求
    * 同時填入 IPv4 和 IPv6 或直接不填任何網路層協定時，程式將根據網路環境自動選擇所使用的協定
    * 同時填入 TCP 和 UDP 等於只填入 TCP 因為 UDP 為 DNS 的標準網路層協定，所以即使填入 TCP 失敗時也會使用 UDP 請求
  * Direct Request - 直連模式，啟用後將使用系統的 API 直接請求遠端伺服器而啟用只使用本工具的 Hosts 功能：可填入 IPv4 和 IPv6 和 0，關閉為 0
    * 建議當系統使用全域代理功能時啟用，程式將除境內服務器外的所有請求直接交給系統而不作任何過濾等處理，系統會將請求自動發往遠端伺服器進行解析
    * 填入 IPv4 或 IPv6 時將會啟用對應協定的 Direct Request 功能，填入 IPv4 + IPv6 將會啟用所有協定的功能
  * Cache Type - DNS 緩存的類型：分 Timer/計時型以及 Queue/佇列型：預設為 Queue
  * Cache Parameter - DNS 緩存的參數：Timer/計時型 時為時間長度（單位為秒），Queue/佇列型 時為佇列長度
  * Default TTL - Hosts 條目預設存留時間：單位為秒，留空則為 900秒/15分鐘
  
* Local DNS - 境內功能變數名稱解析參數區域
  * Local Protocol - 發送境內請求所使用的協定：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的協定可隨意組合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 時，只使用指定協定向境內 DNS 伺服器發出請求
    * 同時填入 IPv4 和 IPv6 或直接不填任何網路層協定時，程式將根據網路環境自動選擇所使用的協定
    * 同時填入 TCP 和 UDP 等於只填入 TCP 因為 UDP 為 DNS 的標準網路層協定，所以即使填入 TCP 失敗時也會使用 UDP 請求
  * Local Hosts - 白名單境內伺服器請求功能：開啟為 1 /關閉為 0
    * 開啟後才能使用自帶或自訂的 Local Hosts 白名單，且不能與 Local Hosts 和 Local Routing 同時啟用
  * Local Main - 主要境內伺服器請求功能：開啟為 1 /關閉為 0
    * 開啟後所有請求先使用 Local 的伺服器進行解析，遇到遭投毒污染的解析結果時自動再向境外伺服器請求
    * 本功能不能與 Local Hosts 同時啟用
  * Local Routing - Local 路由表識別功能：開啟為 1 /關閉為 0
    * 開啟後使用 Local 請求的解析結果都會被檢查，路由表命中會直接返回結果，命中失敗將丟棄解析結果並向境外伺服器再次發起請求
    * 本功能只能在 Local Main 為啟用狀態時才能啟用

* Addresses - 普通模式位址區域
  * IPv4 Listen Address - IPv4 本地監聽位址：需要輸入一個帶埠格式的位址，留空為不啟用
    * 支援多個位址
    * 填入此值後 IPv4 協定的 Operation Mode 和 Listen Port 參數將被自動忽略
  * IPv4 EDNS Client Subnet Address - IPv4 用戶端子網位址：需要輸入一個帶前置長度的本機公共網路位址，留空為不啟用
    * 啟用本功能前需要啟用 EDNS Client Subnet 總開關，否則將直接忽略此參數
  * IPv4 DNS Address - IPv4 主要 DNS 伺服器位址：需要輸入一個帶埠格式的位址，留空為不啟用
    * 支援多個位址
    * 支援使用服務名稱代替埠號
  * IPv4 Alternate DNS Address - IPv4 備用 DNS 伺服器位址：需要輸入一個帶埠格式的位址，留空為不啟用
    * 支援多個位址
    * 支援使用服務名稱代替埠號
  * IPv4 Local DNS Address - IPv4 主要境內 DNS 伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，留空為不啟用
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * IPv4 Local Alternate DNS Address - IPv4 備用境內 DNS 伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，留空為不啟用
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * IPv6 Listen Address - IPv6 本地監聽位址：需要輸入一個帶埠格式的位址，留空為不啟用
    * 支援多個位址
    * 填入此值後 IPv6 協定的 Operation Mode 和 Listen Port 參數將被自動忽略
  * IPv6 EDNS Client Subnet Address - IPv6 用戶端子網位址：需要輸入一個帶前置長度的本機公共網路位址，留空為不啟用
    * 啟用本功能前需要啟用 EDNS Client Subnet 總開關，否則將直接忽略此參數
  * IPv6 DNS Address - IPv6 主要 DNS 伺服器位址：需要輸入一個帶埠格式的位址，留空為不啟用
    * 支援多個位址
    * 支援使用服務名稱代替埠號
  * IPv6 Alternate DNS Address - IPv6 備用 DNS 伺服器位址：需要輸入一個帶埠格式的位址，留空為不啟用
    * 支援多個位址
    * 支援使用服務名稱代替埠號
  * IPv6 Local DNS Address - IPv6 主要境內 DNS 伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，留空為不啟用
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * IPv6 Local Alternate DNS Address - IPv6 備用境內 DNS 伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，留空為不啟用
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * 注意：
    * 單個 IPv4 位址格式為 "IPv4 位址:埠"，單個 IPv6 位址格式為"[IPv6 位址]:埠"，帶前置長度位址格式為 "IP 位址/網路前置長度"（均不含引號）
    * 多個 IPv4 位址格式為 "位址A:埠|位址B:埠|位址C:埠"，多個 IPv6 位址格式為 "[位址A]:埠| [位址B]:埠| [位址C]:埠"（均不含引號），啟用同時請求多伺服器後將同時向清單中的伺服器請求解析功能變數名稱，並採用最快回應的伺服器的結果，同時請求多伺服器啟用後將自動啟用 Alternate Multi Request 參數（參見下文）
    * 可填入的伺服器數量為：填入主要/待命伺服器的數量 * Multi Request Times = 總請求的數值，此數值不能超過 64
	* 指定埠時可使用服務名稱代替：
      * TCPMUX/1
      * ECHO/7
      * DISCARD/9
      * SYSTAT/11
      * DAYTIME/13
      * NETSTAT/15
      * QOTD/17
      * MSP/18
      * CHARGEN/19
      * FTP_DATA/20
      * FTP_DATA/21
      * SSH/22
      * TELNET/23
      * SMTP/25
      * TIMESERVER/37
      * RAP/38
      * RLP/39
      * NAMESERVER/42
      * WHOIS/43
      * TACACS/49
      * DNS/53
      * XNSAUTH/56
      * MTP/57
      * BOOTPS/67
      * BOOTPC/68
      * TFTP/69
      * RJE/77
      * FINGER/79
      * TTYLINK/87
      * SUPDUP/95
      * SUNRPC/111
      * SQL/118
      * NTP/123
      * EPMAP/135
      * NETBIOS_NS/137
      * NETBIOS_DGM/138
      * NETBIOS_SSN/139
      * IMAP/143
      * BFTP/152
      * SGMP/153
      * SQLSRV/156
      * DMSP/158
      * SNMP/161
      * SNMP_TRAP/162
      * ATRTMP/201
      * ATHBP/202
      * QMTP/209
      * IPX/213
      * IMAP3/220
      * BGMP/246
      * TSP/318
      * IMMP/323
      * ODMR/366
      * RPC2PORTMAP/369
      * CLEARCASE/371
      * HPALARMMGR/383
      * ARNS/384
      * AURP/387
      * LDAP/389
      * UPS/401
      * SLP/427
      * HTTPS/443
      * SNPP/444
      * MICROSOFTDS/445
      * KPASSWD/464
      * TCPNETHASPSRV/475
      * RETROSPECT/497
      * ISAKMP/500
      * BIFFUDP/512
      * WHOSERVER/513
      * SYSLOG/514
      * ROUTERSERVER/520
      * NCP/524
      * COURIER/530
      * COMMERCE/542
      * RTSP/554
      * NNTP/563
      * HTTPRPCEPMAP/593
      * IPP/631
      * LDAPS/636
      * MSDP/639
      * AODV/654
      * FTPSDATA/989
      * FTPS/990
      * NAS/991
      * TELNETS/992

* Values - 擴展參數值區域
  * Buffer Queue Limits - 資料緩衝區佇列數量限制：單位為個，最小為 8 最大為 1488095
    * 啟用 Queue Limits Reset Time 參數時，此參數為單位時間內最多可接受請求的數量
    * 不啟用 Queue Limits Reset Time 參數時為用於接收資料的緩衝區的數量，由於記憶體資料的複製比網路 I/O 快超過一個數量級，故此情況下不需要設置太多緩衝區
  * Queue Limits Reset Time - 資料緩衝區佇列數量限制重置時間：單位為秒，設置為 0 時關閉此功能
  * EDNS Payload Size - EDNS 標籤附帶使用的最大載荷長度：最小為 DNS 協定實現要求的 512(bytes)，留空則使用 EDNS 標籤要求最短的 1220(bytes)
  * IPv4 TTL - IPv4 主要 DNS 伺服器接受請求的遠端 DNS 伺服器資料包的 TTL 值：0 為自動獲取，取值為 1-255 之間
    * 支援多個 TTL 值，與 IPv4 DNS Address 相對應
  * IPv4 Alternate TTL - IPv4 備用 DNS 伺服器接受請求的遠端 DNS 伺服器資料包的 TTL 值：0 為自動獲取，取值為 1-255 之間
    * 支援多個 TTL 值，與 IPv4 Alternate DNS Address 相對應
  * IPv6 Hop Limits - IPv6 主要 DNS 伺服器接受請求的遠端 DNS 伺服器資料包的 Hop Limits 值：0 為自動獲取，取值為 1-255 之間
    * 支援多個 Hop Limits 值，與 IPv6 DNS Address 相對應
  * IPv6 Alternate Hop Limits - IPv6 備用 DNS 伺服器接受請求的遠端 DNS 伺服器資料包的 Hop Limits 值：0 為自動獲取，取值為 1-255 之間
    * 支援多個 Hop Limits 值，與 IPv6 Alternate DNS Address 相對應
  * Hop Limits Fluctuation - IPv4 TTL/IPv6 Hop Limits 可接受範圍，即 IPv4 TTL/IPv6 Hop Limits 的值 ± 數值的範圍內的資料包均可被接受，用於避免網路環境短暫變化造成解析失敗的問題：取值為 1-255 之間
  * Reliable Socket Timeout - 可靠協定埠超時時間，可靠埠指 TCP 協定：最小為 500，可留空，留空時為 3000，單位為毫秒
  * Unreliable Socket Timeout - 不可靠協定埠超時時間，不可靠埠指 UDP/ICMP/ICMPv6 協定：最小為 500，可留空，留空時為 2000，單位為毫秒
  * Receive Waiting - 資料包接收等待時間，啟用後程式會嘗試等待一段時間以嘗試接收所有資料包並返回最後到達的資料包：單位為毫秒，留空或填 0 表示關閉此功能
    * 本參數與 Pcap Reading Timeout 密切相關，由於抓包模組每隔一段讀取超時時間才會返回給程式一次，當資料包接收等待時間小於讀取超時時間時會導致本參數變得沒有意義，在一些情況下甚至會拖慢功能變數名稱解析的回應速度
    * 本參數啟用後雖然本身只決定抓包模組的接收等待時間，但同時會影響到非抓包模組的請求。 非抓包模組會自動切換為等待超時時間後發回最後收到的回復，預設為接受最先到達的正確的回復，而它們的超時時間由 Reliable Socket Timeout/Unreliable Socket Timeout 參數決定
	* 一般情況下，越靠後所收到的資料包，其可靠性可能會更高
  * ICMP Test - ICMP/Ping 測試間隔時間：單位為秒，最短間隔時間為5秒
  * Domain Test - DNS 伺服器解析功能變數名稱測試間隔時間：單位為秒，最短間隔時間為 5 秒
  * Alternate Times - 待命伺服器失敗次數閾值，一定週期內如超出閾值會觸發伺服器切換
  * Alternate Time Range - 待命伺服器失敗次數閾值計算週期：單位為秒，預設為 60秒/1分鐘
  * Alternate Reset Time - 待命伺服器重置切換時間，切換產生後經過此事件會切換回主要伺服器：單位為秒
  * Multi Request Times - 一次向同一個遠端伺服器發送並行功能變數名稱解析請求：0 和 1 時為收到一個請求時請求 1 次，2 時為收到一個請求時請求 2 次，3 時為收到一個請求時請求 3 次...... 以此類推
    * 此值將應用到 Local Hosts 外對所有遠端伺服器所有協定的請求，因此可能會對系統以及遠端伺服器造成壓力，請謹慎考慮開啟的風險！
    * 可填入的最大數值為：填入主要/待命伺服器的數量 * Multi Request Times = 總請求的數值，此數值不能超過 64
    * 一般除非丟包非常嚴重干擾正常使用否則不建議開啟，開啟也不建議將值設得太大。 實際使用可以每次+1後重啟服務測試效果，找到最合適的值
  * 注意：
    * IPv4 協定使用多 TTL 值的格式為 "TTL(A)|TTL(B)|TTL(C)"（不含引號），也可直接預設（即只填一個 0 不使用此格式）則所有 TTL 都將由程式自動獲取
    * 使用同時請求多伺服器格式為 "Hop Limits(A)|Hop Limits(B)|Hop Limits(C)"（不含引號），也可直接預設（即只填一個 0 不使用此格式）則所有 Hop Limits 都將由程式自動獲取
    * 使用多 TTL/Hop Limits 值所對應的順序與對應位址參數中的位址順序相同

* Switches - 控制開關區域
  * TCP Fast Open - TCP 快速打開功能：開啟為 1 /關閉為 0
    * 目前本功能只支援 Linux 平臺，非 Linux 平臺將直接忽略此參數，其中：
      * IPv4 需要 3.7 以及更新版本的內核支援
      * IPv6 需要 3.16 以及更新版本的內核支援
      * 切勿在不受支援的內核版本上開啟本功能，否則可能導致程式無法正常收發資料包！
    * 開啟系統對本功能的支援：
      * 臨時支援：需要在擁有 ROOT 許可權的終端執行 echo 3 > /proc/sys/net/ipv4/tcp_fastopen
      * 長期支援：
        * 在 /etc/rc.local 檔最下面添加 echo 3 > /proc/sys/net/ipv4/tcp_fastopen 保存，以後每次啟動都將自動設置此值
        * 在 /etc/sysctl.conf 檔中添加 net.ipv4.tcp_fastopen = 3 保存
  * Domain Case Conversion - 隨機轉換功能變數名稱請求大小寫：開啟為 1 /關閉為 0
  * Compression Pointer Mutation - 隨機添加壓縮指標：可填入 1 (+ 2 + 3)，關閉為 0 
    * 隨機添加壓縮指標有3種不同的類型，對應 1 和 2 和 3
    * 可單獨使用其中一個，即只填一個數位，或填入多個，中間使用 + 號連接
    * 填入多個時，當實際需要使用隨機添加壓縮指標時將隨機使用其中的一種，每個請求都有可能不相同
  * EDNS Label - EDNS 標籤支援，開啟後將為所有請求添加 EDNS 標籤：開啟為 1 /關閉為 0
  * EDNS Client Subnet - EDNS 用戶端子網支援，開啟後將為所有請求添加 EDNS 用戶端子網資訊：開啟為 1 /關閉為 0
    * 本功能要求啟用 EDNS Label 參數
  * DNSSEC Request - DNSSEC 請求，開啟後將嘗試為所有請求添加 DNSSEC 請求：開啟為 1 /關閉為 0
    * 本功能要求啟用 EDNS Label 參數
    * 此功能不具備任何驗證 DNSSEC 記錄的能力，單獨開啟理論上並不能避免 DNS 投毒污染的問題
  * DNSSEC Validation - DNSSEC 記錄驗證功能，將檢查所有帶有 DNSSEC 記錄的功能變數名稱解析，驗證失敗將被丟棄：開啟為 1 /關閉為 0
    * 本功能要求啟用 EDNS Label 和 DNSSEC Request 參數
    * 此功能不具備完整的 DNSSEC 記錄檢驗的能力，單獨開啟理論上不能避免 DNS 投毒污染的問題
    * 本功能不檢查不存在 DNSSEC 記錄的功能變數名稱解析
  * DNSSEC Force Validation - 強制 DNSSEC 記錄驗證功能，將丟棄所有沒有 DNSSEC 記錄的功能變數名稱解析：開啟為 1 /關閉為 0
    * 本功能要求啟用 EDNS Label、DNSSEC Request 和 DNSSEC Validation 參數
    * 此功能不具備完整的 DNSSEC 記錄檢驗的能力，單獨開啟理論上不能避免 DNS 投毒污染的問題
    * 警告：由於現時已經部署 DNSSEC 的功能變數名稱數量極少，未部署 DNSSEC 的功能變數名稱解析沒有 DNSSEC 記錄，這將導致所有未部署 DNSSEC 的功能變數名稱解析失敗，現階段切勿開啟本功能！
  * Alternate Multi Request - 待命伺服器同時請求參數，開啟後將同時請求主要伺服器和待命伺服器並採用最快回應的伺服器的結果：開啟為 1 /關閉為 0
    * 同時請求多伺服器啟用後本參數將強制啟用，將同時請求所有存在於清單中的伺服器，並採用最快回應的伺服器的結果
  * IPv4 Data Filter - IPv4 資料包頭檢測：開啟為 1 /關閉為 0
  * TCP Data Filter - TCP 資料包頭檢測：開啟為 1 /關閉為 0
  * DNS Data Filter - DNS 資料包頭檢測：開啟為 1 /關閉為 0
  * Blacklist Filter - 解析結果黑名單過濾：開啟為 1 /關閉為 0

* Data - 資料區域
  * ICMP ID - ICMP/Ping 資料包頭部 ID 的值：格式為 0x**** 的十六進位字元，如果留空則獲取執行緒的 ID 作為請求用 ID
  * ICMP Sequence - ICMP/Ping 資料包頭部 Sequence/序號 的值：格式為 0x**** 的十六進位字元，如果留空則為 0x0001
  * Domain Test Data - DNS 伺服器解析功能變數名稱測試：請輸入正確、確認不會被投毒污染的功能變數名稱並且不要超過 253 位元組 ASCII 資料，留空則會隨機生成一個功能變數名稱進行測試
  * Domain Test ID - DNS 資料包頭部 ID 的值：格式為 0x**** 的十六進位字元，如果留空則為 0x0001
  * ICMP PaddingData - ICMP 附加資料，Ping 程式發送請求時為補足資料使其達到 Ethernet 類型網路最低的可發送長度時添加的資料：長度介乎于 18位元組 - 1500位元組 ASCII 資料之間，留空則使用 Microsoft Windows Ping 程式的 ICMP 附加資料
  * Localhost Server Name - 本地DNS伺服器名稱：請輸入正確的功能變數名稱並且不要超過 253 位元組 ASCII 資料，留空則使用 pcap-dnsproxy.localhost.server 作為本機伺服器名稱

* Proxy - 代理區域
  * SOCKS Proxy - SOCKS 協定總開關，控制所有和 SOCKS 協定有關的選項：開啟為 1 /關閉為 0
  * SOCKS Version - SOCKS 協定所使用的版本：可填入 4 或 4A 或 5
    * SOCKS 版本 4 不支援 IPv6 位址以及功能變數名稱的目標伺服器，以及不支援 UDP 轉發功能
    * SOCKS 版本 4a 不支援 IPv6 位址的目標伺服器，以及不支援 UDP 轉發功能
  * SOCKS Protocol - 發送 SOCKS 協定請求所使用的協定：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的協定可隨意組合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 時，只使用指定協定向 SOCKS 伺服器發出請求
    * 同時填入 IPv4 和 IPv6 或直接不填任何網路層協定時，程式將根據網路環境自動選擇所使用的協定
    * 同時填入 TCP 和 UDP 等於只填入 UDP 因為 TCP 為 SOCKS 最先支援以及最普遍支援的標準網路層協定，所以即使填入 UDP 請求失敗時也會使用 TCP 請求
  * SOCKS Reliable Socket Timeout - 可靠 SOCKS 協定埠超時時間，可靠埠指 TCP 協定：最小為 500，可留空，留空時為 6000，單位為毫秒
  * SOCKS Unreliable Socket Timeout - 不可靠 SOCKS 協定埠超時時間，不可靠埠指 UDP 協定：最小為 500，可留空，留空時為 3000，單位為毫秒
  * SOCKS UDP No Handshake - SOCKS UDP 不握手模式，開啟後將不進行 TCP 握手直接發送 UDP 轉發請求：開啟為 1 /關閉為 0
    * SOCKS 協定的標準流程使用 UDP 轉發功能前必須使用 TCP 連接交換握手資訊，否則 SOCKS 伺服器將直接丟棄轉發請求
    * 部分 SOCKS 本地代理可以直接進行 UDP 轉發而不需要使用 TCP 連接交換握手資訊，啟用前請務必確認 SOCKS 伺服器的支援情況
  * SOCKS Proxy Only - 只使用 SOCKS 協定代理模式：開啟為 1 /關閉為 0
  * SOCKS IPv4 Address - SOCKS 協定 IPv4 主要 SOCKS 伺服器位址：需要輸入一個帶埠格式的位址
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * SOCKS IPv6 Address - SOCKS 協定 IPv6 主要 SOCKS 伺服器位址：需要輸入一個帶埠格式的位址
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * SOCKS Target Server - SOCKS 最終目標伺服器：需要輸入一個帶埠格式的 IPv4/IPv6 位址或功能變數名稱
    * 不支援多個位址或功能變數名稱，只能填入單個位址或功能變數名稱
    * 支援使用服務名稱代替埠號
  * SOCKS Username - 連接 SOCKS 伺服器時所使用的使用者名：最長可填入 255 個字元，留空為不啟用
  * SOCKS Password - 連接 SOCKS 伺服器時所使用的密碼：最長可填入 255 個字元，留空為不啟用

* DNSCurve - DNSCurve 協定基本參數區域
  * DNSCurve - DNSCurve 協定總開關，控制所有和 DNSCurve 協定有關的選項：開啟為 1 /關閉為 0
  * DNSCurve Protocol - DNSCurve 發送請求所使用的協定：可填入 IPv4 和 IPv6 和 TCP 和 UDP
    * 填入的協定可隨意組合，只填 IPv4 或 IPv6 配合 UDP 或 TCP 時，只使用指定協定向遠端 DNS 伺服器發出請求
    * 同時填入 IPv4 和 IPv6 或直接不填任何網路層協定時，程式將根據網路環境自動選擇所使用的協定
    * 同時填入 TCP 和 UDP 等於只填入 TCP 因為 UDP 為 DNS 的標準網路層協定，所以即使填入 TCP 失敗時也會使用 UDP 請求
  * DNSCurve Payload Size - DNSCurve EDNS 標籤附帶使用的最大載荷長度，同時亦為發送請求的總長度，並決定請求的填充長度：最小為 DNS 協定實現要求的 512(bytes)，留空則為 512(bytes)
  * DNSCurve Reliable Socket Timeout - 可靠 DNSCurve 協定埠超時時間，可靠埠指 TCP 協定：最小為 500，可留空，留空時為 3000，單位為毫秒
  * DNSCurve Unreliable Socket Timeout - 不可靠 DNSCurve 協定埠超時時間，不可靠埠指 UDP 協定：最小為 500，可留空，留空時為 2000，單位為毫秒
  * Encryption - 啟用加密，DNSCurve 協定支援加密和非加密模式：開啟為 1 /關閉為 0
  * Encryption Only - 只使用加密模式：開啟為 1 /關閉為 0
    * 注意：使用 "只使用加密模式" 時必須提供伺服器的魔數和指紋用於請求和接收
  * Client Ephemeral Key - 一次性用戶端金鑰組模式：每次請求解析均使用隨機生成的一次性用戶端金鑰組：開啟為 1 /關閉為 0
  * Key Recheck Time - DNSCurve 協定DNS伺服器連接資訊檢查間隔：單位為秒，最短為10秒800 秒

* DNSCurve Addresses - DNSCurve 協定位址區域
  * DNSCurve IPv4 DNS Address - DNSCurve 協定 IPv4 主要 DNS 伺服器位址：需要輸入一個帶埠格式的位址
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * DNSCurve IPv4 Alternate DNS Address - DNSCurve 協定 IPv4 備用 DNS 伺服器位址：需要輸入一個帶埠格式的位址
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * DNSCurve IPv6 DNS Address - DNSCurve 協定 IPv6 主要 DNS 伺服器位址：需要輸入一個帶埠格式的位址
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * DNSCurve IPv6 Alternate DNS Address - DNSCurve 協定 IPv6 備用 DNS 伺服器位址：需要輸入一個帶埠格式的位址
    * 不支援多個位址，只能填入單個位址
    * 支援使用服務名稱代替埠號
  * DNSCurve IPv4 Provider Name - DNSCurve 協定 IPv4 主要 DNS 伺服器提供者，請輸入正確的功能變數名稱並且不要超過 253 位元組 ASCII 資料
  * DNSCurve IPv4 Alternate Provider Name - DNSCurve 協定 IPv4 備用 DNS 伺服器提供者，請輸入正確的功能變數名稱並且不要超過 253 位元組 ASCII 資料
  * DNSCurve IPv6 Provider Name - DNSCurve 協定 IPv6 主要 DNS 伺服器提供者，請輸入正確的功能變數名稱並且不要超過 253 位元組 ASCII 資料
  * DNSCurve IPv6 Alternate Provider Name - DNSCurve 協定 IPv6 備用 DNS 伺服器提供者，請輸入正確的功能變數名稱並且不要超過 253 位元組 ASCII 資料
  * 注意：
    * 自動獲取 DNSCurve 伺服器連接資訊時必須輸入提供者的功能變數名稱，不能留空
    * 更多支援 DNSCurve/DNSCrypt 的伺服器請移步 https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv

* DNSCurve Keys - DNSCurve 協定金鑰區域
  * Client Public Key - 自訂用戶端公開金鑰：可使用 KeyPairGenerator 生成，留空則每次啟動時自動生成
  * Client Secret Key - 自訂用戶端私密金鑰：可使用 KeyPairGenerator 生成，留空則每次啟動時自動生成
  * IPv4 DNS Public Key - DNSCurve 協定 IPv4 主要 DNS 伺服器驗證用公開金鑰
  * IPv4 Alternate DNS Public Key - DNSCurve 協定 IPv4 備用 DNS 伺服器驗證用公開金鑰
  * IPv6 DNS Public Key - DNSCurve 協定 IPv6 主要 DNS 伺服器驗證用公開金鑰
  * IPv6 Alternate DNS Public Key - DNSCurve 協定 IPv6 備用 DNS 伺服器驗證用公開金鑰
  * IPv4 DNS Fingerprint - DNSCurve 協定 IPv4 主要 DNS 伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取
  * IPv4 Alternate DNS Fingerprint - DNSCurve 協定 IPv4 備用 DNS 伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取
  * IPv6 DNS Fingerprint - DNSCurve 協定 IPv6 備用 DNS 伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取
  * IPv6 Alternate DNS Fingerprint - DNSCurve 協定 IPv6 備用 DNS 伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取
  * 注意：
    * 公開網站上的 "公開金鑰" 普遍為驗證用的公開金鑰，用於驗證與伺服器通訊時使用的指紋，兩者為不同性質的公開金鑰不可混用！

* DNSCurve Magic Number - DNSCurve 協定魔數區域
  * IPv4 Receive Magic Number - DNSCurve 協定 IPv4 主要 DNS 伺服器接收魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則使用程式內置的接收魔數
  * IPv4 Alternate Receive Magic Number - DNSCurve 協定 IPv4 備用 DNS 伺服器接收魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則使用程式內置的接收魔數
  * IPv6 Receive Magic Number - DNSCurve 協定 IPv6 主要 DNS 伺服器接收魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則使用程式內置的接收魔數
  * IPv6 Alternate Receive Magic Number - DNSCurve 協定 IPv6 備用 DNS 伺服器接收魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則使用程式內置的接收魔數
  * IPv4 DNS Magic Number - DNSCurve 協定 IPv4 主要 DNS 伺服器發送魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則自動獲取
  * IPv4 Alternate DNS Magic Number - DNSCurve 協定 IPv4 備用 DNS 伺服器發送魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則自動獲取
  * IPv6 DNS Magic Number - 協定 IPv6 主要 DNS 伺服器發送魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則自動獲取
  * IPv6 Alternate DNS Magic Number - DNSCurve 協定 IPv6 備用 DNS 伺服器發送魔數：長度必須為 8 位元組（ASCII）或 18 位元組（十六進位），留空則自動獲取
  * 注意：Magic Number 參數均同時支援使用 ASCII 字元或十六進位字串進行指定
    * 直接填入可列印 ASCII 字串即可
    * 十六進位字串需要在字串前面加上 0x（大小寫敏感）


-------------------------------------------------------------------------------


設定檔自動刷新支援參數清單：

* 以下清單中的參數在寫入設定檔後會自動刷新而無須重新開機程式，其它參數的刷新則必須重新開機程式
* 如非必要建議不要依賴程式的自動刷新功能，強烈建議修改設定檔後重新開機程式！

* Version
* File Refresh Time
* Print Error
* Log Maximum Size
* IPFilter Type
* IPFilter Level
* Accept Type
* Direct Request
* Default TTL
* Local Protocol
* IPv4 TTL
* IPv6 HopLimits
* IPv4 AlternateTTL
* IPv6 AlternateHopLimits
* HopLimits Fluctuation
* Reliable Socket Timeout
* Unreliable Socket Timeout
* Receive Waiting
* ICMP Test
* Domain Test
* Multi Request Times
* Domain Case Conversion
* IPv4 Data Filter
* TCP Data Filter
* DNS Data Filter
* SOCKS Reliable Socket Timeout
* SOCKS Unreliable Socket Timeout
* SOCKS Target Server
* SOCKS Username
* SOCKS Password
* DNSCurve Reliable Socket Timeout
* DNSCurve Unreliable Socket Timeout
* Key Recheck Time
* Client Public Key
* Client Secret Key
* IPv4 DNS Public Key
* IPv4 Alternate DNS Public Key
* IPv6 DNS Public Key
* IPv6 Alternate DNS Public Key
* IPv4 DNS Fingerprint
* IPv4 Alternate DNS Fingerprint
* IPv6 DNS Fingerprint
* IPv6 Alternate DNS Fingerprint
* IPv4 Receive Magic Number
* IPv4 Alternate Receive Magic Number
* IPv6 Receive Magic Number
* IPv6 Alternate Receive Magic Number
* IPv4 DNS Magic Number
* IPv4 Alternate DNS Magic Number
* IPv6 DNS Magic Number
* IPv6 Alternate DNS Magic Number


-------------------------------------------------------------------------------


Hosts 檔案格式說明：

Hosts 設定檔分為多個提供不同功能的區域
* 區域通過標籤識別，修改時切勿將其刪除
* 優先順序：Local Hosts/境內DNS解析功能變數名稱清單 > Hosts/主要Hosts清單，Whitelist/白名單條目 和 Banned/黑名單條目 的優先順序由位置決定，參見下文詳細說明
* 一條條目的總長度切勿超過 4096位元組/4KB
* 需要注釋請在條目開頭添加 #/井號
* 優先順序別自上而下遞減，條目越前優先順序越高
* 平行 Hosts 條目支援數量由請求功能變數名稱以及 EDNS Payload 長度決定，不要超過75個 A 記錄或43個 AAAA 記錄


* Whitelist - 白名單條目
  * 此類型的條目列出的符合要求的功能變數名稱會直接繞過 Hosts 不會使用 Hosts 功能
  * 有效參數格式為 "NNULL 正則運算式"（不含引號）
  * 注意優先順序的問題，例如有一片含白名單條目的區域：

    NULL .*\.test.localhost
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost

  * 雖然 .*\.localhost 包含了 .*\.test\.localhost 但由於優先順序別自上而下遞減，故先命中 .*\.test\.localhost 並返回使用遠端伺服器解析
  * 從而繞過了下面的條目，不使用 Hosts 的功能

* Whitelist Extended - 白名單條目擴展功能
  * 此類型的條目還支援對符合規則的特定類型功能變數名稱請求直接繞過 Hosts 不會使用 Hosts 功能
  * 有效參數格式為 "NULL:DNS類型(| DNS類型) 正則運算式"（不含引號）
  * 只允許特定類型功能變數名稱請求，有效參數格式為 "NULL(Permit):DNS類型(| DNS類型) 正則運算式"（不含引號）

    NULL:A| AAAA .*\.test.localhost
    NULL(Deny):NS| SOA .*\.localhost

  * 第一條即直接跳過匹配規則的 A 記錄和 AAAA 記錄的功能變數名稱請求，其它類型的請求則被匹配規則
  * 而第二條則只匹配規則的 NS 記錄和 SOA 記錄的功能變數名稱請求，其它類型的請求則被直接跳過

* Banned - 黑名單條目
  * 此類型的條目列出的符合要求的功能變數名稱會直接返回功能變數名稱不存在的功能，避免重定向導致的超時問題
  * 有效參數格式為 "BANNED 正則運算式"（不含引號）
  * 注意優先順序的問題，例如有一片含黑名單條目的區域：

    Banned .*\.test.localhost
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost

  * 雖然 .*\.localhost 包含了 .*\.test\.localhost 但由於優先順序別自上而下遞減，故先命中 .*\.test\.localhost 並直接返回功能變數名稱不存在
  * 從而繞過了下面的條目，達到遮罩功能變數名稱的目的

* Banned Extended - 黑名單條目擴展功能
  * 此類型的條目還支援對符合規則的特定類型功能變數名稱請求進行遮罩或放行
  * 有效參數格式為 "BANNED:DNS類型(| DNS類型) 正則運算式"（不含引號）
  * 只允許特定類型功能變數名稱請求，有效參數格式為 "BANNED(Permit):DNS類型(| DNS類型) 正則運算式"（不含引號）

    BANNED:A|AAAA .*\.test.localhost
    BANNED(Permit):NS|SOA .*\.localhost

  * 第一条即屏蔽匹配规则的 A 记录和 AAAA 记录的域名请求，其它类型的请求则被放行
  * 而第二条则只放行匹配规则的 NS 记录和 SOA 记录的域名请求，其它类型的请求则被屏蔽

* Hosts - 主要 Hosts 清單
有效參數格式為 "位址(|位址A|位址B) 正則運算式"（不含引號，括弧內為可選項目，注意間隔所在的位置）
  * 位址與正則運算式之間的間隔字元可為 Space/半形空格 或者 HT/水準定位符號，間隔長度不限，但切勿輸入全形空格
  * 一條條目只能接受一種網址類別型（IPv4/IPv6），如有同一個功能變數名稱需要同時進行 IPv4/IPv6 的 Hosts，請分為兩個條目輸入
  * 平行位址原理為一次返回多個記錄，而具體使用哪個記錄則由要求者決定，一般為第1個
  * 例如有一個 [Hosts] 下有效資料區域：

    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3 .*\.test\.localhost
    ::4|::5|::6 .*\.localhost

  * 雖然 .*\.localhost 包含了 .*\.test\.localhost 但由於優先順序別自上而下遞減，故先命中 .*\.test\.localhost 並直接返回，不會再進行其它檢查
    * 請求解析 xxx.localhost 的 A 記錄（IPv4）會返回 127.0.0.4、127.0.0.5 和 127.0.0.6
    * 請求解析 xxx.localhost 的 AAAA 記錄（IPv6）會返回 ::4、::5和::6
    * 請求解析 xxx.test.localhost 的 A 記錄（IPv4）會返回 127.0.0.1、127.0.0.2和127.0.0.3
    * 請求解析 xxx.test.localhost 的 AAAA 記錄（IPv6）會返回 ::1、::2和::3

* Local Hosts - 境內 DNS 解析功能變數名稱清單
本區域資料用於為功能變數名稱使用境內 DNS 伺服器解析提高存取速度，使用時請確認境內 DNS 伺服器位址不為空（參見上文 設定檔詳細參數說明 一節）
有效參數格式為 "正則運算式"（不含引號）
  * 要使用本功能，必須將設定檔內的 Local Hosts 選項打開！
  * 本功能不會對境內 DNS 伺服器回復進行任何過濾，請確認本區域填入的資料不會受到 DNS 投毒污染的干擾
  * 例如有一個 [Local Hosts] 下有效資料區域：

    .*\.test\.localhost
    .*\.localhost

  * 即所有符合以上正則運算式的功能變數名稱請求都將使用境內 DNS 伺服器解析

* Address Hosts - 解析結果位址其他清單
  * 本區域資料用於替換解析結果中的位址，提供更精確的 Hosts 自訂能力
  * 例如有一個 [Address Hosts] 下有效資料區域：

    127.0.0.1|127.0.0.2 127.0.0.0-127.255.255.255
    ::1 ::-::FFFF

  * 解析結果的位址範圍為 127.0.0.0 到 127.255.255.255 時將被替換為 127.0.0.1 或 127.0.0.2
  * 解析結果的位址範圍為 :: 到 ::FFFF 時將被替換為 ::1

* Stop - 臨時停止讀取標籤
  * 在需要停止讀取的資料前添加 "[Stop]"（不含引號） 標籤即可在中途停止對檔的讀取，直到有其它標籤時再重新開始讀取
  * 例如有一片資料區域：

    [Hosts]
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    [Stop]
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3 .*\.test\.localhost
    ::4|::5|::6 .*\.localhost

    [Local Hosts]
    .*\.test\.localhost
    .*\.localhost

  * 則從 [Stop] 一行開始，下面到 [Local Hosts] 之間的資料都將不會被讀取
  * 即實際有效的資料區域是：

    [Hosts]
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost

    [Local Hosts]
    .*\.test\.localhost
    .*\.localhost


-------------------------------------------------------------------------------


IPFilter 檔案格式說明：

IPFilter 設定檔分為 Blacklist/黑名單區域 和 IPFilter/位址過濾區域 以及 Local Routing/境內路由表區域
* 區域通過標籤識別，修改時切勿將其刪除
* 一條條目的總長度切勿超過4096位元組/4KB
* 需要注釋請在條目開頭添加 #/井號


* Blacklist - 黑名單區域
當 Blacklist Filter 為開啟時，將檢查本清單功能變數名稱與解析結果，如果解析結果裡含有與功能變數名稱對應的黑名單位址，則會直接丟棄此解析結果
有效參數格式為 "位址(|位址A|位址B) 正則運算式"（不含引號，括弧內為可選項目，注意間隔所在的位置）
  * 位址與正則運算式之間的間隔字元可為 Space/半形空格 或者 HT/水準定位符號，間隔長度不限，但切勿輸入全形空格
  * 一條條目只能接受一種網址類別型（IPv4/IPv6），如有同一個功能變數名稱需要同時進行 IPv4/IPv6 位址的過濾，請分為兩個條目輸入

* IPFilter - 位址過濾區域
位址過濾黑名單或白名單由設定檔的 IPFilter Type 值決定，Deny 禁止/黑名單和 Permit 允許/白名單
有效參數格式為 "開始位址 - 結束位址, 過濾等級, 條目簡介注釋"（不含引號）
  * 同時支援 IPv4 和 IPv6 位址，但填寫時請分開為2個條目
  * 同一類型的位址位址段有重複的條目將會被自動合併

* Local Routing - 境內路由表區域
當 Local Routing 為開啟時，將檢查本清單的路由表是否命中，檢查與否與功能變數名稱請求是否使用 Local 伺服器有關，路由表命中後會直接返回結果，命中失敗將丟棄解析結果並向境外伺服器再次發起請求
有效參數格式為 "位址塊/網路前置長度"（不含引號）
  * 本路由表支援 IPv4 和 IPv6 協定
  * IPv4 時網路前置長度範圍為 1-32，IPv6 時網路前置長度範圍為 1-128

* Stop - 臨時停止讀取標籤
在需要停止讀取的資料前添加 "[Stop]"（不含引號） 標籤即可在中途停止對檔的讀取，直到有其它標籤時再重新開始讀取
  * 具體情況參見上文的介紹


-------------------------------------------------------------------------------


程序運行參數說明：
由於部分功能無法通過使用配置文件指定使用，故而使用程序外掛參數進行支持
所有外掛參數也可通過-h 和--help 參數查詢

* -v 和 --version
  輸出程序版本號信息到屏幕上
* -h 和 --help
  輸出程序幫助信息到屏幕上
* --flush-dns
  立即清空所有程序內以及系統的 DNS 緩存
* --first-setup
  進行本地防火牆測試(Windows)
* -c Path 和 --config-file Path
  啟動時指定配置文件所在的以及程序的工作目錄
* --disable-daemon
  關閉守護進程模式(Linux)