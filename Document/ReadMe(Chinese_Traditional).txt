特別聲明：

Pcap_DNSProxy 僅供學習交流，遵循 GNU GPL 通用公共許可證 (GNU General Public License) ，切勿將其用於任何非法用途！
使用前請自行估量是否有載入 Pcap_DNSProxy 的需要，如果不能清楚判斷而造成之不良後果，專案組所有成員均不承擔一切責任！
使用 Pcap_DNSProxy 原始程式碼前務必參閱 LICENSE 通用公共許可證之內容！


Pcap_DNSProxy 專案的GitHub頁面：
* 主分支: https://github.com/chengr28/Pcap_DNSProxy
* Release 分支: https://github.com/chengr28/Pcap_DNSProxy/tree/Release

Pcap_DNSProxy 專案的Sourceforge頁面：
https://sourceforge.net/projects/pcap-dnsproxy


-------------------------------------------------------------------------------


Pcap_DNSProxy 是一個基於 LibPcap/WinPcap 製作的用於忽略DNS投毒污染的小工具，後期也加入了對包含正則運算式的Hosts和 DNSCurve/DNSCrypt 協定的支援
很多使用TCP協定進行解析的工具，可以用於忽略DNS投毒污染。但事實上已經出現有使用TCP協定請求功能變數名稱解析時被連接重置的情況，而使用UDP協定則又會被DNS投毒污染，導致其始終無法獲得正確的功能變數名稱解析。本工具主要工作在UDP協定上，可以將偽造的資料包完全過濾，同時UDP協定比起TCP協定更具有佔用資源低和發送轉發接收速度快等特點。本工具同時也支援使用TCP協定進行請求，而且在被連接重置時會自動切換到UDP協定，可以使要求者獲得正確的功能變數名稱解析
完全支援正則運算式 Hosts 條目，可以為消費者提供更加便捷的途徑設定功能變數名稱所對應的位址，避免修改系統檔的麻煩
本工具使用 C/C++ 編寫而成，使用 Visual Studio 2013/VC++ 進行編譯，完全支援 Unicode

Pcap_DNSProxy 的特點：
* 同時支援本地IPv4/IPv6協定監聽和遠端請求
* 普通DNS請求模式同時支援TCP/UDP協定
* Native Code 原生碼編譯，不含任何託管代碼，x64版為原生64位目標平臺編譯
* 作為系統服務工作于底層
* 多執行緒模型，充分利用多執行緒處理器的硬體資源
* 使用 WinPcap/LibPcap 利用系統底層驅動抓取資料包，多種過濾方式忽略接收到的偽造資料包
* 支援伺服器模式，相當於一個小型的DNS伺服器，能為其它設備提供解析服務，並可限制可請求的範圍
* 主要和備用雙伺服器模式，多個伺服器多次請求功能，提高DNS解析的可靠性
* DNS緩存功能
* 支援 EDNS0 標籤
* 支援 DNSCurve/DNSCrypt 協定
* Hosts Only 模式可只使用本工具支援正則運算式的 Hosts 的直連模式
* 支援 Local Hosts 境內DNS伺服器解析功能，可提高對境內功能變數名稱的解析速度和伺服器的存取速度
* 豐富的配置選項，讀取檔支援 ANSI、UTF-8(/BOM)、UTF-16(LE/BE) 和 UTF-32(LE/BE) 編碼以及 Windows/Unix/Macintosh 換行格式
* 錯誤報表功能

Pcap_DNSProxy 使用的庫：
* 正則運算式支援由 C++ STL(Windows)/系統自帶的正則庫(Linux/Mac) 提供
* 檔 Hash 使用的演算法由 SHA-3/Keccak 提供：http://keccak.noekeon.org
* 由 C++ STL 自帶的梅森旋轉演算法引擎產生離散型均勻分佈亂數，用於隨機功能變數名稱探測
* DNSCurve 協定使用的 Curve25519/Salsa20/Poly1305 演算法由 LibSodium 提供：https://github.com/jedisct1/libsodium
* DNSCurve 協定加密模式使用的一次性 Nonce 亦由 LibSodium 附帶的亂數產生器提供

Pcap_DNSProxy 支援平臺：
* 本工具抓包模組所支援的網路類型
  * 網路裝置類型為 Ethernet 的網路
  * 原生IPv4網路和原生IPv6網路（非原生IPv6網路環境建議不要開啟IPv6功能）
  * 基於PPPoE或PPPoEv6的IPv4網路和IPv6網路
  * 如果需要支援更多網路類型，可與作者聯繫
* Windows 平臺
  * Windows XP SP3/2003 SP2 以及更新內核的版本(32位/x86版本)和 Windows Vista/2008 以及更新的版本(64位/x64版本)
  * 支援最新版本 [WinPcap](http://www.winpcap.org/install/default.htm)
* Linux 平臺
  * 支援 [編譯所需依賴包](https://github.com/chengr28/Pcap_DNSProxy/wiki/ReadMe_Linux) 的Linux發行版本
  * 支援最新版本 [Libpcap](http://www.tcpdump.org)
* Mac 平臺
  * 採用Intel平臺處理器的 Mac OS X 10.5 Leopard 以及更新的版本


-------------------------------------------------------------------------------


安裝方法（需要以管理員身份進行）：

1.訪問 http://www.winpcap.org/install/default.htm 下載並以管理員許可權安裝 WinPcap
  * Release 版本壓縮包中也提供有 WinPcap 的安裝程式
  * WinPcap 只需要安裝一次，以後更新時請從第2步開始操作
  * 如果 WinPcap 提示已安裝舊版本無法繼續時，參見 FAQ 中 運行結果分析 一節
  * 安裝時自啟動選項對工具的運行沒有影響，因為本工具直接調用 WinPcap API，不需要經過伺服器程式
2.訪問 https://github.com/chengr28/Pcap_DNSProxy/tree/Release 並使用 GitHub 的 Download ZIP 功能將所有檔下載到本地
  * Windows 版本的 Pcap_DNSProxy 在 ZIP 的 Windows 目錄內，可將整個目錄單獨抽出運行
  * Windows 下批次處理會自動判斷 x64 和 x86 版本
3.打開下載回來的 ZIP 檔，將 Windows 目錄解壓到磁片的任意位置
  * 目錄所在位置和程式檔案名可以隨意更改
  * 注意：設定檔/Hosts檔和IPFilter檔只能使用固定的檔案名（更多詳細情況參見下文 功能和技術 一節）
4.確定工具目錄的名稱和路徑後進入目錄內，右鍵以管理員身份(Vista以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceInstall.bat
  * 批次處理會將程式註冊系統服務，並進行 Windows 防火牆測試
  * 以後每次開機服務都將自動啟動
5.此時 Windows 系統會詢問是否同意程式訪問網路，請將 "私人網路絡" 以及 "公用網路" 都勾上並確認
6.打開 "網路和共用中心" - "更改配接器設置" 選擇 "本地連接" 或 "無線連接" 或 "寬頻連線"
  * 右擊 "屬性" - "Internet協定(TCP/IP)"(XP/2003) 或 "Internet協定版本4(IPv4)"(Vista以及更新版本) - "屬性" - 勾選 "使用下面的DNS伺服器位址"
  * 在 "首選DNS伺服器" 內填入 "127.0.0.1"（不含引號） 確定保存並退出即可
  * 如果需要使用IPv6協定的本機伺服器
    * 請先編輯設定檔的 "IPv6 DNS Address" 一欄，參見下文 設定檔詳細參數說明 一節
    * 右擊 "屬性" - "Internet協定版本6(IPv6)" - "屬性" - 勾選 "使用下面的DNS伺服器位址"
    * 在 "首選DNS伺服器" 內填入 "::1"（不含引號） 確定保存並退出即可
  * 注意：建議將 "本地連接" 和 "無線連接" 以及 "寬頻連線" 全部修改！


重啟服務方法（需要以管理員身份進行）：

1.右鍵以管理員身份(Vista以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceStop.bat
  * 批次處理將直接停止服務的運行
2.右鍵以管理員身份(Vista以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceStart.bat 即可
  * 批次處理將啟動服務，完成後相當於重啟服務


更新程式方法（需要以管理員身份進行）：

注意：更新程式切勿直接覆蓋，否則可能會造成不可預料的錯誤！請按照以下的步驟進行：
1.提前下載好新版本的 Pcap_DNSProxy（亦即 安裝方法 中第2步），更新過程可能會造成功能變數名稱解析短暫中斷
2.備份好所有設定檔/Hosts檔/IPFilter檔的自訂內容
3.右鍵以管理員身份(Vista以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceStop.bat 停止服務
4.將整個 Pcap_DNSProxy 程式的目錄刪除
  * 注意 Windows 防火牆可能會留有允許程式訪問網路的資訊，卸載服務後又變更了程式的目錄則可能需要使用註冊表清理工具清理
5.將新版本的 Pcap_DNSProxy 解壓到任何位置（亦即 安裝方法 中第3步）
6.將設定檔的自訂內容加回新版本設定檔裡相應的區域內
7.按照 安裝方法 中第4步重新部署 Pcap_DNSProxy


安全模式下的使用方法（需要以管理員身份進行）：

程式具備在安全模式下運行的能力，在安全模式下右鍵以管理員身份直接運行程式
* 直接運行模式有主控台視窗，關閉程式時直接關閉主控台視窗即可
* 注意：直接運行可能會生成 Service start error, ERROR_FAILED_SERVICE_CONTROLLER_CONNECT(The service process could not connect to the service controller). 錯誤，因為程式是設計運行于系統服務模式，雖然也可直接運行但並不推薦


卸載方法（需要以管理員身份進行）：

1.按照 安裝方法 中第6步還原DNS功能變數名稱伺服器位址配置
2.右鍵以管理員身份(Vista以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceUninstall.bat 即可，批次處理將直接停止服務並卸載服務
  * 注意 Windows 防火牆可能會留有允許程式訪問網路的資訊，故卸載後可能需要使用註冊表清理工具清理
  * 轉移工具目錄路徑不需要卸載服務，先停止服務轉移，轉移完成後重新右鍵以管理員身份(Vista以及更新版本)或直接以管理員登錄按兩下(XP/2003)運行 ServiceInstall.bat 即可


正常工作查看方法：

1.打開命令提示符
  * 在開始功能表或直接 Win + R 調出 運行 ，輸入 cmd 並回車
  * 開始功能表 - 程式/所有程式 - 附件 - 命令提示符
2.輸入 nslookup www.google.com 並回車
3.運行結果應類似：

   >nslookup www.google.com
    服务器:  pcap-dnsproxy.localhost.server（視設定檔設置的值而定，參見下文 設定檔詳細參數說明 一節）
    Address:  127.0.0.1（視所在網路環境而定，原生IPv6為 ::1）

    非权威应答:
    名称:    www.google.com
    Addresses: ……（IP位址或地址清單）


4.如非以上結果，請移步 FAQ 文檔中 運行結果分析 一節


-------------------------------------------------------------------------------


注意事項：

* 如修改DNS伺服器，請務必設置一個正確的、有效的、可以正常使用的境外DNS伺服器！
* 關於 WinPacap
  * 如果程式啟動提示丟失 wpcap.dll 請重新安裝 WinPcap 或者將其更新到最新版本
  * 安裝前注意系統是否已經安裝過 WinPcap 建議不要重複安裝
* Linux/Mac 平臺下讀取檔案名首字母大寫優先順序高於小寫，Windows 平臺下讀取檔案名時不存在大小寫的區別
* 設定檔/Hosts檔/IPFilter檔和錯誤報表所在的目錄以上文 安裝方法 一節中第4步註冊的服務資訊為准
  * 填寫時一行不要超過4096位元組/4KB
  * 檔讀取只支援整個文本單一的編碼和換行格式組合，切勿在文字檔中混合所支援的編碼或換行格式！
* 服務啟動前請先確認沒有其它本地DNS伺服器運行或本工具多個拷貝運行中，否則可能會導致監聽衝突無法正常工作
  * 監聽衝突會建置錯誤報告，可留意 Windows Socket 相關的錯誤（參見 FAQ 文檔中 Error.log 詳細錯誤報表 一節）
* 殺毒軟體/協力廠商防火牆可能會阻止本程式的操作，請將行為全部允許或將本程式加入到白名單中
* 如果啟動服務時提示 "服務沒有及時回應啟動或者控制請求" 請留意是否有錯誤報表生成，詳細的錯誤資訊參見 FAQ 文檔中 Error.log 詳細錯誤報表 一節
* 目錄和程式的名稱可以隨意更改，但請務必在進行安裝方法第4步前完成。如果服務註冊後需移動工具目錄的路徑，參見上文 卸載方法 第2步的注意事項
* 由於本人水準有限，程式編寫難免會出現差錯疏漏，如有問題可至專案頁面提出，望諒解 v_v


-------------------------------------------------------------------------------


功能和技術：
* 批次處理的作用（運行結束會有運行結果）：
  * ServiceInstall - 將程式註冊為系統服務，並啟動程式進行 Windows 防火牆測試
    * 運行結束時會顯示 "Done. Please confirm the PcapDNSProxyService service had been installed."
    * 具體是否成功需要留意螢幕上的提示
  * ServiceStart - 啟動工具服務
    * 運行結束時會顯示 "Done. Please confirm the PcapDNSProxyService service had been started."
    * 具體是否成功需要留意螢幕上的提示
  * ServiceQuery - 適用于 Windows XP/2003 以及更舊版本Windows的測試批次處理，能測試控管服務是否安裝成功
    * 如果服務安裝成功，運行後會顯示 "SERVICE_NAME: PcapDNSProxyService"（不含引號）
  * ServiceStop - 即時停止工具服務，重啟服務時需要先停止服務
    * 運行結束時會顯示 "Done. Please confirm the PcapDNSProxyService service had been stopped."
    * 具體是否成功需要留意螢幕上的提示
  * ServiceUninstall - 停止並卸載工具服務
    * 運行結束時會顯示 "Done. Please confirm the PcapDNSProxyService service had been deleted."
    * 具體是否成功需要留意螢幕上的提示
* 設定檔支援的檔案名（只會讀取優先順序較高者，優先順序較低者將被直接忽略）：
  * Windows: Config.ini > Config.conf > Config
  * Linux/Mac: Config.conf > Config.ini > Config
* Hosts 檔支援的檔案名（優先順序自上而下遞減）：
  * Windows: Hosts.ini > Hosts.conf > Hosts > Hosts.txt
  * Linux/Mac: Hosts.conf > Hosts.ini > Hosts > Hosts.txt
  * Hosts 檔存在即會讀取，優先順序高者先讀取，存在相同條目時將附加到優先順序高者後，請求回應時位置越前，相同的位址將會被自動合併
* IPFilter 資料庫支援的檔案名（優先順序自上而下遞減）：
  * IPFilter.dat
  * IPFilter.csv
  * IPFilter.txt
  * IPFilter
  * Guarding.P2P
  * Guarding
  * IPFilter 檔存在即會讀取，相同的位址範圍將會被自動合併
* 請求功能變數名稱解析優先順序
  * 使用系統API函數進行功能變數名稱解析（大部分）：系統 Hosts > Pcap_DNSProxy 的 Hosts 條目（Whitelist/白名單條目 > Hosts/主要Hosts清單） > DNS緩存 > Local Hosts/境內DNS解析功能變數名稱清單 > 遠端DNS伺服器
  * 直接使用網路介面卡設置進行功能變數名稱解析（小部分）：Pcap_DNSProxy 的 Hosts.ini（Whitelist/白名單條目 > Hosts/主要Hosts清單） > DNS緩存 > Local Hosts/境內DNS解析功能變數名稱清單 > 遠端DNS伺服器
  * 請求遠端DNS伺服器的優先順序：Hosts Only 模式 > TCP模式的DNSCurve 加密/非加密模式（如有） > UDP模式的DNSCurve 加密/非加密模式（如有） > TCP模式普通請求（如有） > UDP模式普通請求
* 本工具的 DNSCurve/DNSCrypt 協定是內置的實現，不需要安裝 DNSCrypt 官方的工具！
  * DNSCurve 協定為 Streamlined/精簡類型
  * 自動獲取連接資訊時必須保證系統時間的正確，否則證書驗證時會出錯導致連接資訊獲取失敗！
  * DNSCrypt 官方工具會佔用本地DNS埠導致 Pcap_DNSProxy 部署失敗！


-------------------------------------------------------------------------------


特別使用技巧：
這裡羅列出部分作者建議的介紹和使用技巧，供大家參考和使用。關於調整配置，參見下文 設定檔詳細參數說明 一節

* 一個含有大部分境內功能變數名稱的 [Local Hosts] 如有需要可直接添加到 Pcap_DNSProxy 的 Hosts 裡，參見 Hosts 檔案格式說明 一節
  * https://xinhugo-list.googlecode.com/svn/trunk/White_List.txt
  * 或者可以直接使用 Local Main 功能，將大部分的解析請求發往境內的DNS伺服器，參見 Local Main 參數
* DNS緩存類型
  * Timer/計時型：可以自訂緩存的時間長度，佇列長度不限
  * Queue/佇列型：預設緩存時間15分鐘，可通過 Hosts 檔的 Default TTL 值自訂，同時可自訂緩存佇列長度（亦即限制佇列長度的 Timer/計時型）
  * 強烈建議打開DNS緩存功能！
* 本工具配置選項豐富，配置不同的組合會有不同的效果，介紹幾個比較常用的組合：
  * 預設配置：UDP 請求 + 抓包模式
  * Hosts Only = 1 時：UDP 請求 + 直連模式，比抓包模式的系統資源佔用低
    * 此組合的過濾效果依靠黑名單，並不太可靠
  * Local Main = 1 時：將大部分的解析請求發往境內的DNS伺服器，遇到被污染的位址後切換到境外伺服器進行解析
    * 此組合的過濾效果依靠黑名單，並不太可靠
  * Protocol = TCP：先TCP請求失敗後再 UDP 請求 + 抓包模式，對網路資源的佔用比較高
    * 由於TCP請求大部分時候不會被投毒污染，此組合的過濾效果比較可靠
  * 將目標伺服器的請求埠改為非標準DNS埠：例如 OpenDNS 支援53標準埠和5353非標準埠的請求
    * 非標準DNS埠現階段尚未被干擾，此組合的過濾效果比較可靠
  * Multi Request Times = ** 時：應用到所有除請求境內伺服器外的所有請求，一個請求多次發送功能
    * 此功能用於對抗網路丟包比較嚴重的情況，對系統和網路資源的佔用都比較高，但在網路環境惡劣的情況下能提高獲得解析結果的可靠性
  * DNSCurve = 1 同時 Encryption = 0：使用 DNSCurve/DNSCrypt 非加密模式請求功能變數名稱解析
    * 此組合等於使用非標準DNS埠請求，但是多了一層標籤識別使得可靠性很高，詳細情況參見上文
  * DNSCurve = 1 同時 Encryption = 1：使用 DNSCurve/DNSCrypt 加密模式請求功能變數名稱解析
    * 此組合加密傳輸所有功能變數名稱請求，功能變數名稱解析可靠性最高
  * DNSCurve = 1 同時 Encryption = 1 同時 Encryption Only = 1：只使用 DNSCurve/DNSCrypt 加密模式請求功能變數名稱解析
    * 上文的加密組合並不阻止程式在請求 DNSCurve/DNSCrypt 加密模式失敗是使用其它協定請求功能變數名稱解析，開啟 Encryption Only = 1 後將只允許使用加密傳輸，安全性和可靠性最高


-------------------------------------------------------------------------------


設定檔詳細參數說明：

有效參數格式為 "選項名稱 = 數值/資料"（不含引號，注意空格和等號的位置）
注意：設定檔只會在工具服務開始時讀取，修改本檔的參數後請重啟服務（參見上文 注意事項 一節中的 重啟服務）

* Base - 基本參數區域
  * Version - 設定檔的版本，用於正確識別設定檔：本參數與程式版本號不相關，切勿修改，預設為發佈時的最新設定檔版本
  * File Refresh Time - 檔刷新間隔時間：單位為秒，最短間隔時間為5秒，預設為10秒
  * File Hash - 檔 Hash 功能，開啟此功能能降低刷新檔時的CPU佔用：開啟為1/關閉為0，預設為1

* Log - 日誌參數區域
  * Print Error - 錯誤報表功能：開啟為1/關閉為0，預設為1
  * Log Maximum Size - 日誌檔最大容量：直接填數位時單位為位元組，可加上單位，支援的單位有KB/MB/GB，可接受範圍為4KB - 4GB，如果留空則為8MB，預設為空
  * 注意：日誌檔到達最大容量後將被直接刪除，然後重新生成新的日誌檔，原來的日誌將無法找回！

* DNS - 功能變數名稱解析參數區域
  * Protocol - 發送請求所使用的協定，分 UDP 和 TCP：預設為 UDP
    * 注意：此處所指的協定指的是程式請求遠端DNS伺服器時所使用的協定，而向本程式請求功能變數名稱解析時可隨意使用 UDP 或 TCP
  * Hosts Only - Hosts Only 直連模式，啟用後將使用系統直接請求遠端伺服器而啟用只使用本工具的 Hosts 功能：開啟為1/關閉為0，預設為0
    * 注意：解析的結果是否會被投毒污染與使用的偽包篩檢程式有關，強烈建議將 DNS Data Filter 和 Blacklist Filter 過濾模組開啟，啟用這兩個過濾模組後結果理論上將是沒有被投毒污染的，否則會被投毒污染！
  * Local Main - 主要境內伺服器請求功能，開啟後則平時使用 Local 的伺服器進行解析，遇到遭投毒污染的解析結果時自動再向境外伺服器請求
    * 注意：解析的結果是否會被投毒污染與使用的偽包篩檢程式有關，強烈建議將 DNS Data Filter 和 Blacklist Filter 過濾模組開啟，啟用這兩個過濾模組後結果理論上將是沒有被投毒污染的，否則會被投毒污染！
  * Cache Type - DNS緩存的類型：分 Timer/計時型以及 Queue/佇列型
  * Cache Parameter - DNS緩存的參數：Timer/計時型 時為時間長度，Queue/佇列型 時為佇列長度

* Listen - 監聽參數區域
  * Pcap Capture - 抓包功能總開關，開啟後抓包模組才能正常使用：開啟為1/關閉為0，預設為1
  * Operation Mode - 程式的監聽工作模式，分 Server/伺服器模式、Private/私有網路模式 和 Proxy/代理模式：預設為 Private
    * Server/伺服器模式：打開DNS通用埠（TCP/UDP同時打開），可為所有其它設備提供代理功能變數名稱解析請求服務
    * Private/私有網路模式：打開DNS通用埠（TCP/UDP同時打開），可為僅限於私有網路位址的設備提供代理功能變數名稱解析請求服務
    * Proxy/代理模式：只打開回環位址的DNS埠（TCP/UDP同時打開），只能為本機提供代理功能變數名稱解析請求服務
    * Custom/自訂模式：打開DNS通用埠（TCP/UDP同時打開），可用的位址由 IPFilter 參數決定
  * Listen Protocol - 監聽協定，本地監聽的協定：可填入 IPv4 和 IPv6 和 IPv4 + IPv6，預設為 IPv4 + IPv6
    * 只填 IPv4 或 IPv6 時，只監聽指定協定的本地埠
    * IPv4 + IPv6 時同時監聽兩個協定的本地埠
  * Listen Port - 監聽埠，本地監聽請求的埠：可填入 1-65535 之間的埠，如果留空則為53，預設為空
  * IPFilter Type - IPFilter 參數的類型：分為 Deny 禁止和 Permit 允許，對應 IPFilter 參數應用為黑名單或白名單，預設為 Deny
  * IPFilter Level - IPFilter 參數的過濾級別，級別越高過濾越嚴格，與 IPFilter 條目相對應：0為不啟用過濾，如果留空則為0，預設為空
  * Accept Type - 禁止或只允許所列DNS類型的請求：格式為 "Deny:DNS記錄的名稱或ID(|DNS記錄的名稱或ID)" 或 "Permit:DNS記錄的名稱或ID(|DNS記錄的名稱或ID)"（不含引號，括弧內為可選項目）
    * 所有可用的DNS類型清單：
      * A/1
      * NS/2
      * CNAME/5
      * SOA/6
      * PTR/12
      * MX/15
      * TXT/16
      * RP/17
      * SIG/24
      * KEY/25
      * AAAA/28
      * LOC/29
      * SRV/33
      * NAPTR/35
      * KX/36
      * CERT/37
      * DNAME/39
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
      * HIP/55
      * SPF/99
      * TKEY/249
      * TSIG/250
      * IXFR/251
      * AXFR/252
      * ANY/255
      * TA/32768
      * DLV/32769

* Addresses - 普通模式位址區域
注意：IPv4位址格式為 "IPv4位址:埠"，IPv6位址格式為"[IPv6位址]:埠"（均不含引號）
  * IPv4 DNS Address - IPv4主要DNS伺服器位址：需要輸入一個帶埠格式的位址，預設為 8.8.4.4:53(Google Public DNS No.2)
    * 本參數支援同時請求多伺服器的功能，開啟後將同時向清單中的伺服器請求解析功能變數名稱，並採用最快回應的伺服器的結果
    * 使用同時請求多伺服器格式為 "位址A:埠|位址B:埠|位址C:埠"（不含引號）
    * 同時請求多伺服器啟用後將自動啟用 Alternate Multi Request 參數（參見下文）
  * IPv4 Alternate DNS Address - IPv4備用DNS伺服器位址：需要輸入一個帶埠格式的位址，預設為 8.8.8.8:53(Google Public DNS No.1)
    * 本參數支援同時請求多伺服器的功能，開啟後將同時向清單中的伺服器請求解析功能變數名稱，並採用最快回應的伺服器的結果
    * 使用同時請求多伺服器格式為 "位址A:埠|位址B:埠|位址C:埠"（不含引號）
    * 同時請求多伺服器啟用後將自動啟用 Alternate Multi Request 參數（參見下文）
  * IPv4 Local DNS Address - IPv4主要境內DNS伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，預設為 114.114.115.115:53(114 DNS No.2)
  * IPv4 Local Alternate DNS Address - IPv4備用境內DNS伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，預設為 114.114.114.114:53(114 DNS No.1)
  * IPv6 DNS Address - IPv6主要DNS伺服器位址：需要輸入一個帶埠格式的位址，留空為不啟用，預設為空
  * IPv6 Alternate DNS Address - IPv6備用DNS伺服器位址：需要輸入一個帶埠格式的位址，留空為不啟用，預設為空
  * IPv6 Local DNS Address - IPv6主要境內DNS伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，留空為不啟用，預設為空
  * IPv6 Local Alternate DNS Address - IPv6備用境內DNS伺服器位址，用於境內功能變數名稱解析：需要輸入一個帶埠格式的位址，留空為不啟用，預設為空

* Values - 擴展參數值區域
  * EDNS0 Payload Size - EDNS0 標籤附帶使用的最大載荷長度：最小為DNS協定實現要求的512(bytes)，留空則使用 EDNS0 標籤要求最短的1220(bytes)，預設為留空
  * IPv4 TTL - IPv4主要DNS伺服器接受請求的遠端DNS伺服器資料包的TTL值：0為自動獲取，取值為 1-255 之間：預設為0
    * 本參數支援同時請求多伺服器的功能，與 IPv4 DNS Address 相對應
    * 使用同時請求多伺服器格式為 "TTL(A)|TTL(B)|TTL(C)"（不含引號），也可直接預設（即只填一個0不是用此格式）則所有TTL都將由程式自動獲取
    * 使用時多TTL值所對應的順序與 IPv4 DNS Address 中對應的位址順序相同
  * IPv6 Hop Limits - IPv6主要DNS伺服器接受請求的遠端DNS伺服器資料包的 Hop Limits 值：0為自動獲取，取值為 1-255 之間，預設為0
    * 本參數支援同時請求多伺服器的功能，與 IPv6 DNS Address 相對應
    * 使用同時請求多伺服器格式為 "Hop Limits(A)|Hop Limits(B)|Hop LimitsC)"（不含引號），也可直接預設（即只填一個0不是用此格式）則所有 Hop Limits 都將由程式自動獲取
    * 使用時多 Hop Limits 值所對應的順序與 IPv6 DNS Address 中對應的位址順序相同
  * IPv4 Alternate TTL - IPv4備用DNS伺服器接受請求的遠端DNS伺服器資料包的TTL值：0為自動獲取，取值為 1-255 之間：預設為0
    * 本參數支援同時請求多伺服器的功能，與 IPv4 Alternate DNS Address 相對應
    * 使用同時請求多伺服器格式為 "TTL(A)|TTL(B)|TTL(C)"（不含引號），也可直接預設（即只填一個0不是用此格式）則所有TTL都將由程式自動獲取
    * 使用時多TTL值所對應的順序與 IPv4 Alternate DNS Address 中對應的位址順序相同
  * IPv6 Alternate Hop Limits - IPv6備用DNS伺服器接受請求的遠端DNS伺服器資料包的 Hop Limits 值：0為自動獲取，取值為 1-255 之間，預設為0
    * 本參數支援同時請求多伺服器的功能，與 IPv6 Alternate DNS Address 相對應
    * 使用同時請求多伺服器格式為 "Hop Limits(A)|Hop Limits(B)|Hop Limits(C)"（不含引號），也可直接預設（即只填一個0不是用此格式）則所有 Hop Limits 都將由程式自動獲取
    * 使用時多 Hop Limits 值所對應的順序與 IPv6 Alternate DNS Address 中對應的位址順序相同
  * Hop Limits Fluctuation - IPv4 TTL/IPv6 Hop Limits 可接受範圍，即 IPv4 TTL/IPv6 Hop Limits 的值±數值的範圍內的資料包均可被接受，用於避免網路環境短暫變化造成解析失敗的問題：取值為 1-255 之間，預設為2
  * ICMP Test - ICMP/Ping測試間隔時間：單位為秒，最短間隔時間為5秒，預設為900秒/15分鐘
  * Domain Test - DNS伺服器解析功能變數名稱測試間隔時間：單位為秒，最短間隔時間為5秒，預設為900秒/15分鐘
  * Alternate Times - 待命伺服器失敗次數閾值，一定週期內如超出閾值會觸發伺服器切換：預設為5次
  * Alternate Time Range - 待命伺服器失敗次數閾值計算週期：單位為秒，預設為60秒/1分鐘
  * Alternate Reset Time - 待命伺服器重置切換時間，切換產生後經過此事件會切換回主要伺服器：單位為秒，預設為300秒/5分鐘
  * Multi Request Times - 接受一個功能變數名稱請求後向同一個遠端伺服器發送多次功能變數名稱解析請求：0為關閉，1時為收到一個請求時請求2次，2時為收到一個請求時請求3次......最大值為15，也就是最多可同時請求16次，預設為0
    * 注意：此值將應用到 Local Hosts 外對所有遠端伺服器所有協定的請求，因此可能會對系統以及遠端伺服器造成壓力，請謹慎考慮開啟的風險！
    * 一般除非丟包非常嚴重干擾正常使用否則不建議開啟，開啟也不建議將值設得太大。實際使用可以每次+1後重啟服務測試效果，找到最合適的值

* Switches - 控制開關區域
  * Domain Case Conversion - 隨機轉換功能變數名稱請求大小寫：開啟為1/關閉為0，預設為1
  * Compression Pointer Mutation - 隨機添加壓縮指標：開啟為1/關閉為0，預設為0
  * EDNS0 Label - EDNS0 標籤支援，開啟後將為所有請求添加 EDNS0 標籤：開啟為1/關閉為0，預設為0
  * DNSSEC Request - DNSSEC 請求，開啟後將嘗試為所有請求添加 DNSSEC 請求：開啟為1/關閉為0，預設為0
    * 注意：此功能為實驗性質，本程式不具備任何驗證 DNSSEC 回復的能力，單獨開啟此功能時並不能避免DNS投毒污染的問題
  * Alternate Multi Request - 待命伺服器同時請求參數，開啟後將同時請求主要伺服器和待命伺服器並採用最快回應的伺服器的結果：開啟為1/關閉為0，預設為0
    * 同時請求多伺服器啟用後本參數將強制啟用，將同時請求所有存在於清單中的伺服器，並採用最快回應的伺服器的結果
  * IPv4 Data Filter - IPv4資料包頭檢測：開啟為1/關閉為0，預設為0
  * TCP Data Filter - TCP資料包頭檢測；開啟為1/關閉為0，預設為1
    * 注意：此選項只能在程式工作模式為TCP下才能使用，非TCP模式時此參數無效
  * DNS Data Filter - DNS資料包頭檢測：開啟為1/關閉為0，預設為1
  * Blacklist Filter - 解析結果黑名單過濾：開啟為1/關閉為0，預設為1

* Data - 資料區域
  * ICMP ID - ICMP/Ping資料包頭部ID的值：格式為 0x**** 的十六進位字元，如果留空則獲取執行緒的ID作為請求用ID，預設為空
  * ICMP Sequence - ICMP/Ping資料包頭部Sequence/序號的值：格式為 0x**** 的十六進位字元，如果留空則為 0x0001 ，預設為空
  * Domain Test Data - DNS伺服器解析功能變數名稱測試：請輸入正確、確認不會被投毒污染的功能變數名稱並且不要超過253位元組ASCII資料，留空則會隨機生成一個功能變數名稱進行測試，預設為空
  * Domain Test ID - DNS資料包頭部ID的值：格式為 0x**** 的十六進位字元，如果留空則為 0x0001 ，預設為空
  * ICMP PaddingData - ICMP附加資料，Ping程式發送請求時為補足資料使其達到Ethernet類型網路最低的可發送長度時添加的資料：長度介乎于 18位元組 - 1512位元組 ASCII資料之間，留空則使用 Microsoft Windows Ping 程式的ICMP附加資料，預設為空
  * Localhost Server Name - 本地DNS伺服器名稱：請輸入正確的功能變數名稱並且不要超過253位元組ASCII資料，留空則使用 pcap-dnsproxy.localhost.server 作為本機伺服器名稱，預設為空

* DNSCurve - DNSCurve 協定基本參數區域
  * DNSCurve - DNSCurve 協定總開關，控制所有和 DNSCurve 協定有關的選項：開啟為1/關閉為0，預設為0
  * DNSCurve Protocol - 發送請求所使用的協定，分 UDP 和 TCP：預設為 UDP
  * DNSCurve Payload Size - DNSCurve EDNS0 標籤附帶使用的最大載荷長度，同時亦為發送請求的總長度，並決定請求的填充長度：最小為DNS協定實現要求的512(bytes)，留空則為512(bytes)，預設為留空
  * Encryption - 啟用加密，DNSCurve 協定支援加密和非加密模式：開啟為1/關閉為0，預設為1
  * Encryption Only - 只使用加密模式：開啟為1/關閉為0，預設為1
    * 注意：使用 只使用加密模式 時必須提供伺服器的魔數和指紋用於請求和接收
  * Key Recheck Time - DNSCurve 協定DNS伺服器連接資訊檢查間隔：單位為秒，最短為10秒，預設為3600秒/1小時

* DNSCurve Addresses - DNSCurve 協定位址區域
  * DNSCurve IPv4 DNS Address - DNSCurve 協定IPv4主要DNS伺服器位址：需要輸入一個帶埠格式的位址，預設為 208.67.220.220:443(OpenDNS No.2)
  * DNSCurve IPv4 Alternate DNS Address - DNSCurve 協定IPv4備用DNS伺服器位址：需要輸入一個帶埠格式的位址，預設為 208.67.222.222:443(OpenDNS No.1)
  * DNSCurve IPv6 DNS Address - DNSCurve 協定IPv6主要DNS伺服器位址：需要輸入一個帶埠格式的位址，預設為空
  * DNSCurve IPv6 Alternate DNS Address - DNSCurve 協定IPv6備用DNS伺服器位址：需要輸入一個帶埠格式的位址，預設為空
  * DNSCurve IPv4 Provider Name - DNSCurve 協定IPv4主要DNS伺服器提供者，請輸入正確的功能變數名稱並且不要超過253位元組ASCII資料，預設為 2.dnscrypt-cert.opendns.com(OpenDNS)
    * 注意：自動獲取 DNSCurve 伺服器連接資訊時必須輸入提供者的功能變數名稱，不能留空
  * DNSCurve IPv4 Alternate Provider Name - DNSCurve 協定IPv4備用DNS伺服器提供者，請輸入正確的功能變數名稱並且不要超過253位元組ASCII資料，預設為 2.dnscrypt-cert.opendns.com(OpenDNS)
    * 注意：自動獲取 DNSCurve 伺服器連接資訊時必須輸入提供者的功能變數名稱，不能留空
  * DNSCurve IPv6 Provider Name - DNSCurve 協定IPv6主要DNS伺服器提供者，請輸入正確的功能變數名稱並且不要超過253位元組ASCII資料，預設為空
    * 注意：自動獲取 DNSCurve 伺服器連接資訊時必須輸入提供者的功能變數名稱，不能留空
  * DNSCurve IPv6 Provider Name - DNSCurve 協定IPv6備用DNS伺服器提供者，請輸入正確的功能變數名稱並且不要超過253位元組ASCII資料，預設為空
    * 注意：自動獲取 DNSCurve 伺服器連接資訊時必須輸入提供者的功能變數名稱，不能留空

* DNSCurve Keys - DNSCurve 協定金鑰區域
注意：公開網站上的 "公開金鑰" 普遍為驗證用的公開金鑰，用於驗證與伺服器通訊時使用的指紋，兩者為不同性質的公開金鑰不可混用！
  * Client Public Key - 自訂用戶端公開金鑰：可使用 KeyPairGenerator 生成，留空則每次啟動時自動生成，預設為空
  * Client Secret Key - 自訂用戶端私密金鑰：可使用 KeyPairGenerator 生成，留空則每次啟動時自動生成，預設為空
  * IPv4 DNS Public Key - DNSCurve 協定IPv4主要DNS伺服器驗證用公開金鑰，預設為 B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79(OpenDNS)
  * IPv4 Alternate DNS Public Key - DNSCurve 協定IPv4備用DNS伺服器驗證用公開金鑰，預設為 B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79(OpenDNS)
  * IPv6 DNS Public Key - DNSCurve 協定IPv6主要DNS伺服器驗證用公開金鑰，預設為空
  * IPv6 Alternate DNS Public Key - DNSCurve 協定IPv6備用DNS伺服器驗證用公開金鑰，預設為空
  * IPv4 DNS Fingerprint - DNSCurve 協定IPv4主要DNS伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取，預設為空
  * IPv4 Alternate DNS Fingerprint - DNSCurve 協定IPv4備用DNS伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取，預設為空
  * IPv6 DNS Fingerprint - DNSCurve 協定IPv6備用DNS伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取，預設為空
  * IPv6 Alternate DNS Fingerprint - DNSCurve 協定IPv6備用DNS伺服器傳輸用指紋，留空則自動通過伺服器提供者和公開金鑰獲取，預設為空

* DNSCurve Magic Number - DNSCurve 協定魔數區域
  * IPv4 Receive Magic Number - DNSCurve 協定IPv4主要DNS伺服器接收魔數：長度必須為8位元組，留空則使用程式內置的接收魔數，預設留空
  * IPv4 Alternate Receive Magic Number - DNSCurve 協定IPv4備用DNS伺服器接收魔數：長度必須為8位元組，留空則使用程式內置的接收魔數，預設留空
  * IPv6 Receive Magic Number - DNSCurve 協定IPv6主要DNS伺服器接收魔數：長度必須為8位元組，留空則使用程式內置的接收魔數，預設留空
  * IPv6 Alternate Receive Magic Number - DNSCurve 協定IPv6備用DNS伺服器接收魔數：長度必須為8位元組，留空則使用程式內置的接收魔數，預設留空
  * IPv4 DNS Magic Number - DNSCurve 協定IPv4主要DNS伺服器發送魔數：長度必須為8位元組，留空則自動獲取，預設留空
  * IPv4 Alternate DNS Magic Number - DNSCurve 協定IPv4備用DNS伺服器發送魔數：長度必須為8位元組，留空則自動獲取，預設留空
  * IPv6 DNS Magic Number - 協定IPv6主要DNS伺服器發送魔數：長度必須為8位元組，留空則自動獲取，預設留空
  * IPv6 Alternate DNS Magic Number - DNSCurve 協定IPv6備用DNS伺服器發送魔數：長度必須為8位元組，留空則自動獲取，預設留空

* 預設的設定檔內容

[Base]
Version = 0.4
File Refresh Time = 10
File Hash = 1

[Log]
Print Error = 1
Print Running Log = 0
Log Maximum Size = 

[DNS]
Protocol = UDP
Hosts Only = 0
Local Main = 0
Cache Type = Queue
Cache Parameter = 256

[Listen]
Pcap Capture = 1
Operation Mode = Private
Listen Protocol = IPv4 + IPv6
Listen Port = 
IPFilter Type = Deny
IPFilter Level < 
Accept Type = 

[Addresses]
IPv4 DNS Address = 8.8.4.4:53
IPv4 Alternate DNS Address = 8.8.8.8:53
IPv4 Local DNS Address = 114.114.115.115:53
IPv4 Local Alternate DNS Address = 114.114.114.114:53
IPv6 DNS Address = 
## Format -> IPv6 DNS Address = [2001:4860:4860::8844]:53
IPv6 DNS Alternate Address = 
## Format -> IPv6 DNS Alternate Address = [2001:4860:4860::8888]:53
IPv6 Local DNS Address = 
IPv6 Local Alternate DNS Address = 

[Values]
EDNS0 Payload Size = 
IPv4 TTL = 0
IPv6 Hop Limits = 0
IPv4 Alternate TTL = 0
IPv6 Alternate Hop Limits = 0
Hop Limits Fluctuation = 2
ICMP Test = 900
Domain Test = 900
Alternate Times = 5
Alternate Time Range = 60
Alternate Reset Time = 300
Multi Request Times = 0

[Switches]
Domain Case Conversion = 1
Compression Pointer Mutation = 0
EDNS0 Label = 0
DNSSEC Request = 0
Alternate Multi Request = 0
IPv4 Data Filter = 0
TCP Data Filter = 1
DNS Data Filter = 1
Blacklist Filter = 1

[Data]
ICMP ID = 
ICMP Sequence = 
ICMP PaddingData = 
Domain Test ID = 
Domain Test Data = 
Localhost Server Name = 

[DNSCurve]
DNSCurve = 0
DNSCurve Protocol = UDP
DNSCurve Payload Size = 
Encryption = 1
Encryption Only = 0
Key Recheck Time = 3600

[DNSCurve Addresses]
DNSCurve IPv4 DNS Address = 208.67.220.220:443
DNSCurve IPv4 Alternate DNS Address = 208.67.222.222:443
DNSCurve IPv6 DNS Address = 
## DNSCurve IPv6 DNS Address = [2620:0:CCC::2]:443
DNSCurve IPv6 Alternate DNS Address = 
## DNSCurve Alternate IPv6 DNS Address = [2620:0:CCD::2]:443
DNSCurve IPv4 Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv4 Alternate Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv6 Provider Name = 
## DNSCurve IPv6 Provider Name = 2.dnscrypt-cert.opendns.com
DNSCurve IPv6 Alternate Provider Name = 
## DNSCurve IPv6 Alternate Provider Name = 2.dnscrypt-cert.opendns.com

[DNSCurve Keys]
Client Public Key = 
Client Secret Key = 
IPv4 DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv4 Alternate DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv6 DNS Public Key = 
## IPv6 DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv6 Alternate DNS Public Key = 
## IPv6 Alternate DNS Public Key = B735:1140:206F:225D:3E2B:D822:D7FD:691E:A1C3:3CC8:D666:8D0C:BE04:BFAB:CA43:FB79
IPv4 DNS Fingerprint = 
## IPv4 DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007
IPv4 Alternate DNS Fingerprint = 
## IPv4 Alternate DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007
IPv6 DNS Fingerprint = 
##IPv6 DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007
IPv6 Alternate DNS Fingerprint = 
##IPv6 Alternate DNS Fingerprint = 227C:86C7:7574:81AB:6AE2:402B:4627:6E18:CFBB:60FA:DF92:652F:D694:01E8:EBF2:B007

[DNSCurve Magic Number]
IPv4 Receive Magic Number = 
IPv4 Alternate Receive Magic Number = 
IPv6 Receive Magic Number = 
IPv6 Alternate Receive Magic Number = 
IPv4 DNS Magic Number = 
## IPv4 DNS Magic Number = qe47QHHw
IPv4 Alternate DNS Magic Number = 
## IPv4 Alternate DNS Magic Number = qe47QHHw
IPv6 DNS Magic Number = 
## IPv6 DNS Magic Number = qe47QHHw
IPv6 Alternate DNS Magic Number = 
## IPv6 Alternate DNS Magic Number = qe47QHHw


-------------------------------------------------------------------------------


Hosts 檔案格式說明：

Hosts設定檔分為Base/基本區域、Hosts/主要Hosts清單 和 Local Hosts/境內DNS解析功能變數名稱清單 三個區域
* 區域通過標籤識別，修改時切勿將其刪除
* 優先順序：Local Hosts/境內DNS解析功能變數名稱清單 > Hosts/主要Hosts清單，Whitelist/白名單條目 和 Banned/黑名單條目 的優先順序由位置決定，參見下文詳細說明
* 一條條目的總長度切勿超過4096位元組/4KB
* 需要注釋請在條目開頭添加 #/井號
* 優先順序別自上而下遞減，條目越前優先順序越高
* 平行 Hosts 條目支援數量由請求功能變數名稱以及 EDNS0 Payload 長度決定，建議不要超過70個A記錄或40個AAAA記錄

* Base - 基本參數區域
  * Version - 設定檔的版本，用於正確識別 Hosts 檔：本參數與程式版本號不相關，切勿修改，預設為發佈時的最新設定檔版本
  * Default TTL - Hosts 條目預設存留時間：單位為秒，留空則為900秒/15分鐘，預設為空

* Whitelist - 白名單條目
此類型的條目列出的符合要求的功能變數名稱會直接繞過 Hosts，不會使用 Hosts 功能
直接在條目前添加 "Null"（不含引號）即可，有效參數格式為 "Null 正則運算式"（不含引號）
  * 注意優先順序的問題，例如有一片含白名單條目的區域：

    NULL .*\.test.localhost
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost

    雖然 .*\.localhost 包含了 .*\.test\.localhost 但由於優先順序別自上而下遞減，故先命中 .*\.test\.localhost 並返回使用遠端伺服器解析
    從而繞過了下面的條目，不使用Hosts的功能

* Banned - 黑名單條目
此類型的條目列出的符合要求的功能變數名稱會直接返回功能變數名稱不存在的功能，避免重定向導致的超時問題
直接在條目前添加 "Banned"（不含引號）即可，有效參數格式為 "Banned 正則運算式"（不含引號）
  * 注意優先順序的問題，例如有一片含黑名單條目的區域：

    Banned .*\.test.localhost
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.localhost

    雖然 .*\.localhost 包含了 .*\.test\.localhost 但由於優先順序別自上而下遞減，故先命中 .*\.test\.localhost 並直接返回功能變數名稱不存在
    從而繞過了下面的條目，達到遮罩功能變數名稱的目的

* Hosts - 主要Hosts清單
有效參數格式為 "位址(|位址A|位址B) 功能變數名稱的正則運算式"（不含引號，括弧內為可選項目，注意間隔所在的位置）
  * 位址與正則運算式之間的間隔字元可為Space/半形空格或者HT/水準定位符號，間隔長度不限，但切勿輸入全形空格
  * 一條條目只能接受一種網址類別型（IPv4/IPv6），如有同一個功能變數名稱需要同時進行IPv4/IPv6的Hosts，請分為兩個條目輸入
  * 平行位址原理為一次返回多個記錄，而具體使用哪個記錄則由要求者決定，一般為第1個
  * 例如有一個 [Hosts] 下有效資料區域：

    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3    .*\.test\.localhost
    ::4|::5|::6    .*\.localhost

    雖然 .*\.localhost 包含了 .*\.test\.localhost 但由於優先順序別自上而下遞減，故先命中 .*\.test\.localhost 並直接返回，不會再進行其它檢查
    * 請求解析 xxx.localhost 的A記錄（IPv4）會返回 127.0.0.4、127.0.0.5和127.0.0.6
    * 請求解析 xxx.localhost 的AAAA記錄（IPv6）會返回 ::4、::5和::6
    * 請求解析 xxx.test.localhost 的A記錄（IPv4）會返回 127.0.0.1、127.0.0.2和127.0.0.3
    * 請求解析 xxx.test.localhost 的AAAA記錄（IPv6）會返回 ::1、::2和::3

* Local Hosts - 境內DNS解析功能變數名稱清單
本區域資料用於為功能變數名稱使用境內DNS伺服器解析提高存取速度，使用時請確認境內DNS伺服器位址不為空（參見上文 設定檔詳細參數說明 一節）
有效參數格式為 "功能變數名稱的正則運算式"（不含引號）
  * 本功能不會對境內DNS伺服器回復進行任何過濾，請確認本區域填入的資料不會受到DNS投毒污染的干擾
  * 例如有一個 [Local Hosts] 下有效資料區域：

    .*\.test\.localhost
    .*\.localhost

    * 即所有符合以上正則運算式的功能變數名稱請求都將使用境內DNS伺服器解析

* Stop - 臨時停止讀取標籤
在需要停止讀取的資料前添加 "[Stop]"（不含引號） 標籤即可在中途停止對檔的讀取，直到有其它標籤時再重新開始讀取
  * 例如有一片資料區域：

    [Hosts]
    127.0.0.1|127.0.0.2|127.0.0.3 .*\.test\.localhost
    [Stop]
    127.0.0.4|127.0.0.5|127.0.0.6 .*\.localhost
    ::1|::2|::3    .*\.test\.localhost
    ::4|::5|::6    .*\.localhost

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


* 預設的 Hosts 檔內容


## Example:
#
# (Anywhere)
# NULL localhost
# BANNED localhost
#
# [Hosts]
# 127.0.0.1 localhost
# ::1 localhost
# 
# [Local Hosts]
# localhost
#

[Base]
Version = *.*（視所使用的版本而定，參見 ChangeLog 文檔）
Default TTL = 

[Hosts]


[Local Hosts]



-------------------------------------------------------------------------------


IPFilter 檔案格式說明：

IPFilter 設定檔分為 Blacklist/黑名單區域 和 IPFilter/位址過濾區域
  * 區域通過標籤識別，修改時切勿將其刪除
  * 一條條目的總長度切勿超過4096位元組/4KB
  * 需要注釋請在條目開頭添加 #/井號


* Blacklist - 黑名單區域
當 Blacklist Filter 為開啟時，將檢查本清單功能變數名稱與解析結果，如果解析結果裡含有與功能變數名稱對應的黑名單位址，則會直接丟棄此解析結果
有效參數格式為 "位址(|位址A|位址B) 功能變數名稱的正則運算式"（不含引號，括弧內為可選項目，注意間隔所在的位置）
  * 位址與正則運算式之間的間隔字元可為Space/半形空格或者HT/水準定位符號，間隔長度不限，但切勿輸入全形空格
  * 一條條目只能接受一種網址類別型（IPv4/IPv6），如有同一個功能變數名稱需要同時進行IPv4/IPv6位址的過濾，請分為兩個條目輸入

* IPFilter - 位址過濾區域
位址過濾黑名單或白名單由設定檔的 IPFilter Type 值決定，Deny 禁止/黑名單和 Permit 允許/白名單
有效參數格式為 "開始位址 - 結束位址, 過濾等級, 條目簡介注釋"（不含引號）
  * 同時支援IPv4和IPv6位址，但填寫時請分開為2個條目
  * 同一類型的位址位址段有重複的條目將會被自動合併

* Stop - 臨時停止讀取標籤
在需要停止讀取的資料前添加 "[Stop]"（不含引號） 標籤即可在中途停止對檔的讀取，直到有其它標籤時再重新開始讀取
  * 例如有一片資料區域：

    [Blacklist]
    127.0.0.1 localhost
    [Stop]
    ::1 localhost

    [IPFilter]
    Address(Start) - Address(End)    , Level, Comments
    127.0.0.0      - 127.255.255.255 ,     0, IPv4 Link-Local addresses
    ::             - ::1             ,     0, IPv6 Link-Local addresses

  * 則從 [Stop] 一行開始，下面到 [IPFilter] 之間的資料都將不會被讀取
  * 即實際有效的資料區域是：

    [Blacklist]
    127.0.0.1 localhost

    [IPFilter]
    Address(Start) - Address(End)    , Level, Comments
    127.0.0.0      - 127.255.255.255 ,     0, IPv4 Link-Local addresses
    ::             - ::1             ,     0, IPv6 Link-Local addresses


* 預設的 IPFilter 檔內容


## Example:
#
# [Blacklist]
# 127.0.0.1 localhost
# ::1 localhost
#
# [IPFilter]
# Address(Start) - Address(End)    , Level, Comments
# 127.0.0.0      - 127.255.255.255 ,     0, IPv4 Link-Local addresses
# ::             - ::1             ,     0, IPv6 Link-Local addresses
# ...
#

[Base]
Version = 0.4

[Blacklist]
74.125.39.102|74.125.39.113|74.125.127.102|74.125.155.102|209.85.229.138 plus\.google\.com

[IPFilter]


