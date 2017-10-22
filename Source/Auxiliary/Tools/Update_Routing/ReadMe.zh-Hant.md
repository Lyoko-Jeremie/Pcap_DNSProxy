## 服用方法

* 選擇 `Updata_Big5.bat` 打開

## 可選參數

* `-LOCAL`
  從上次的緩存中重建

## 本地文件相關

* `#Routingipv4#`
  僅 IPv4 路由表獨立緩存
* `#Routingipv6#`
  僅 IPv6 路由表獨立緩存
* `delegated-apnic-latest`
  上次抓取的原始 APNIC 路由表文件
* `Log_Lib`
  IPv4 非掩碼長度轉換爲 IPv4 前綴長度的映射庫, 刪除會影響路由表生成速度, 更新時還會生成此文件
* `latest` 文件夾
  用於進行更新比對的緩存文件
* `Routing.txt`
  最終生成的可用路由表文件, 直接剪切或拷貝替換上級目錄同名文件即可
