## 服用方法

 - 选择 Updata_GB2312.bat 打开

## 可选参数

 - -LOCAL   (从上次的缓存中重建)


## 本地文件相关

 - #Routingipv4#   (仅 IPv4 路由表独立缓存)
 - #Routingipv6#   (仅 IPv6 路由表独立缓存)
 - delegated-apnic-latest   (上次抓取的原始 APNIC 路由表文件)
 - Log_Lib   (IPv4 非掩码长度转换为 IPv6 前缀长度的映射库, 删除会影响路由表生成速度, 更新时还会生成此文件)
 - latest文件夾   (用于进行更新比对的缓存文件)
 - Routing.txt   (最终生成的可用路由表文件, 直接剪切或拷贝替换上级目录同名文件即可)
