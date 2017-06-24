:: Pcap_DNSProxy routing list update batch
:: Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
:: 
:: Author: muink, Chengr28
:: 


@echo off&title 路由表一键更新
mode con: cols=80 lines=28

:: Go to batch dir.
cd /D "%~dp0"

:[inte]
:: 完整性验证
md latest\ipv4>nul 2>nul
md latest\ipv6>nul 2>nul
:: 检查bin程序组完整性
..\Support\md5 -c609F46A341FEDEAEEC18ABF9FB7C9647 ..\Support\md5.exe 2>nul||echo.依赖程序似乎被破坏了, 重新安装一次试试?&&ping -n 5 127.0.0.1>nul&&goto END
..\Support\md5 -cA0BAC06597560FFDE52C225659F2BF3A ..\Support\curl.exe 2>nul||echo.依赖程序似乎被破坏了, 重新安装一次试试?&&ping -n 5 127.0.0.1>nul&&goto END
..\Support\md5 -cC95C0A045697BE8F782C71BD46958D73 ..\Support\sed.exe 2>nul||echo.依赖程序似乎被破坏了, 重新安装一次试试?&&ping -n 5 127.0.0.1>nul&&goto END
..\Support\md5 -c9A5E35DCB4B35A2350E6FDF4620743B6 ..\Support\CCase.exe 2>nul||echo.依赖程序似乎被破坏了, 重新安装一次试试?&&ping -n 5 127.0.0.1>nul&&goto END

if not "%~1" == "" (
	if "%~1" == "-LOCAL" (set ST=%~1) else goto %~1
)

:[main]
:: 拉取FTP数据
title 路由表一键更新: 拉取数据中...
call:[DownloadData]

:: 验证新旧LIST文件MD5
title 路由表一键更新: 验证数据中...
call:[Hash_DAL]

:: 若未更新,从本地缓存重建数据或取消更新
:RebuildDAL
setlocal enabledelayedexpansion
cls
if defined DALmd5_lab (
	set ny=y&set /p ny=远端数据未更新,从本地重建一次路由表?[Y/N]
	if "!ny!" == "y" endlocal&goto BuildCNIP
	if "!ny!" == "n" exit
	endlocal&goto RebuildDAL
)
endlocal

:: 提取CN地区IP数据
:BuildCNIP
call:[ExtractCNIPList] 4
call:[ExtractCNIPList] 6

:: 验证新旧IP数据MD5
call:[Hash_CNIPList] 4
call:[Hash_CNIPList] 6
:: 如果cnip列表未更新,则直接抽取cnip路由表缓存重建或直接重建路由表
if defined IPV4md5_lab if exist #Routingipv4# set IPV4RoutCache=EXIST
if defined IPV6md5_lab if exist #Routingipv6# set IPV6RoutCache=EXIST

:: 标准化原始数据
:FormatIPList
title 路由表一键更新: 整理数据中...
del /s/q "%temp%\#ipv4listLab#" >nul 2>nul
del /s/q "%temp%\#ipv6listLab#" >nul 2>nul
if not defined IPV4RoutCache null>"%temp%\#ipv4listLab#" 2>nul&start /min "路由表一键更新: 生成ipv4路由表中..." "%~f0" [FormatIPV4List]S
if not defined IPV6RoutCache null>"%temp%\#ipv6listLab#" 2>nul&start /min "路由表一键更新: 生成ipv6路由表中..." "%~f0" [FormatIPV6List]S
:FormatIPList_DetectLabel
:: 检测结束等待标志
if exist "%temp%\#ipv4listLab#" ping /n 3 127.0.0.1>nul&goto FormatIPList_DetectLabel
if exist "%temp%\#ipv6listLab#" ping /n 3 127.0.0.1>nul&goto FormatIPList_DetectLabel

:WriteFile
:: 合并整合数据
(echo.[Local Routing]
echo.## China mainland routing blocks
echo.## Source: https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
echo.## Last update: %date:~0,4%-%date:~5,2%-%date:~8,2%)>Routing.txt
:: 创建列表头文件
call:[WriteIPHead] 4
call:[WriteIPHead] 6
:: 整合数据
copy /y/b Routing.txt+"%temp%\IPv4ListHead"+#Routingipv4#+"%temp%\IPv6ListHead"+#Routingipv6# Routing.txt
goto END

:[DownloadData]
copy /b/y ..\Support\curl.exe %temp% >nul
cd /D %temp%
if not "%ST%" == "LOCAL" (
	curl "https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest" -o "delegated-apnic-latest"
	del /F /Q curl.exe
	cd /D "%~dp0"
	copy /b/y "%temp%\delegated-apnic-latest" .\delegated-apnic-latest >nul
) else (
	curl "file://%~dp0delegated-apnic-latest" -o "delegated-apnic-latest" 2>nul||del /F /Q curl.exe&&echo.不存在本地文件..&&ping /n 2 127.0.0.1>nul&&goto END
	del /F /Q curl.exe
	cd /D "%~dp0"
)
goto :eof

:[Hash_DAL]
setlocal enabledelayedexpansion
:: 抽取新文件的MD5
for /f "delims=" %%i in ('..\Support\md5 -n "%temp%\delegated-apnic-latest"') do set DAL_newmd5=%%i
:: 抽取最后一次更新时的MD5
for /f "delims=." %%i in ('dir /a:-d/b ".\latest\*.md5" 2^>nul') do set DAL_oldmd5=%%i
if not defined DAL_oldmd5 set DAL_oldmd5=00000000000000000000000000000000
:: 数据层面的差别验证
if "%DAL_oldmd5%" == "%DAL_newmd5%" (
	:: 数据未更新,标志位挂起
	set DALmd5_lab=EQUAL
) else (
	:: 数据已更新,更新本地缓存
	copy /b/y "%temp%\delegated-apnic-latest" ".\latest\%DAL_oldmd5%.md5" >nul
	ren ".\latest\%DAL_oldmd5%.md5" "%DAL_newmd5%.md5" >nul 2>nul
)
del /s/q "%temp%\delegated-apnic-latest" >nul 2>nul
for /f "tokens=1-2 delims=|" %%i in ("%DAL_newmd5%|%DALmd5_lab%") do endlocal&set DALmd5=%%i&set DALmd5_lab=%%j
goto :eof

:[ExtractCNIPList]
:: 提取cnip列表
type ".\latest\%DALmd5%.md5"|findstr ipv%1|findstr CN>"%temp%\#listipv%1#"
goto :eof

:[Hash_CNIPList]
setlocal enabledelayedexpansion
:: 抽取新文件的MD5
for /f "delims=" %%i in ('..\Support\md5 -n "%temp%\#listipv%1#"') do set IPV%1_newmd5=%%i
:: 抽取最后一次更新时的MD5
for /f "delims=." %%i in ('dir /a:-d/b ".\latest\ipv%1\*.md5" 2^>nul') do set IPV%1_oldmd5=%%i
if not defined IPV%1_oldmd5 set IPV%1_oldmd5=00000000000000000000000000000000
:: 数据层面的差别验证
if "!IPV%1_oldmd5!" == "!IPV%1_newmd5!" (
	:: 数据未更新,标志位挂起
	set IPV%1md5_lab=EQUAL
) else (
	:: 数据已更新,更新本地缓存
	copy /b/y "%temp%\#listipv%1#" ".\latest\ipv%1\!IPV%1_oldmd5!.md5" >nul
	ren ".\latest\ipv%1\!IPV%1_oldmd5!.md5" "!IPV%1_newmd5!.md5" >nul 2>nul
)
del /s/q "%temp%\#listipv%1#" >nul 2>nul
for /f "tokens=1-2 delims=|" %%i in ("!IPV%1_newmd5!|!IPV%1md5_lab!") do endlocal&set IPV%1md5=%%i&set IPV%1md5_lab=%%j
goto :eof

:[FormatIPV6List]S
:: 格式化ipv6列表
@echo off&title 路由表一键更新: 生成ipv6路由表中...
(for /f "tokens=4-5 delims=|" %%i in ('type ".\latest\ipv6\%IPV6md5%.md5"') do echo %%i/%%j|..\Support\ccase)>#Routingipv6#
:: 删除结束等待标志
del /s/q "%temp%\#ipv6listLab#" >nul 2>nul
exit

:[FormatIPV4List]S
:: 格式化ipv4列表
@echo off&title 路由表一键更新: 生成ipv4路由表中...
(for /f "tokens=4-5 delims=|" %%i in ('type ".\latest\ipv4\%IPV4md5%.md5"') do echo.%%i/%%j#)>#Routingipv4#
set /a index=1,indexx=2,index_out=0
set str=*&set lop=0
:[FormatIPV4List]S_LOOP
if %lop% geq 32 start /w "路由表一键更新: 生成ipv4路由表发生错误..." "%~f0" [FormatIPV4List]S_ERROR&goto END
for /f "tokens=1-2 delims=/#" %%i in ('findstr /v "%str%" #Routingipv4#') do (
	set address=%%i&set /a value_mi=%%j
	call:[SearchLIB]
	set /a lop+=1
	goto [FormatIPV4List]S_LOOP
)
..\Support\sed -i "s/#//g" #Routingipv4#
goto [FormatIPV4List]S_END
:[FormatIPV4List]S_ERROR
echo.列表存在未知错误,即将退出...
ping /n 3 127.0.0.1>nul
:[FormatIPV4List]S_END
:: 删除结束等待标志
del /s/q "%temp%\#ipv4listLab#" >nul 2>nul
exit

:[SearchLIB]
for /f "tokens=1-2 delims=/" %%i in ('findstr "%value_mi%\/" Log_Lib 2^>nul') do set count=%%j
if not defined count call:[logT]
:: 替换所有 /%value_mi% 为 /%count%
..\Support\sed -i "s/\/%value_mi%#/\/%count%#/g" #Routingipv4#
if not "%str%" == "*" (set str=%str% \/%count%#) else set str=\/%count%#
set count=
goto :eof

:[logT]
:: value_mi 值勿超过 2^31-1 也就是 2147483647,由于 2147483647 不是 2 的幂,实际情况是最大 2^30 也就是 1073741824
:[logT][inte]
setlocal enabledelayedexpansion
if %value_mi% == 0 goto [logT][end]
if %value_mi% == 1 goto [logT][end]
:[logT][main]
if %value_mi% gtr 1 (
	set /a value_mi">>="index,index_out+=index
	if !value_mi! equ 1 goto [logT][end]
	if !value_mi! lss 1 set /a index=1,indexx=2,value_mi=%value_mi%,index_out=%index_out%&goto [logT][main]
	if !value_mi! lss !indexx! set /a index=1,indexx=2&goto [logT][main]
	if !value_mi! equ !indexx! set /a index_out+=index&goto [logT][end]
	set /a index*=2,indexx*=indexx
	goto [logT][main]
)
:[logT][end]
for /f %%s in ("%index_out%") do endlocal&set /a count=32-%%s
echo.%value_mi%/%count%>>Log_Lib
goto :eof

:[WriteIPHead]
:: 写入列表头
(echo.
echo.
echo.## IPv%1
)>"%temp%\IPv%1ListHead"
goto :eof

:END
exit
