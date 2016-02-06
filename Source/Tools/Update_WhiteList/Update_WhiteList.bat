:: Pcap_DNSProxy white list update batch
:: A local DNS server based on WinPcap and LibPcap
:: Author: dgeibi, Chengr28


@echo off

:: Write header and download latest data.
(
	echo.[Local Hosts]
	echo.## China mainland domains
	echo.## Source: https://github.com/felixonmars/dnsmasq-china-list
	echo.## Last update: %date:~0,4%-%date:~5,2%-%date:~8,2%
	echo.
	echo.
) > "WhiteList.txt"
..\Support\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
..\Support\sed -e "s@/114.114.114.114$@@" -e "s@\.@\\\.@g" -e "s@server=/@\.*\\b@" -e "s@bcn$@\.cn\$@" accelerated-domains.china.conf >> WhiteList.txt
del /F /Q accelerated-domains.china.conf

:: Choice
:Continue
echo.
set /P X=Use google.china.conf? [Y/N]:
if /i "%X%"=="Y" goto Google
if /i "%X%"=="N" goto Default
goto Continue

:: Database with Google
:Google
..\Support\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf
..\Support\sed -e "s@/114.114.114.114$@@" -e "s@\.@\\\.@g" -e "s@server=/@\.*\\b@" google.china.conf >> WhiteList.txt
del /F /Q google.china.conf

:: Default database
:Default
echo.
pause
