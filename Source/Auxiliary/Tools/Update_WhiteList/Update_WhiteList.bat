:: Pcap_DNSProxy white list update batch
:: Pcap_DNSProxy, a local DNS server based on WinPcap and LibPcap
:: Author: dgeibi, Chengr28


@echo off

:: Write header and download latest data.
..\Support\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
(
	echo.[Local Hosts]
	echo.## China mainland domains
	echo.## Source: https://github.com/felixonmars/dnsmasq-china-list
	echo.## Last update: %date:~0,4%-%date:~5,2%-%date:~8,2%
	echo.
	echo.
) > "WhiteList.txt"
..\Support\sed -e "s@114.114.114.114$@@" -e "s@^s@S@" accelerated-domains.china.conf >> WhiteList.txt
del /F /Q accelerated-domains.china.conf


:: Choice(Google)
:Continue_Google
echo.
set /P Input=Do you want to add Google domain database(google.china.conf)? [Y/N]:
if /i "%Input%"=="Y" goto Google
if /i "%Input%"=="N" goto Continue_Apple
goto Continue_Google


:: Database of Google
:Google
echo.
..\Support\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf
..\Support\sed -e "s@114.114.114.114$@@" -e "s@^s@S@" google.china.conf >> WhiteList.txt
del /F /Q google.china.conf


:: Choice(Apple)
:Continue_Apple
echo.
set /P Input=Do you want to add Apple domain database(apple.china.conf)? [Y/N]:
if /i "%Input%"=="Y" goto Apple
if /i "%Input%"=="N" goto Exit
goto Continue_Apple


:: Database of Apple
:Apple
echo.
..\Support\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf
..\Support\sed -e "s@114.114.114.114$@@" -e "s@^s@S@" apple.china.conf >> WhiteList.txt
del /F /Q apple.china.conf


:: Default database
:Exit
echo.
pause
