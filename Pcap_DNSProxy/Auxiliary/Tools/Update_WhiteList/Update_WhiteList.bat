:: Pcap_DNSProxy white list update batch
:: Pcap_DNSProxy, a local DNS server based on packet capturing
:: 
:: Contributions: dgeibi, Chengr28
:: 


@CHCP 65001
@ECHO off
CLS


:: Write header and download latest data.
..\Binary\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf
(
	ECHO.[Local Hosts]
	ECHO.## China mainland domains
	ECHO.## Source: https://github.com/felixonmars/dnsmasq-china-list
	ECHO.## Last update: %date:~0,4%-%date:~5,2%-%date:~8,2%
	ECHO.
	ECHO.
) > "WhiteList.txt"
ECHO.
..\Binary\sed -e "s@114.114.114.114$@@" -e "s@^s@S@" accelerated-domains.china.conf >> WhiteList.txt
DEL /F /Q accelerated-domains.china.conf


:: Choice Google
:CHOICE_GOOGLE
ECHO.
SET /P Input=Do you want to add Google domain database(google.china.conf)? [Y/N]:
IF /I "%Input%"=="Y" GOTO PART_GOOGLE
IF /I "%Input%"=="N" GOTO CHOICE_APPLE
GOTO CHOICE_GOOGLE


:: Download domain data of Google in Mainland China part.
:PART_GOOGLE
ECHO.
..\Binary\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf
ECHO.
..\Binary\sed -e "s@114.114.114.114$@@" -e "s@^s@S@" google.china.conf >> WhiteList.txt
DEL /F /Q google.china.conf


:: Choice Apple
:CHOICE_APPLE
ECHO.
SET /P Input=Do you want to add Apple domain database(apple.china.conf)? [Y/N]:
IF /I "%Input%"=="Y" GOTO PART_APPLE
IF /I "%Input%"=="N" GOTO END
GOTO CHOICE_APPLE


:: Download domain data of Apple in Mainland China part.
:PART_APPLE
ECHO.
..\Binary\curl -O https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf
ECHO.
..\Binary\sed -e "s@114.114.114.114$@@" -e "s@^s@S@" apple.china.conf >> WhiteList.txt
DEL /F /Q apple.china.conf


:: Exit
:END
ECHO.
PAUSE
