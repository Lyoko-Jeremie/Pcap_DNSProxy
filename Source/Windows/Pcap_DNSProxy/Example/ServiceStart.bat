:: Pcap_DNSProxy start service batch
:: A local DNS server base on WinPcap and LibPcap.
:: 
:: Author: Hugo Chan, Chengr28
:: 

@echo off

:: Files check
cd /d %~dp0
cls
if not exist Fciv.exe goto Warning
if not exist Pcap_DNSProxy.exe goto Warning
if not exist Pcap_DNSProxy_x86.exe goto Warning

:Hash-A
Fciv -sha1 Pcap_DNSProxy.exe |findstr /I CC9BE6CD0FCFD5E67985E5AD9CBA3A1E6D0CB987 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto HASH-B
:HASH-1
goto Warning

:Hash-B
Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I 87B02F9CC0456B1724EE84CD7792E88C2466C8E8 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto Main
:HASH-1
goto Warning

:Warning
@echo.
@echo The file(s) may be damaged or corrupt!
@echo Please download all files again, also you can skip this check.
:: Choice.exe cannot be run in Windows XP/2003.
:: choice /M "Are you sure you want to continue start service"
:: if errorlevel 2 exit
:: if errorlevel 1 echo.
set /p UserChoice="Are you sure you want to continue start service? [Y/N]"
if /i "%UserChoice%" == "Y" (goto Main) else exit

:: Main process
:Main
sc start PcapDNSProxyService
ipconfig /flushdns
@echo.
@echo Done. Please confirm the PcapDNSProxyService service had been started.
@echo.
@pause
