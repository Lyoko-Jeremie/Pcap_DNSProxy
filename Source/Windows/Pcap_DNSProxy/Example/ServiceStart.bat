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
Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 62E818167427E4E6DA33EF83B3D458C0611089F6 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto HASH-B
:HASH-1
goto Warning

:Hash-B
Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I C85F71A58CAFC0505E76CB160B12DE491611B8D3 > NUL
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
