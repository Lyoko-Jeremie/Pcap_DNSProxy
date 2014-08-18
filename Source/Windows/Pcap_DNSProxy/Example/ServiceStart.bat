:: Pcap_DNSProxy start service batch
:: A local DNS server base on WinPcap and LibPcap.
:: 
:: Author: Hugo Chan, Chengr28
:: 

@echo off

:: Files check
if not exist Fciv.exe goto Warning
if not exist Pcap_DNSProxy.exe goto Warning
if not exist Pcap_DNSProxy_x86.exe goto Warning
cls

:Hash-A
Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 9B4746F96FAC1433842C94AB553B3B9420B5A8DC > NUL

goto HASH-%ERRORLEVEL%
:HASH-0
goto HASH-B
:HASH-1
goto Warning

:Hash-B
Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I ACD9C7AFBFFC0845989C0CF0CE47A86E17CA2B73 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto Main
:HASH-1
goto Warning

:Warning
@echo.
@echo The file(s) may be damaged or corrupt!
@echo Please download all files again, also you can skip this check.
choice /M "Are you sure you want to continue start service"
if errorlevel 2 exit
if errorlevel 1 echo.

:: Main process
:Main
sc start PcapDNSProxyService
ipconfig /flushdns
@echo.
@echo Done. Please confirm the PcapDNSProxyService service had been started.
@echo.
@pause
