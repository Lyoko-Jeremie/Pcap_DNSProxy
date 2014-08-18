:: Pcap_DNSProxy install service batch
:: A local DNS server base on WinPcap and LibPcap.
:: 
:: Author: Hugo Chan, Chengr28
:: 

@echo off

:: Permission check
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (set SystemPath = %SystemRoot%\SysWOW64) else (set SystemPath = %SystemRoot%\system32)
rd "%SystemPath%\test_permissions" > nul 2 > nul
md "%SystemPath%\test_permissions" 2 > nul || (echo Require Administrator Permission. && pause > nul && Exit)
rd "%SystemPath%\test_permissions" > nul 2 > nul
cd /d %~dp0

:: Files check
if not exist Fciv.exe goto Warning
if not exist Pcap_DNSProxy.exe goto Warning
if not exist KeyPairGenerator.exe goto Warning
if not exist Pcap_DNSProxy_x86.exe goto Warning
if not exist KeyPairGenerator_x86.exe goto Warning
cls

:Hash-A
Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 9B4746F96FAC1433842C94AB553B3B9420B5A8DC > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto HASH-B
:HASH-1
goto Warning

:Hash-B
Fciv -sha1 KeyPairGenerator.exe |findstr /I AEABC26182DF9895FCE6A667BE2198d9BD5E2F68 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto HASH-C
:HASH-1
goto Warning

:Hash-C
Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I ACD9C7AFBFFC0845989C0CF0CE47A86E17CA2B73 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto HASH-D
:HASH-1
goto Warning

:Hash-D
Fciv -sha1 KeyPairGenerator_x86.exe |findstr /I C4AC11B52F51b8E61380FD23B2CE20458A65BD47 > NUL
goto HASH-%ERRORLEVEL%
:HASH-0
goto Type
:HASH-1
goto Warning

:Warning
@echo.
@echo The file(s) may be damaged or corrupt!
@echo Please download all files again, also you can skip this check.
choice /M "Are you sure you want to continue install service"
if errorlevel 2 exit
if errorlevel 1 echo.

:: Architecture check and main process
:Type
sc stop PcapDNSProxyService
sc delete PcapDNSProxyService
if "%PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432%" == "x86" (goto X86) else goto X64

:X86
sc create PcapDNSProxyService binPath= "%~dp0Pcap_DNSProxy_x86.exe" start= auto
reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0Pcap_DNSProxy_x86.exe" /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
Pcap_DNSProxy_x86 --FirstStart
goto Exit

:X64
sc create PcapDNSProxyService binPath= "%~dp0Pcap_DNSProxy.exe" start= auto
reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0Pcap_DNSProxy.exe" /f
reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
Pcap_DNSProxy --FirstStart
goto Exit

:Exit
sc description PcapDNSProxyService "A local DNS server base on WinPcap and LibPcap."
sc start PcapDNSProxyService
ipconfig /flushdns
@echo.
@echo Done. Please confirm the PcapDNSProxyService service had been installed.
@echo.
@pause
