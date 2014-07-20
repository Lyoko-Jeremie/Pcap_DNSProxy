@echo off
if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (set SystemPath = %SystemRoot%\SysWOW64) else (set SystemPath = %SystemRoot%\system32)
rd "%SystemPath%\test_permissions" > nul 2 > nul
md "%SystemPath%\test_permissions" 2 > nul || (echo Require Administrator Permission. && pause > nul && Exit)
rd "%SystemPath%\test_permissions" > nul 2 > nul
cd /d %~dp0
cls

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

:Exit
sc description PcapDNSProxyService "A local DNS server base on WinPcap and LibPcap."
sc start PcapDNSProxyService
echo.
echo Done. Please confirm the PcapDNSProxyService service had been installed.
echo.
pause
