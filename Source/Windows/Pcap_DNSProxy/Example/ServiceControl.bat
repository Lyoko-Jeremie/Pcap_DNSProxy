:: Pcap_DNSProxy service control batch
:: A local DNS server base on WinPcap and LibPcap.

@echo off

@echo Pcap_DNSProxy service control batch
@echo.
@echo 1: Install service
@echo 2: Uninstall service
@echo 3: Start service
@echo 4: Stop service
@echo 5: Restart service
@echo 6: Service Query(Windows XP/2003 only)
@echo.
set /p UserChoice="Choose: "
set UserChoice=Case_%UserChoice%
cls
goto %UserChoice%


:: Service Install part
:: Author: Hugo Chan, Chengr28
:Case_1
	:: Permission check
	if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (set SystemPath=%SystemRoot%\SysWOW64) else (set SystemPath=%SystemRoot%\System32)
	del /f /q %SystemPath%\TestPermission.log
	echo "Permission check." >> %SystemPath%\TestPermission.log
	if not exist %SystemPath%\TestPermission.log (echo Require Administrator permission. && pause > nul && Exit)
	del /f /q %SystemPath%\TestPermission.log

	:: Files check
	cd /d %~dp0
	cls
	if not exist Fciv.exe goto Warning
	if not exist Pcap_DNSProxy.exe goto Warning
	if not exist Pcap_DNSProxy_x86.exe goto Warning

	:Hash-A
	Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 1F4575D0D3442FDA0A908BD2CE02F7A78AFDCCED > NUL
	goto HASH-%ERRORLEVEL%
	:HASH-0
	goto HASH-B
	:HASH-1
	goto Warning

	:Hash-B
	Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I 9E56C4E078C2C22DFBAFD59D398F77C2D5B3CEE3 > NUL
	goto HASH-%ERRORLEVEL%
	:HASH-0
	goto Type
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
	if /i "%UserChoice%" == "Y" (goto Type) else exit

	:: Architecture check and main process
	:Type
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	if "%PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432%" == "x86" (goto X86) else goto X64

	:X86
	sc create PcapDNSProxyService binPath= "%~dp0Pcap_DNSProxy_x86.exe" DisplayName= "PcapDNSProxy Service" start= auto
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0Pcap_DNSProxy_x86.exe" /f
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
	Pcap_DNSProxy_x86 --FirstStart
	goto Exit

	:X64
	sc create PcapDNSProxyService binPath= "%~dp0Pcap_DNSProxy.exe" DisplayName= "PcapDNSProxy Service" start= auto
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0Pcap_DNSProxy.exe" /f
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
	Pcap_DNSProxy --FirstStart
	goto Exit

	:Exit
	sc description PcapDNSProxyService "A local DNS server base on WinPcap and LibPcap."
	sc failure PcapDNSProxyService reset= 0 actions= restart/5000/restart/10000//
	sc start PcapDNSProxyService
	ipconfig /flushdns
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been installed.
	@echo.
	@pause
	exit


:: Service Uninstall part
:: Author: Chengr28
	:Case_2
	:: Permission check
	if "%PROCESSOR_ARCHITECTURE%" == "AMD64" (set SystemPath=%SystemRoot%\SysWOW64) else (set SystemPath=%SystemRoot%\System32)
	del /f /q %SystemPath%\TestPermission.log
	echo "Permission check." >> %SystemPath%\TestPermission.log
	if not exist %SystemPath%\TestPermission.log (echo Require Administrator permission. && pause > nul && Exit)
	del /f /q %SystemPath%\TestPermission.log
	
	cls
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been deleted.
	@echo.
	@pause
	exit


:: Service Start part
:: Author: Hugo Chan, Chengr28
:Case_3
	:: Files check
	cd /d %~dp0
	cls
	if not exist Fciv.exe goto Warning
	if not exist Pcap_DNSProxy.exe goto Warning
	if not exist Pcap_DNSProxy_x86.exe goto Warning

	:Hash-A
	Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 1F4575D0D3442FDA0A908BD2CE02F7A78AFDCCED > NUL
	goto HASH-%ERRORLEVEL%
	:HASH-0
	goto HASH-B
	:HASH-1
	goto Warning

	:Hash-B
	Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I 9E56C4E078C2C22DFBAFD59D398F77C2D5B3CEE3 > NUL
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
	exit


:: Service Stop part
:: Author: Chengr28
:Case_4
	sc stop PcapDNSProxyService
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been stopped.
	@echo.
	@pause
	exit


:: Service Restart part
:: Author: Chengr28
:Case_5
	:: Files check
	cd /d %~dp0
	cls
	if not exist Fciv.exe goto Warning
	if not exist Pcap_DNSProxy.exe goto Warning
	if not exist Pcap_DNSProxy_x86.exe goto Warning

	:Hash-A
	Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 1F4575D0D3442FDA0A908BD2CE02F7A78AFDCCED > NUL
	goto HASH-%ERRORLEVEL%
	:HASH-0
	goto HASH-B
	:HASH-1
	goto Warning

	:Hash-B
	Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I 9E56C4E078C2C22DFBAFD59D398F77C2D5B3CEE3 > NUL
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
	sc stop PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	sc start PcapDNSProxyService
	ipconfig /flushdns
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been restarted.
	@echo.
	@pause
	exit


:: Service Query part
:: Author: PyDNSProxy project(https://code.google.com/p/pydnsproxy)
:: In Windows XP/2003, 'sc query' will always exit with status code '0',
:: No matter the query faild or not.
:Case_6
	@echo.
	sc query PcapDNSProxyService | find "SERVICE_NAME: PcapDNSProxyService"
	@echo.
	@pause
	exit
