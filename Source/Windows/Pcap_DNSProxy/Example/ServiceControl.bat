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


:: Choice(Part 1)
set /p UserChoice="Choose: "


:: Permission check
	if %UserChoice% GTR 0 (
		if %UserChoice% LSS 6 (
			@echo.
			if %PROCESSOR_ARCHITECTURE% EQU AMD64 (
				cd /d "%SystemRoot%\System32"
			) else (
				cd /d "%SystemRoot%\SysWOW64"
			)
			del /f /q TestPermission.log
			@echo Permission check. > TestPermission.log
			if not exist TestPermission.log (
				@echo.
				@echo Require Administrator permission!
				@pause
				exit
			) else (
				del /f /q TestPermission.log
				cd /d "%~dp0"
				cls
			)
		)
	)

:: Files check
	set FileCheck=0
	if %UserChoice% EQU 0 (set FileCheck=1)
	if %UserChoice% EQU 3 (set FileCheck=1)
	if %UserChoice% EQU 5 (set FileCheck=1)
	if %FileCheck% EQU 1 (
		cd /d "%~dp0"
		if not exist Fciv.exe (goto WARNING)
		if not exist Pcap_DNSProxy.exe (goto WARNING)
		if not exist Pcap_DNSProxy_x86.exe (goto WARNING)
		Fciv -sha1 Pcap_DNSProxy.exe |findstr /I 712685C61DB12EB0E1AF5271F4421E28E041CEDD > NUL
		if ERRORLEVEL 1 (goto WARNING)
		Fciv -sha1 Pcap_DNSProxy_x86.exe |findstr /I AFF92F1F67A3C2172FA1EC1308E8FC2ABA2E9413 > NUL
		if ERRORLEVEL 1 (goto WARNING)
	)
	goto CHOICE

:WARNING
	@echo.
	@echo The file(s) may be damaged or corrupt!
	@echo Please download all files again, also you can skip this check.
	set /p UserChoice_File="Are you sure you want to continue? [Y/N]"
	if /i %UserChoice_File% EQU Y (goto CHOICE) else exit

:: Choice(Part 2)
:CHOICE
set UserChoice=CASE_%UserChoice%
cls
goto %UserChoice%


:: Service Install part
:: Author: Hugo Chan, Chengr28
:CASE_1
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (goto X86) else (goto X64)

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
:CASE_2
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ipconfig /flushdns
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been deleted.
	@echo.
	@pause
	exit


:: Service Start part
:: Author: Hugo Chan, Chengr28
:CASE_3
	sc start PcapDNSProxyService
	ipconfig /flushdns
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been started.
	@echo.
	@pause
	exit


:: Service Stop part
:: Author: Chengr28
:CASE_4
	sc stop PcapDNSProxyService
	ipconfig /flushdns
	@echo.
	@echo Done. Please confirm the PcapDNSProxyService service had been stopped.
	@echo.
	@pause
	exit


:: Service Restart part
:: Author: Chengr28
:CASE_5
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
:CASE_6
	@echo.
	sc query PcapDNSProxyService | find "SERVICE_NAME: PcapDNSProxyService"
	@echo.
	@pause
	exit
