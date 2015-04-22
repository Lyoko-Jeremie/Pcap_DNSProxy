:: Pcap_DNSProxy service control batch
:: A local DNS server base on WinPcap and LibPcap.


@echo off

:: Get Administrator Privileges
:: Author: Evan Greene
:: https://sites.google.com/site/eneerge/home/BatchGotAdmin
>nul 2>&1 "%SystemRoot%\system32\cacls.exe" "%SystemRoot%\system32\config\system"
if '%errorlevel%' NEQ '0' (
	echo Requesting Administrative Privileges...
	goto UAC_Prompt
) else (
	goto Get_Admin
)

:UAC_Prompt
	echo set UAC = CreateObject^("Shell.Application"^) > "%TEMP%\GetAdmin.vbs"
	echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%TEMP%\GetAdmin.vbs"
	"%TEMP%\GetAdmin.vbs"
	exit /B

:Get_Admin
	if exist "%TEMP%\GetAdmin.vbs" (del "%TEMP%\GetAdmin.vbs" )
	pushd "%cd%"
	cd /D "%~dp0"


:: Choice
echo Pcap_DNSProxy service control batch
echo.
echo 1: Install service
echo 2: Uninstall service
echo 3: Start service
echo 4: Stop service
echo 5: Restart service
echo 6: Service Query(Windows XP/2003 only)
echo.
set /P UserChoice="Choose: "
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
	Pcap_DNSProxy_x86.exe --FirstStart
	goto Exit

	:X64
	sc create PcapDNSProxyService binPath= "%~dp0Pcap_DNSProxy.exe" DisplayName= "PcapDNSProxy Service" start= auto
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0Pcap_DNSProxy.exe" /f
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
	Pcap_DNSProxy.exe --FirstStart

	:Exit
	sc description PcapDNSProxyService "A local DNS server base on WinPcap and LibPcap."
	sc failure PcapDNSProxyService reset= 0 actions= restart/5000/restart/10000//
	sc start PcapDNSProxyService
	ipconfig /flushdns
	ping 127.0.0.1 -n 3 >nul
	if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (
		Tasklist |findstr /I "Pcap_DNSProxy_x86.exe" > NUL
	) else (
		Tasklist |findstr /I "Pcap_DNSProxy.exe" > NUL
	)
	if ERRORLEVEL 1 (
		echo.
		echo Service start failed, please check the configurations.
	)
	echo.
	pause
	exit


:: Service Uninstall part
:: Author: Chengr28
:CASE_2
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ipconfig /flushdns
	echo.
	pause
	exit


:: Service Start part
:: Author: Hugo Chan, Chengr28
:CASE_3
	sc start PcapDNSProxyService
	ipconfig /flushdns
	ping 127.0.0.1 -n 3 >nul
	if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (
		Tasklist |findstr /I "Pcap_DNSProxy_x86.exe" > NUL
	) else (
		Tasklist |findstr /I "Pcap_DNSProxy.exe" > NUL
	)
	if ERRORLEVEL 1 (
		echo.
		echo Service start failed, please check the configurations.
	)
	echo.
	pause
	exit


:: Service Stop part
:: Author: Chengr28
:CASE_4
	sc stop PcapDNSProxyService
	ipconfig /flushdns
	echo.
	pause
	exit


:: Service Restart part
:: Author: Chengr28
:CASE_5
	sc stop PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	sc start PcapDNSProxyService
	ipconfig /flushdns
	ping 127.0.0.1 -n 3 >nul
	if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (
		Tasklist |findstr /I "Pcap_DNSProxy_x86.exe" > NUL
	) else (
		Tasklist |findstr /I "Pcap_DNSProxy.exe" > NUL
	)
	if ERRORLEVEL 1 (
		echo.
		echo Service start failed, please check the configurations.
	)
	echo.
	pause
	exit


:: Service Query part
:: Author: PyDNSProxy project(https://code.google.com/p/pydnsproxy)
:: In Windows XP/2003, 'sc query' will always exit with status code '0',
:: No matter the query faild or not.
:CASE_6
	echo.
	sc query PcapDNSProxyService | find "SERVICE_NAME: PcapDNSProxyService"
	echo.
	pause
	exit
