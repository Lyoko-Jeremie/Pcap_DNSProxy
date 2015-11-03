:: Pcap_DNSProxy service control batch
:: A local DNS server based on WinPcap and LibPcap
:: Author: Hugo Chan, wongsyrone, Chengr28


@echo off


:: Check processor architecture.
set Arch=
if %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (set Arch=_x86)
set Prog=Pcap_DNSProxy%Arch%.exe


:: Choice
echo Pcap_DNSProxy service control batch
echo.
echo 1: Install service
echo 2: Uninstall service
echo 3: Start service
echo 4: Stop service
echo 5: Restart service
echo 6: Flush DNS cache in Pcap_DNSProxy
echo.
set /P UserChoice="Choose: "
set UserChoice=CASE_%UserChoice%
cd /D "%~dp0"
cls
goto %UserChoice%


:: Service install part
:CASE_1
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul

	sc create PcapDNSProxyService binPath= "%~dp0%Prog%" DisplayName= "PcapDNSProxy Service" start= auto
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v Application /d "%~dp0%Prog%" /f
	reg add HKLM\SYSTEM\CurrentControlSet\Services\PcapDNSProxyService\Parameters /v AppDirectory /d "%~dp0" /f
	%Prog% --first-setup

	sc description PcapDNSProxyService "A local DNS server based on WinPcap and LibPcap"
	sc failure PcapDNSProxyService reset= 0 actions= restart/5000/restart/10000//
	sc start PcapDNSProxyService
	ipconfig /flushdns
	call :CHECK_PROG
	pause
	exit


:: Service uninstall part
:CASE_2
	sc stop PcapDNSProxyService
	sc delete PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	ipconfig /flushdns
	echo.
	pause
	exit


:: Service start part
:CASE_3
	sc start PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	ipconfig /flushdns
	ping 127.0.0.1 -n 3 >nul
	call :CHECK_PROG
	pause
	exit


:: Service stop part
:CASE_4
	sc stop PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	ipconfig /flushdns
	echo.
	pause
	exit


:: Service restart part
:CASE_5
	sc stop PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	sc start PcapDNSProxyService
	ping 127.0.0.1 -n 3 >nul
	ipconfig /flushdns
	call :CHECK_PROG
	pause
	exit


:: Flush DNS cache part
:CASE_6
	echo.
	%Prog% --flush-dns
	echo.
	pause
	exit


:: Process check
:CHECK_PROG
	Tasklist |findstr /I "%Prog%" > NUL
	if ERRORLEVEL 1 (
		echo.
		echo Service start failed, please check the configurations.
	)
	echo.
