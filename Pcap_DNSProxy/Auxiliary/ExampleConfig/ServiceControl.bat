:: Pcap_DNSProxy service control batch
:: Pcap_DNSProxy, a local DNS server based on packet capturing
:: 
:: Contributions: Hugo Chan, Stzx, Syrone Wong, Chengr28
:: 


@CHCP 65001
@ECHO off
CLS


:: Administrative permission check
net session >nul 2>nul
IF ERRORLEVEL 1 (
	COLOR 4F
	ECHO Please run as Administrator.
	ECHO.
	PAUSE & BREAK
	ECHO.
	CLS
)


:: Processor architecture check
SET Architecture=
IF %PROCESSOR_ARCHITECTURE%%PROCESSOR_ARCHITEW6432% == x86 (
	SET Architecture=_x86
)
SET Executable=Pcap_DNSProxy%Architecture%.exe
SET ServiceName=PcapDNSProxyService


:: Command
SET Command=%~1
IF NOT "%Command%" == "" (
	GOTO CASE_%Command%
)


:: Choice
:CHOICE
ECHO Pcap_DNSProxy service control batch
ECHO.
ECHO 1: Install service
ECHO 2: Uninstall service
ECHO 3: Start service
ECHO 4: Stop service
ECHO 5: Restart service
ECHO 6: Flush domain cache in Pcap_DNSProxy
ECHO 7: Flush domain cache in system only
ECHO 8: Exit
ECHO.
SET /P UserChoice="Choose: "
SET UserChoice=CASE_%UserChoice%
CD /D "%~dp0"
CLS
GOTO %UserChoice%


:: Service install
:CASE_1
	CALL :DELETE_SERVICE
	ping 127.0.0.1 -n 3 >nul
	CALL :KILL_PROCESS
	ping 127.0.0.1 -n 3 >nul
	sc create %ServiceName% binPath= "%~dp0%Executable%" DisplayName= "Pcap_DNSProxy Service" start= auto
	%Executable% --firewall-test
	sc description %ServiceName% "Pcap_DNSProxy, a local DNS server based on packet capturing"
	sc failure %ServiceName% reset= 0 actions= restart/5000/restart/10000//
	sc start %ServiceName%
::	IF %ERRORLEVEL% EQU 0 (
::		ipconfig /flushdns
::	)
	CALL :CHECK_PROCESS
	IF "%Command%" == "" (
		PAUSE
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Service uninstall
:CASE_2
	CALL :DELETE_SERVICE
	ping 127.0.0.1 -n 3 >nul
	CALL :KILL_PROCESS
	ipconfig /flushdns
	IF "%Command%" == "" (
		ECHO.
		PAUSE
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Service start
:CASE_3
	sc query %ServiceName% >nul
	IF %ERRORLEVEL% EQU 0 (
		CALL :START_SERVICE
	) ELSE (
		COLOR 4F
		ECHO The service seems not installed.
		ECHO.
	)
	IF "%Command%" == "" (
		PAUSE
		COLOR
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Service stop
:CASE_4
	CALL :STOP_SERVICE
	ping 127.0.0.1 -n 3 >nul
	ipconfig /flushdns
	IF "%Command%" == "" (
		ECHO.
		PAUSE
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Service restart
:CASE_5
	CALL :STOP_SERVICE
	ping 127.0.0.1 -n 3 >nul
	CALL :KILL_PROCESS
	ping 127.0.0.1 -n 3 >nul
	CALL :START_SERVICE
	IF "%Command%" == "" (
		PAUSE
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Flush domain cache(Pcap_DNSProxy)
:CASE_6
	CALL :CHECK_PROCESS
	%Executable% --flush-dns
	IF "%Command%" == "" (
		ECHO.
		PAUSE
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Flush domain cache(System)
:CASE_7
	ipconfig /flushdns
	IF "%Command%" == "" (
		ECHO.
		PAUSE
		CLS
		GOTO CHOICE
	) ELSE (
		EXIT
	)


:: Exit
:CASE_8
	COLOR
	EXIT


:: Process check
:CHECK_PROCESS
	tasklist | findstr /L /I "%Executable%" >nul
	IF %ERRORLEVEL% NEQ 0 (
		COLOR 4F
		ECHO.
		ECHO The program is not running, please check the configuration and error log.
		ECHO.
		PAUSE
		COLOR
		CLS
		GOTO CHOICE
	)
	ECHO.
	GOTO :EOF


:: Process kill
:KILL_PROCESS
	tasklist | findstr /L /I "%Executable%" >nul && taskkill /F /IM %Executable% >nul
	GOTO :EOF


:: Service start
:START_SERVICE
	sc query %ServiceName% >nul && ( sc query %ServiceName% | find "RUNNING" >nul || sc start %ServiceName% )
	IF %ERRORLEVEL% EQU 0 (
		ping 127.0.0.1 -n 3 >nul
::		ipconfig /flushdns
::		ping 127.0.0.1 -n 3 >nul
		CALL :CHECK_PROCESS
	)
	GOTO :EOF


:: Service stop
:STOP_SERVICE
	sc query %ServiceName% >nul && ( sc query %ServiceName% | find "STOPPED" >nul || sc stop %ServiceName% )
	GOTO :EOF


:: Service delete
:DELETE_SERVICE
	sc query %ServiceName% >nul && ( sc query %ServiceName% | find "STOPPED" >nul || sc stop %ServiceName% ) && sc delete %ServiceName%
	GOTO :EOF
