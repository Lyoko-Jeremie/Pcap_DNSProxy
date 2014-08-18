:: Pcap_DNSProxy stop service batch
:: A local DNS server base on WinPcap and LibPcap.
:: 
:: Author: Chengr28
:: 

@echo off

sc stop PcapDNSProxyService
@echo.
@echo Done. Please confirm the PcapDNSProxyService service had been stopped.
@echo.
@pause
