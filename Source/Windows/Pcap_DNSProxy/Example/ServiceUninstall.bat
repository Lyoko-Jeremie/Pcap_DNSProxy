:: Pcap_DNSProxy uninstall service batch
:: A local DNS server base on WinPcap and LibPcap.
:: 
:: Author: Chengr28
:: 

@echo off

sc stop PcapDNSProxyService
sc delete PcapDNSProxyService
@echo.
@echo Done. Please confirm the PcapDNSProxyService service had been deleted.
@echo.
@pause
