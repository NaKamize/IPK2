### Obsah:
Makefile
ipk-sniffer.cpp
README.md
manual.pdf
### Spustenie:
Preložiť program pomocou príkazu make. Sniffer je potrebné spustit s root opravneniami v promiscuous režime.
Výpis dostupných rozhraní : ./ipk-sniffer
						./ipk-sniffer -i
						./ipk-sniffer --interface
Zachytávanie paketov na rozhraní: ./ipk-sniffer -i ens33
Väčšie množstvo paketov: ./ipk-sniffer -i ens33 -n 10
Obdmezdenie protokolov: ./ipk-sniffer -i ens33 --tcp (funguje -t, -u, --tcp, --udp, --icmp, --arp).
Filtrovanie pomocou portu ./ipk-sniffer -i ens33 --tcp -p 23 (funguje u TCP a UDP prokolov).
V prípade že bol zachytený paket, ktorý nevyhovuje požiadavkam príkazovej riadky nebude vypísaný.
V prípade zachytenia konkrétneho paketu pr. ARP, ktorý je zamiešaný medzi inými paketmi je možné nastaviť parameter -n na väčšie číslo.
