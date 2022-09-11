#include <iostream>
#include <getopt.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <ctime>
#include <netinet/ether.h>
#include <iomanip>
#include <sstream>

bool tcp = false;
bool udp = false;
bool arp = false;
bool icmp = false;

/**
 * Zdroj: https://www.cplusplus.com/reference/ctime/strftime/
 * @param pkthdr - hlavička paketu, ktorá obsahuje čas
 */
void print_time(const struct pcap_pkthdr *pkthdr) {
    time_t my_time;
    struct tm *timeinfo;
    char buffer[80];
    my_time = pkthdr->ts.tv_sec;
    timeinfo = localtime(&my_time);

    strftime(buffer, 80, "%FT%T", timeinfo);
    printf("%s.%.3ld", buffer, pkthdr->ts.tv_usec / 1000);
    std::time_t t = std::time(nullptr);
    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%z");
    std::string tz = oss.str();
    tz.insert(3, ":");
    std::cout << tz;
}

/**
 *  Funkcia po 16 zhakov vypisuje hexadecimalnu cast. Po 16 znakoch sa vypisuje aj
 *  ASCII časť. ASCII časť sa ukladá do alfabet, pomocou modulo operátora.
 *  Na konci sa vypíše zvlášť posledný riadok, kedy sa doplnia prázdne miesta v
 *  hexadecimalnej části. Posledné miesta
 * @param len - dlžka paketu
 * @param packet - data paketu
 */
void print_packet(int len, const u_char *packet) {
    int hex_num = 0x000;
    int alfabet[16];
    bool start_print = false;
    unsigned int last_line = (len / 16) * 16;
    int j;
    for (int i = 0; i < len; i++) {

        alfabet[i % 16] = packet[i];

        if (i % 16 == 0) {
            if (start_print) {
                for (j = i; j < i + 16; j++) {
                    if (packet[j - 16] > 31 and packet[j - 16] < 128) {
                        printf("%c", packet[j - 16]);
                    } else {
                        printf(".");
                    }
                }
            }
            start_print = true;
            printf("\n0x%03x0: ", hex_num++);
        }
        printf("%02x ", packet[i]);

        if (i == len-1) {
            unsigned int count_to_print = len - last_line;

            for (unsigned int k = 0; k < 16 - count_to_print; k++) {
                printf("   ");
            }

            for (unsigned int k = 0; k < count_to_print; k++) {
                if (alfabet[k] < 32 or alfabet[k] > 127) {
                    alfabet[k] = '.';
                }
                printf("%c", alfabet[k]);
            }
        }
    }
    printf("\n");
}

/**
 * Zdroje : ASADO,  M.: he  Sniffer’s  Guide  to  Raw  Traffic. https://eecs.wsu.edu/~sshaikot/docs/lbpcap/libpcap-tutorial.pdf
 *          http://www.qnx.com/developers/docs/6.5.0/index.jsp?topic=%2Fcom.qnx.doc.neutrino_lib_ref%2Fi%2Finet_ntop.html
 *          Author: Tim Carstens
 *          https://www.tcpdump.org/pcap.html?fbclid=IwAR1dvDpDM_vfgOBZxDy2YeT2J3t1TJLyZAB__VY44eezI7eBqzm3s1zM4Rw
 * @param args
 * @param pkthdr - informácie o pakete - čas, veľkosť
 * @param packet - data
 */
void my_callback(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {

    (void)args; // unused

    struct iphdr *ip_hdr = (struct iphdr*) (packet + sizeof(struct ethhdr)); // IP hlavička
    struct ether_header *eth_hdr = (struct ether_header*) packet; // ethernetova hlavička
    auto iphdrlen = ip_hdr->ihl * 4; // veľkosť v bytoch IP hlavičky

    struct tcphdr *tcp_hdr = (struct tcphdr *) (packet + sizeof(struct ethhdr) + iphdrlen); // TCP hlavička
    struct udphdr *udp_hdr = (struct udphdr *) (packet + sizeof(struct ethhdr) + iphdrlen); // UDP hlavička

    struct sockaddr_in source; // IP format pre vypis
    struct sockaddr_in dest;
    auto size_packet = pkthdr->caplen; // velkost paketu v bytoch

    // Spracovanie ARP paketu
    if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
        if (arp) {
            print_time(pkthdr);
            // format adresy pre ARP
            struct ether_addr *source = (struct ether_addr *) eth_hdr->ether_shost;
            struct ether_addr *dest = (struct ether_addr *) eth_hdr->ether_dhost;
            std::cout << " " << ether_ntoa(source) << " > " << ether_ntoa(dest)
                      << " lenght " << pkthdr->caplen << " bytes" << "\n";
            print_packet(size_packet, packet);
        }
    }

    if (ip_hdr->version == 4) {
        if (ip_hdr->protocol != IPPROTO_ICMP and ip_hdr->protocol != IPPROTO_TCP and ip_hdr->protocol != IPPROTO_UDP) {
            return;
        }
        // vyčistenie a uloženie si adries
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ip_hdr->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = ip_hdr->daddr;
        // vypis paketov sa skladá z formátovanej adresy a portu z IP hlavičky
        switch (ip_hdr->protocol) {
            case IPPROTO_ICMP:
                if (icmp) {
                    print_time(pkthdr);
                    std::cout << " " << inet_ntoa(source.sin_addr) << " > " << inet_ntoa(dest.sin_addr)
                              << " lenght " << pkthdr->caplen << " bytes"
                              << "\n";
                    print_packet(size_packet, packet);
                }
                break;
            case IPPROTO_TCP:
                if(tcp) {
                    print_time(pkthdr);
                    std::cout << " " << inet_ntoa(source.sin_addr) << " : " << ntohs(tcp_hdr->source) << " > "
                              << inet_ntoa(dest.sin_addr) << " : " << ntohs(tcp_hdr->dest) << " lenght "
                              << pkthdr->caplen
                              << " bytes" << "\n";
                    print_packet(size_packet, packet);
                }
                break;
            case IPPROTO_UDP:
                if (udp) {
                    print_time(pkthdr);
                    std::cout << " " << inet_ntoa(source.sin_addr) << " : " << ntohs(udp_hdr->source) << " > "
                              << inet_ntoa(dest.sin_addr) << " : " << ntohs(udp_hdr->dest) << " lenght "
                              << pkthdr->caplen
                              << " bytes" << "\n";
                    print_packet(size_packet, packet);
                }
                break;
            default:
                break;
        }
    }
    if (ip_hdr->version == 6) {
        int ipv6_hdr_size = 40; // IPv6 hlavička má presne 40 bytov
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(packet + sizeof(ethhdr)); //ipv6 hlavi4ka
        struct tcphdr *tcp_hdr6 = (struct tcphdr *) (packet + sizeof(struct ethhdr) + ipv6_hdr_size); //ipv6 tcp hlavička
        struct udphdr *udp_hdr6 = (struct udphdr *) (packet + sizeof(struct ethhdr) + ipv6_hdr_size); //ipv6 udp hlavička

        struct sockaddr_in6 source6; // formát adresy ipv6
        struct sockaddr_in6 dest6;

        // vyčistenie pamäte a uloženie si formatu adresy
        memset(&source6, 0, sizeof(source));
        source6.sin6_addr = ip6_hdr->ip6_src;
        memset(&dest6, 0, sizeof(dest));
        dest6.sin6_addr = ip6_hdr->ip6_dst;
        // sformátovanie adresy pre vypis
        char ipv6_buf_src[INET6_ADDRSTRLEN];
        char ipv6_buf_dest[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, &source6.sin6_addr, ipv6_buf_src, sizeof(ipv6_buf_src));
        inet_ntop(AF_INET6, &dest6.sin6_addr, ipv6_buf_dest, sizeof(ipv6_buf_dest));

        switch (ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
            case IPPROTO_ICMPV6:
                if (icmp) {
                    print_time(pkthdr);
                    std::cout << " " << ipv6_buf_src<< " > " << ipv6_buf_dest
                              << " lenght " << pkthdr->caplen << " bytes"
                              << "\n";
                    print_packet(size_packet, packet);
                }
                break;
            case IPPROTO_TCP:
                if (tcp) {
                    print_time(pkthdr);
                    std::cout << " " << ipv6_buf_src << " : " << ntohs(tcp_hdr6->source) << " > "
                              << ipv6_buf_dest << " : " << ntohs(tcp_hdr6->dest) << " lenght " << pkthdr->caplen
                              << " bytes" << "\n";
                    print_packet(size_packet, packet);
                }
                break;
            case IPPROTO_UDP:
                if (udp) {
                    print_time(pkthdr);
                    std::cout << " " << ipv6_buf_src << " : " << ntohs(udp_hdr6->source) << " > "
                              << ipv6_buf_dest << " : " << ntohs(udp_hdr6->dest) << " lenght " << pkthdr->caplen
                              << " bytes" << "\n";
                    print_packet(size_packet, packet);
                }
                break;
            default:
                break;
        }
    }
}

int main(int argc, char **argv) {
    bool filter = false; // aplikácia filtra
    bool onlyshow = false; // v prípade že chcem ukázať iba vypis rozhraní

    std::string interface;
    std::string temp;
    std::string port = "port ";
    int packet_count = 1;

    /**
     * Zdroj: https://www.gnu.org/software/libc/manual/html_node/Getopt-Long-Option-Example.html
     */
    const option long_options[] = {
            {"interface", required_argument, nullptr, 'i'},
            {"tcp",       no_argument,       nullptr, 't'},
            {"udp",       no_argument,       nullptr, 'u'},
            {"arp",       no_argument,       nullptr, 'a'},
            {"icmp",      no_argument,       nullptr, 'm'},
            {nullptr,     no_argument,       nullptr, 0}
    };

    int c;
    while (true) {

        if (argc == 1) {
            onlyshow = true;
            break;
        }

        if ((strcmp(argv[1], "-i") == 0 or strcmp(argv[1], "--interface") == 0) and argc == 2) {
            onlyshow = true;
            break;
        }

        c = getopt_long(argc, argv, "i:p:tun:", long_options, nullptr);

        if (c == -1) {
            break;
        }

        switch (c) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                temp = optarg;
                port = port.append(temp);
                filter = true;
                break;
            case 't':
                tcp = true;
                break;
            case 'u':
                udp = true;
                break;
            case 'n':
                packet_count = int(strtol(optarg, nullptr, 10));
                break;
            case 'a':
                arp = true;
                break;
            case 'm':
                icmp = true;
                break;
            default:
                fprintf(stderr, "Chybné argumenty !\n");
                exit(1);
        }
    }
    // ak neboli zadané obmedzujuce parametre vypisuje sa všetko
    if (!tcp and !udp and !arp and !icmp) {
        tcp = true;
        udp = true;
        arp = true;
        icmp = true;
    }

    /**
     * Zdroje:Authors: The WinPcap Team
     *        https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut1.html
     *        https://www.winpcap.org/docs/docs_412/html/group__wpcap__tut3.html
     *        Authors: Van JACOBSON, S. M., Craig LERES:Manual page of PCAP:
     *        http://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html
     *        Author: Tim Carstens
     *        https://www.tcpdump.org/pcap.html?fbclid=IwAR1dvDpDM_vfgOBZxDy2YeT2J3t1TJLyZAB__VY44eezI7eBqzm3s1zM4Rw
     */
    pcap_if_t *alldevs; // premenná pre načítanie všetkých rozhraní
    pcap_if_t *d; // iteračná premenná
    pcap_if_t *selecterInterface; // nájduté rozhranie
    pcap_t *handle;  // spracovanie prepoja
    struct bpf_program fp; // skompilovany filter
    bpf_u_int32 net; // ip zariadenia
    bpf_u_int32 mask; // maska zariadenia
    int i = 0; // kontrola či sme našli aspoň nejaké rozhranie
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Hladanie rozhraní zlyhalo : %s\n", errbuf);
        exit(1);
    }

    if (onlyshow) {
        for (d = alldevs; d != nullptr; d = d->next) {
            printf("%s\n", d->name);
        }
        pcap_freealldevs(alldevs);
        return 0;
    }

    for (d = alldevs; d != nullptr; d = d->next) {
        ++i;
        if (d->name == interface) {
            selecterInterface = d;
        }
    }

    if (i == 0 or selecterInterface == nullptr) {
        pcap_freealldevs(alldevs);
        fprintf(stderr, "Hladanie rozhraní zlyhalo !\n");
        exit(1);
    }

    if (pcap_lookupnet(selecterInterface->name, &net, &mask, errbuf) == PCAP_ERROR) {
        net = 0;
        mask = 0;
    }

    /**
     * pcap_open_line Otvorí našu session pre sniffovanie paketov, prvý parameter je názov nášho zariadenia na
     * ktorom prebieha sniffovanie. Následuje BUFSIZ, ktorý určuje maximálny možný počet bytov, ktoré zachytí pcap.
     * Spustený je v promiscuous mode, vďaka ktorému zachytí všetky pakety, ktoré by za normálnych okolnosti nezachytil.
     */
    handle = pcap_open_live(selecterInterface->name, BUFSIZ, 1, 1000, errbuf);
    pcap_freealldevs(alldevs); // dalej uz tento zoznam nepotrebujeme a mozme ho uvolnit
    if (handle == nullptr) {
        fprintf(stderr, "Získavanie paketov zlyhalo %s!\n", errbuf);
        exit(1);
    }

    if (filter) {
        if (pcap_compile(handle, &fp, port.c_str(), 0, net) == PCAP_ERROR) {
            fprintf(stderr, "Nepodarilo sa spracovať filter !\n");
            exit(1);
        }

        if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
            fprintf(stderr, "Nepodarilo sa aplikovať filter !\n");
            exit(1);
        }
    }

    if (pcap_loop(handle, packet_count, my_callback, nullptr) == PCAP_ERROR) {
        fprintf(stderr, "Spracovanie paketov zlyhalo !\n");
        exit(1);
    }

    pcap_close(handle);
    return 0;
}
