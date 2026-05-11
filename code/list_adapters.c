#include <stdio.h>
#include <pcap.h>
#include <windows.h>
#include "list_adapters.h"

int list_network_adapters() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Ошибка: %s\n", errbuf);
        return -1;
    }
    
    int device_number = 1;
    printf("\n==========================================\n");
    printf("Список сетевых адаптеров\n");
    printf("==========================================\n\n");
    
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%d. %s\n", device_number++, device->name);
        
        if (device->description) {
            printf("   %s\n", device->description);
        }
        
        pcap_addr_t *address;
        for (address = device->addresses; address != NULL; address = address->next) {
            if (address->addr) {
                char ip[INET6_ADDRSTRLEN];
                int family = address->addr->sa_family;
                
                if (family == AF_INET) {
                    struct sockaddr_in *ipv4 = (struct sockaddr_in*)address->addr;
                    inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
                    printf("   IP: %s\n", ip);
                }
                else if (family == AF_INET6) {
                    struct sockaddr_in6 *ipv6 = (struct sockaddr_in6*)address->addr;
                    inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip, INET6_ADDRSTRLEN);
                    printf("   IPv6: %s\n", ip);
                }
            }
        }
        printf("\n");
    }
    
    if (device_number == 1) {
        printf("Адаптеры не найдены. Проверьте Npcap.\n");
    }
    
    pcap_freealldevs(alldevs);
    
    printf("==========================================\n");
    printf("Всего: %d\n", device_number - 1);
    
    return 0;
}