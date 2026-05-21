// select_adapter/select_adapter.c
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include "select_adapter/select_adapter.h"
#include "menu/menu.h"

static char selected_device[256] = "";

int select_adapter() {
    pcap_if_t *alldevs;
    pcap_if_t *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int choice, i = 1;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("Ошибка: %s\n", errbuf);
        return -1;
    }
    
    printf("\n==========================================\n");
    printf("Выберите адаптер\n");
    printf("==========================================\n\n");
    
    for (device = alldevs; device != NULL; device = device->next) {
        printf("%d. ", i++);
        if (device->description) {
            printf("%s\n", device->description);
        } else {
            printf("%s\n", device->name);
        }
    }

    printf("\n0. Вернуться в меню\n");

    printf("\nВаш выбор: ");
    choice = get_valid_choice();
    
    if (choice == 0) {
        pcap_freealldevs(alldevs);
        return 0;
    }

    if (choice < 1 || choice > i-1) {
        printf("Неверный выбор.\n");
        pcap_freealldevs(alldevs);
        return -1;
    }
    
    i = 1;
    for (device = alldevs; device != NULL; device = device->next) {
        if (i == choice) {
            strcpy(selected_device, device->name);
            printf("\nВыбран адаптер: %s\n", 
                   device->description ? device->description : device->name);
            break;
        }
        i++;
    }
    
    pcap_freealldevs(alldevs);
    return 0;
}

const char* get_selected_device(void) {
    if (selected_device[0] == '\0') {
        return NULL;
    }
    return selected_device;
}