// capture/capture.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <pcap.h>
#include <winsock2.h>
#include <windows.h>
#include "capture/capture.h"
#include "select_adapter/select_adapter.h"
#include "menu/menu.h"

static volatile int capture_running = 1;
static unsigned long long total_packets = 0;
static unsigned long long mtproto_packets = 0;
static FILE* log_file = NULL;
static pcap_t* g_handle = NULL;

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        printf("\n[!] Остановка захвата...\n");
        if (g_handle != NULL) {
            pcap_breakloop(g_handle);
        }
        return TRUE;
    }
    return FALSE;
}

static void write_log(const char* entry) {
    if (log_file) {
        fprintf(log_file, "%s\n", entry);
        fflush(log_file);
    }
}

static void get_time_str(char* buffer, size_t size, const struct timeval* tv) {
    time_t rawtime = tv->tv_sec;
    struct tm* timeinfo = localtime(&rawtime);
    strftime(buffer, size, "%H:%M:%S", timeinfo);
}

static void bytes_to_hex(const uint8_t* data, int len, char* out, int out_size) {
    out[0] = '\0';
    for (int i = 0; i < len && i < out_size/3; i++) {
        char part[4];
        sprintf(part, "%02X ", data[i]);
        strcat(out, part);
    }
    int last = strlen(out);
    if (last > 0 && out[last-1] == ' ') out[last-1] = '\0';
}

static void packet_handler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    total_packets++;

    // 1. Ethernet заголовок (14 байт)
    // Пропускаем если тип не IPv4 (0x0800)
    const uint16_t* ethertype = (const uint16_t*)(packet + 12);
    if (ntohs(*ethertype) != 0x0800) return;

    // 2. IPv4 заголовок (минимальная длина 20 байт)
    const uint8_t* ip_header = packet + 14;
    uint8_t ip_version = (ip_header[0] >> 4) & 0x0F;
    if (ip_version != 4) return;
    uint8_t ip_header_len = (ip_header[0] & 0x0F) * 4; // в байтах
    if (ip_header_len < 20) return;

    uint8_t ip_protocol = ip_header[9];
    if (ip_protocol != 6) return; // только TCP

    // IP адреса
    struct in_addr src_ip, dst_ip;
    memcpy(&src_ip, ip_header + 12, 4);
    memcpy(&dst_ip, ip_header + 16, 4);
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_ip, dst_ip_str, INET_ADDRSTRLEN);

    // 3. TCP заголовок
    const uint8_t* tcp_header = ip_header + ip_header_len;
    uint16_t src_port = ntohs(*(const uint16_t*)(tcp_header));
    uint16_t dst_port = ntohs(*(const uint16_t*)(tcp_header + 2));
    uint8_t tcp_header_len = ((tcp_header[12] >> 4) & 0x0F) * 4;
    if (tcp_header_len < 20) return;

    // Payload TCP
    const uint8_t* payload = tcp_header + tcp_header_len;
    int payload_len = header->caplen - (14 + ip_header_len + tcp_header_len);
    if (payload_len <= 0) return;

    int detected = 0;
    const char* signature_name = "";
    uint32_t magic = 0;
    if (payload_len >= 1 && payload[0] == 0xEF) {
        detected = 1;
        signature_name = "Abridged transport init (0xEF)";
        magic = 0xEF;
    }
    else if (payload_len >= 4) {
        uint32_t val = *(const uint32_t*)payload;
        if (val == 0xEEEEEEEE) {
            detected = 1;
            signature_name = "Intermediate transport init (0xEEEEEEEE)";
            magic = val;
        }
        else if (val == 0xDDDDDDDD) {
            detected = 1;
            signature_name = "Padded Intermediate transport init (0xDDDDDDDD)";
            magic = val;
        }
    }

    if (!detected) return;

    mtproto_packets++;

    char time_str[32];
    get_time_str(time_str, sizeof(time_str), &header->ts);

    int dump_len = (payload_len < 8) ? payload_len : 8;
    char hex_dump[64] = "";
    bytes_to_hex(payload, dump_len, hex_dump, sizeof(hex_dump));

    char log_entry[512];
    snprintf(log_entry, sizeof(log_entry),
             "[!] MTProto DETECTED: %s Src: %s:%u Dst: %s:%u Signature: %s Payload[0..%d]: %s",
             time_str, src_ip_str, src_port, dst_ip_str, dst_port, signature_name, dump_len-1, hex_dump);

    printf("%s\n", log_entry);
    write_log(log_entry);
}

void start_capture(const char* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = NULL;
    struct bpf_program fp;
    char filter_exp[256];
    char my_ip[INET_ADDRSTRLEN] = {0};
    bpf_u_int32 netmask = 0;

    if (device == NULL) {
        printf("Адаптер не выбран. Запустите выбор адаптера (пункт 2 меню) или выберите сейчас.\n");
        select_adapter();
        device = get_selected_device();
        if (device == NULL) {
            printf("Не удалось выбрать адаптер. Отмена захвата.\n");
            return;
        }
    }

    handle = pcap_open_live(device, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Ошибка открытия адаптера %s: %s\n", device, errbuf);
        return;
    }

    pcap_if_t* alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) != -1) {
        for (pcap_if_t* d = alldevs; d != NULL; d = d->next) {
            if (strcmp(d->name, device) == 0) {
                for (pcap_addr_t* a = d->addresses; a != NULL; a = a->next) {
                    if (a->addr && a->addr->sa_family == AF_INET) {
                        struct sockaddr_in* sa = (struct sockaddr_in*)a->addr;
                        inet_ntop(AF_INET, &(sa->sin_addr), my_ip, INET_ADDRSTRLEN);
                        if (a->netmask) {
                            netmask = ((struct sockaddr_in*)a->netmask)->sin_addr.s_addr;
                        }
                        break;
                    }
                }
                break;
            }
        }
        pcap_freealldevs(alldevs);
    }

    if (my_ip[0] == '\0') {
        fprintf(stderr, "Не удалось определить IP для адаптера %s\n", device);
        pcap_close(handle);
        return;
    }

    printf("Ваш IP: %s\n", my_ip);
    snprintf(filter_exp, sizeof(filter_exp), "tcp and src host %s", my_ip);
    printf("BPF-фильтр: %s\n", filter_exp);

    if (pcap_compile(handle, &fp, filter_exp, 1, netmask) == -1) {
        fprintf(stderr, "Ошибка компиляции фильтра: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Ошибка установки фильтра: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        pcap_close(handle);
        return;
    }
    pcap_freecode(&fp);

    log_file = fopen("mtproto_detections.log", "a");
    if (log_file == NULL) {
        fprintf(stderr, "Предупреждение: не удалось открыть лог-файл. Логирование отключено.\n");
    } else {
        time_t now = time(NULL);
        fprintf(log_file, "\n--- Начало захвата: %.24s ---\n", ctime(&now));
    }

    total_packets = 0;
    mtproto_packets = 0;

    g_handle = handle;
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    printf("Захват на адаптере: %s\n", device);
    printf("BPF-фильтр: %s\n", filter_exp);
    printf("Лог-файл: mtproto_detections.log\n");
    printf("\nЗАХВАТ ЗАПУЩЕН\n");
    printf("Для остановки нажмите Ctrl+C\n");

    if (pcap_loop(handle, 0, packet_handler, NULL) == -1) {
        if (pcap_geterr(handle) && strstr(pcap_geterr(handle), "interrupted") == NULL) {
            fprintf(stderr, "Ошибка в pcap_loop: %s\n", pcap_geterr(handle));
        }
    }

    SetConsoleCtrlHandler(CtrlHandler, FALSE);
    g_handle = NULL;

    pcap_close(handle);
    
    if (log_file) {
        fprintf(log_file, "--- Завершение захвата. Всего пакетов: %llu, MTProto: %llu ---\n", total_packets, mtproto_packets);
        fclose(log_file);
        log_file = NULL;
    }

    printf("\nСТАТИСТИКА\n");
    printf("Всего обработано пакетов: %llu\n", total_packets);
    printf("Пакетов с сигнатурой MTProto: %llu\n", mtproto_packets);

    printf("Лог сохранён в mtproto_detections.log\n");
    printf("\nНажмите Enter для возврата в меню...");
    fflush(stdin);
    getchar();
}