// main.c
#include <stdlib.h>
#include <windows.h>
#include "list_adapters.h"
#include "menu.h"
#include "select_adapter.h"
#include "capture.h"

int main() {
    SetConsoleOutputCP(CP_UTF8);   
    int choice;
    
    while (1) {
        show_menu();
        choice = get_valid_choice();
        
        switch (choice) {
            case 1:
                system("cls");
                list_network_adapters();
                break;
            case 2:
                system("cls");
                select_adapter();
                break;
            case 3:
                system("cls");
                printf("Здесь будет функция захвата пакетов\n");
                // start_capture(get_selected_device());
                break;
            case 0:
                system("cls");
                printf("\nВыход.\n");
                return 0;
            default:
                printf("\nНеверный выбор. Используйте 0-3.\n");
                break;
        }
        
        if (choice != 0) {
            printf("\n");
            system("pause");
            system("cls");
        }
    }
    
    return 0;
}