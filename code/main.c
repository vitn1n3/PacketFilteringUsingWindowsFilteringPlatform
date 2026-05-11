#include <stdlib.h>
#include <windows.h>
#include "list_adapters.h"
#include "menu.h"

int main() {
    SetConsoleOutputCP(CP_UTF8);
    
    int choice;
    
    printf("Сетевой анализатор\n");
    
    while (1) {
        show_menu();
        choice = get_valid_choice();
        
        switch (choice) {
            case 1:
                system("cls");
                list_network_adapters();
                break;
            case 0:
                printf("\nВыход.\n");
                system("pause");
                return 0;
            default:
                printf("\nНеверный выбор. Используйте 0 или 1.\n");
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