#include <stdio.h>
#include "menu.h"

void clear_input_buffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

int get_valid_choice() {
    int choice;
    int result;
    
    while (1) {
        result = scanf("%d", &choice);
        
        if (result == 1) {
            clear_input_buffer();
            return choice;
        } else {
            printf("Ошибка: необходимо ввести число!\n");
            printf("Попробуйте снова: ");
            clear_input_buffer();
        }
    }
}

void show_menu() {
    printf("\n");
    printf("1. Список адаптеров\n");
    printf("0. Выход\n");
    printf("\nВыбор: ");
}