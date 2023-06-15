#include <stdio.h>

int add(int a, int b)
{
    return a + b;
}

int substract(int a, int b)
{
    return a - b;
}

int main()
{
    int a = 5;
    int b = 3;
    printf("a + b = %d\n", add(a, b));
    printf("a - b = %d\n", substract(a, b));
    return 0;
}

// gcc -Wall -Wextra -Werror -o main main.c
