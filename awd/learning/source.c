//
// Created by root on 23-4-13.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char name[80];

void backdoor(){
    puts("You got it!");
    system("/bin/sh");
}

int main(){
    puts("Welcome to AWD Pwn CTF!");
    puts("Input your name:");
    scanf("%s", name);    // buffer overflow
    printf("Your name is:");
    printf(name);           // format string
    return 0;
}