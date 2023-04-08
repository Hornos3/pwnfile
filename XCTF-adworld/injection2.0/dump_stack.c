#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]){
    if(argc != 5){
        puts("Usage: dump_stack [input_file] [start_addr] [end_addr] [output_file]");
        exit(0);
    }
	puts("Starting to dump memory...");
    char* input_file = argv[1];
	long start_addr = strtol(argv[2], NULL, 16);
    long end_addr = strtol(argv[3], NULL, 16);
    printf("Start_addr: %ld, End_addr: %ld\n", start_addr, end_addr);
    long ptr = start_addr;
    char* output_file = argv[4];

    char buffer[0x1000];
    FILE* input = fopen(input_file, "rb");
    FILE* output = fopen(output_file, "wb");

    if(!(input_file && output_file)){
        puts("Open file failed!");
        exit(-1);
    }

    fseek(input, start_addr, SEEK_SET);
    while(ptr < end_addr){
        long read_len = end_addr - ptr;
        if(read_len > 0x1000)
            read_len = 0x1000;
        fread(buffer, read_len, 1, input);
        ptr += read_len;
        fwrite(buffer, read_len, 1, output);
        printf("%ld bytes read.\n", read_len);
    }

    fclose(input);
    fclose(output);
    puts("Finished.");
    return 0;
}
