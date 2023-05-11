#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

//receives a file pointer and returns a virus* that represents the next virus in the file.
virus* readVirus(FILE* file) {
    virus* v = (virus*)malloc(sizeof(virus)); // Allocate memory for virus struct

    // Read the virus struct from the file
    if (fread(v, 18, 1, file) != 1) { //if the read operation did not succeed
        free(v);
        return NULL;
    }

    // Allocate memory for sig based on the SigSize and read the signature
    v->sig = (unsigned char*)malloc(v->SigSize * sizeof(unsigned char));
    fread(v->sig, sizeof(unsigned char), v->SigSize, file);

    return v;
}

/* receives a virus and a pointer to an output file. The function prints the virus to the given output.
It prints the virus name (in ASCII), the virus signature length (in decimal),
and the virus signature (in hexadecimal representation). */
void printVirus(virus* v, FILE* output) {
    fprintf(output, "Virus Name: %s\n", v->virusName);
    fprintf(output, "Virus Signature Size: %d bytes\n", v->SigSize);
    fprintf(output, "Virus Signature: ");
    for (int i = 0; i < v->SigSize; i++) {
        fprintf(output, "%02X ", v->sig[i]);
    }
    fprintf(output, "\n");
}

int main(int argc, char** argv){
    const char* pathname1 = "./signatures-L";
    const char* pathname2 = "./signatures-B";
    FILE* input = fopen(pathname1, "rb");
    FILE* output = fopen("output.txt", "w"); // Open output file in write mode
    if (input == NULL) {
        printf("Error opening signatures-L file.\n");
        return 1;
    }

    // Check magic number
    char magic[5];
    fread(magic, sizeof(char), 4, input);
    magic[4] = '\0';
    if (strcmp(magic, "VISL") != 0) {
        printf("Incorrect magic number. Expected: VISL, Found: %s\n", magic);
        fclose(input);
        return 1;
    }

    // Read and print viruses
    virus* v;
    while ((v = readVirus(input)) != NULL) {
        printVirus(v, output); // Print to standard output
        free(v->sig); // Free allocated memory for virus signature
        free(v); // Free allocated memory for virus struct
    }

    fclose(input);
    return 0;
}