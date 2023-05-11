#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct virus {
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
} virus;

typedef struct link {
    struct link *nextVirus;
    virus *vir;
} link;

typedef struct {
    char *name;
    void (*function)();
} menu;

typedef struct VirusLocation{
    unsigned int location;
    struct VirusLocation* next;
}VirusLocation;

// Function signatures
void load_signatures(FILE* inputFile);
void print_signatures(FILE* output);
void detect_virus(char *buffer, unsigned int size, link *virus_list);
void neutralize_virus(char *fileName, int signatureOffset); 
void quit();

link* virus_list = NULL;// Head of the linked list to store virus signatures
VirusLocation* head = NULL; // Head of the linked list to store virus detected positions

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

//receives a file pointer and returns a virus* that represents the next virus in the file.
virus* readVirus(FILE* file) {
    virus* v = (virus*)malloc(sizeof(virus)); // Allocate memory for virus struct
    // Read the virus struct from the file
    if (fread(v, 18, 1, file) != 1) { //if the read operation did not succeeded
        free(v);
        v = NULL;
        return NULL;
    }
    // Allocate memory for sig based on the SigSize and read the signature
    v->sig = (unsigned char*)malloc(v->SigSize * sizeof(unsigned char));
    fread(v->sig, sizeof(unsigned char), v->SigSize, file);
    return v;
}

/* Print the data of every link in list to the given stream. 
    Each item followed by a newline character. */ 
void list_print(link *virus_list, FILE *stream) {
    link *curr = virus_list;
    while (curr != NULL) {
        printVirus(curr->vir, stream);
        curr = curr->nextVirus;
    }
    curr = NULL;
}

/* Add a new link with the given data to the list (at the end CAN ALSO AT BEGINNING),
    and return a pointer to the list (i.e., the first link in the list). If the list is null -
    create a new entry and return a pointer to the entry. */
link* list_append(link *virus_list, virus *data) { 
    link *newLink = (link *)malloc(sizeof(link));
    newLink->vir = data;
    newLink->nextVirus = virus_list;
    virus_list = newLink;
    return virus_list;
}

/* Free the memory allocated by the list. */
//(new)
void list_free(link *virus_list){
    if(virus_list != NULL) {
        free(virus_list->vir->sig); // Free memory allocated for virus signature
        free(virus_list->vir); // Free the memory for virus data
		list_free(virus_list->nextVirus);
	}
	free(virus_list); // Free the memory for all the links
}

/*old:
void list_free(link *virus_list) {
    link *curr = virus_list;
    while (curr != NULL) {
        link *next = curr->nextVirus;
        free(curr->vir->sig); // Free memory allocated for virus signature
        free(curr->vir); // Free the memory for virus data
        free(curr); // Free the memory for link
        curr = next;
    }
}
*/

// Function to free the memory for the VirusLocation linked list recursively
void free_virus_locations(VirusLocation* head) {
    if (head == NULL) {
        return;
    }

    free_virus_locations(head->next); // Recursively free the rest of the list
    free(head); // Free the current VirusLocation node
}

void load_signatures(FILE* inputFile) {
    char fileName[100];
    printf("Enter file name to load virus signatures: ");
    fgets(fileName, sizeof(fileName), stdin);
    if (fileName[strlen(fileName) - 1] == '\n') {
        fileName[strlen(fileName) - 1] = '\0';
    }
    inputFile = fopen(fileName, "rb");
    if (inputFile == NULL) {
        printf("Failed to open file '%s' for reading.\n", fileName);
        return;
    }
    char magic[5];
    fread(magic, 1, 4, inputFile);
    magic[4] = '\0';
    
    if (strcmp(magic, "VISL") != 0) {
        printf("File '%s' does not contain virus signatures.\n", fileName);
        fclose(inputFile);
        return;
    }
    virus* v;
    while ((v = readVirus(inputFile)) != NULL) {
        virus_list = list_append(virus_list, v);
    }
    v = NULL;
    //free(v);
    fclose(inputFile);
}

void print_signatures(FILE* output) {
    if (virus_list == NULL) {
        return;
    }
    fprintf(output, "Virus signatures:\n");
    list_print(virus_list, output);
}

void detect_virus(char *buffer, unsigned int size, link *virus_list){
    printf("Detecting viruses...\n");
    link* current_virus = virus_list;
    while (current_virus != NULL) {
        virus* current_sig = current_virus->vir;
        for (unsigned int i = 0; i < size; i++) {
            if (memcmp(buffer + i, current_sig->sig, current_sig->SigSize) == 0) {
                VirusLocation* new_location = (VirusLocation*)malloc(sizeof(VirusLocation));
                new_location->location = i;
                // Add new_location to the start of the virus_list
                new_location->next = head;
                head = new_location;
                printf("Virus detected at byte %u :\n", i);
                printVirus(current_sig, stdout); // Call printVirus to print virus details
            }
        }
        current_virus = current_virus->nextVirus;
    }
    current_virus = NULL;
}

void neutralize_virus(char *fileName, int signatureOffset){
    // if(head == NULL){
    //     printf("There are no more viruses to fix!\n");
    //     return;
    // }
    FILE *file = fopen(fileName, "r+");
    if (file == NULL) {
        printf("Failed to open file %s\n", fileName);
        return;
    }
    // Set the file position indicator to the signature offset
    fseek(file, signatureOffset, SEEK_SET);
    unsigned char RET = 0xC3;
    fwrite(&RET, sizeof(unsigned char), 1, file);
    //need to delete the first virus we just fixed
    VirusLocation* temp = head; // Save the current head node in a temporary variable
    head = temp->next; // Update the head to point to the next node
    temp->next = NULL;
    free(temp);
    fclose(file);
}

void quit() {
    printf("Exiting...\n");
    list_free(virus_list);
    virus_list = NULL;
    free_virus_locations(head);
    head = NULL;
    exit(0);
}

menu menuOptions[] = {
    {"Load signatures", load_signatures}, 
    {"Print signatures", print_signatures},
    {"Detect virus",detect_virus},
    {"Fix file", neutralize_virus},
    {"Quit", quit}};

int main(int argc, char **argv){
    int choice;
    FILE* inputFile; 
    inputFile = NULL;
    FILE* file;
    char *input = (char *) malloc(sizeof(char) * 100);
    // Allocate buffer of size 10K
    const int bufferSize = 10000; // Constant buffer size of 10K bytes
    char buffer[bufferSize];
    memset(buffer, 0, bufferSize);
    while (1) {
        // Print the menu options
        printf("Select an option from the menu:\n");
        for (int i = 0; i < 5; i++) {
            printf("%d) %s\n", i + 1, menuOptions[i].name);
        }

        // Get user input for menu selection
        fgets(input, sizeof(input), stdin);
        sscanf(input, "%d", &choice);

        // Check if the input is between 1 and 5
        if (sscanf(input, "%d", &choice) != 1 || choice < 1 || choice > 5) {
            printf("Invalid choice. Please try again.\n");
            continue;
        }
        switch(choice){
            case 1:
                menuOptions[choice-1].function(inputFile);
                break;
            case 2:
                menuOptions[choice-1].function(stdout);
                break;
            case 3:
                file = fopen(argv[1], "rb"); 
                if (file == NULL) {
                    printf("Failed to open file.\n");
                    free(input); // Free allocated memory for input
                    input = NULL;
                    return 1;
                }
                // Read file into buffer
                unsigned int bytesRead = fread(buffer, sizeof(char), bufferSize, file);
                if (bytesRead == 0) {
                    printf("Failed to read file.\n");
                    fclose(file);
                    free(input); // Free allocated memory for input
                    input = NULL;
                    return 1;
                }
                fclose(file);
                menuOptions[choice-1].function(buffer, bytesRead, virus_list);
                break;
            case 4:
                if(head == NULL){
                    printf("There are no more viruses to fix!\n");
                    break;
                }
                menuOptions[choice-1].function(argv[1], head->location);
                break;
            case 5:
                free(input); // Free allocated memory for input
                input = NULL;
                menuOptions[choice-1].function();  
                break;
        }
    }       
    return 0;
}


