#include<windows.h>
#include<shlwapi.h>
#include<fstream>

typedef struct {
    WORD Reserved1;
    WORD ResourceType;
    WORD ImageCount;
    BYTE Width;
    BYTE Height;
    BYTE Colors;
    BYTE Reserved2;
    WORD Planes;
    WORD BitsPerPixel;
    DWORD ImageSize;
    WORD ResourceID;
} GROUPICON;

char* LoadIco(wchar_t* name, DWORD* ImageOffset, GROUPICON* grData, WORD ResourceID)
{
    std::ifstream ico(name, std::ios::in | std::ios::binary);
    if (!ico)
    {
        wprintf(L"Cannot open ico\n");
        system("pause");
        return 0;
    }

    char* buffer;
    DWORD buffersize;

    ico.seekg(0, std::ios::end);
    buffersize = ico.tellg();
    //std::cout << "Size of ico file: " << buffersize << std::endl;
    ico.seekg(0, std::ios::beg);
    buffer = new char[buffersize];
    ico.read(buffer, buffersize);
    ico.close();

    WORD icoNum = *(buffer + 4);
    BYTE largest = 0;
    size_t larId = 0;
    for (size_t i = 0; i < 6; i++)
    {
        if (largest < (BYTE) * (buffer + 6 + 16 * i))
        {
            largest = *(buffer + 6 + 16 * i);
            larId = i;
        }
    }

    grData->Reserved1 = 0;
    grData->ResourceType = 1;
    grData->ImageCount = 1;
    memcpy(&grData->Width, (buffer + 6 + 16 * larId), 8);
    memcpy(&grData->ImageSize, (buffer + 14 + 16 * larId), 4);
    grData->ResourceID = ResourceID;
    memcpy(ImageOffset, (buffer + 18 + 16 * larId), 4);

    return buffer;
}

double FindEntropy(wchar_t* name)
{
    std::ifstream input(name, std::ios::in | std::ios::binary);

    double e = 0;

    if (input)
    {
        int size = 0;
        input.seekg(0, std::ios::end);
        size = input.tellg();
        input.seekg(0, std::ios::beg);

        size_t count[256] = { 0 };
        char c;
        while (input.get(c)) {
            count[c + 128]++;
        }
        size = 0;
        int clog = 256;
        for (size_t i = 0; i < 256; i++)
        {
            if (count[i] == 0)
            {
                clog--;
            }
            size += count[i];
        }
        input.close();

        for (size_t i = 0; i < 256; i++)
        {
            double p = count[i] / (double)size;
            if (p != 0)
            {
                e -= p * std::log(p) / std::log(clog);
            }

        }
    }
    else
    {
        e = -1;
    }
    return e;
}

int wmain(int argc, wchar_t* argv[])
{
    if (argc < 3)
    {
        wprintf(L"Usage : exe_info.exe TargetExe TargetIco\n");
        system("pause");
        return 0;
    }
    if (wcscmp(PathFindExtensionW(argv[1]), L".exe") || wcscmp(PathFindExtensionW(argv[2]), L".ico"))
    {
        wprintf(L"Wrong file type\n");
        system("pause");
        return 0;
    }
    wprintf(L"Input files:\n\t%s\n\t%s\n", argv[1], argv[2]);
    HANDLE hFile, hFileMap;
    DWORD dwImportDirectoryVA, dwSectionCount, dwSection = 0, dwRawOffset;
    LPVOID lpFile;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER pSectionHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_THUNK_DATA pThunkData;
    hFile = CreateFile(argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"Cannot open exe\n");
        system("pause");
        return 0;
    }
    hFileMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, 0, 0);
    lpFile = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
    pDosHeader = (PIMAGE_DOS_HEADER)lpFile;
    pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD)lpFile + pDosHeader->e_lfanew);
    dwSectionCount = pNtHeaders->FileHeader.NumberOfSections;
    dwImportDirectoryVA = pNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;
    pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for (; dwSection < dwSectionCount && pSectionHeader->VirtualAddress <= dwImportDirectoryVA; pSectionHeader++, dwSection++);
    pSectionHeader--;
    dwRawOffset = (DWORD)lpFile + pSectionHeader->PointerToRawData;
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(dwRawOffset + (dwImportDirectoryVA - pSectionHeader->VirtualAddress));
    int numFunc = 0;
    for (; pImportDescriptor->Name != 0; pImportDescriptor++)
    {
        printf("\nLibrary name: %s\n\n", dwRawOffset + (pImportDescriptor->Name - pSectionHeader->VirtualAddress));
        pThunkData = (PIMAGE_THUNK_DATA)(dwRawOffset + (pImportDescriptor->FirstThunk - pSectionHeader->VirtualAddress));
        for (; pThunkData->u1.AddressOfData != 0; pThunkData++)
        {
            if (pThunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                continue;
            char* c = (char*)(dwRawOffset + (pThunkData->u1.AddressOfData - pSectionHeader->VirtualAddress + 2));
            if (strchr((char*)(dwRawOffset + (pThunkData->u1.AddressOfData - pSectionHeader->VirtualAddress + 2)), 'W') != nullptr)
            {
                numFunc++;
            }
            printf("\tFunction: %s\n", (dwRawOffset + (pThunkData->u1.AddressOfData - pSectionHeader->VirtualAddress + 2)));

        }
    }
    UnmapViewOfFile(lpFile);
    CloseHandle(hFileMap);
    CloseHandle(hFile);

    wprintf(L"\nNumber of WinAPI names that contain the letter 'W': %d\n", numFunc);

    HANDLE hEXE = BeginUpdateResource(argv[1], TRUE);
    if (hEXE == NULL)
    {
        wprintf(L"Cannot change ico\n");
        system("pause");
        return 0;
    }

    GROUPICON* grData = new GROUPICON;
    DWORD* ImageOffset = new DWORD;
    char* buffer = LoadIco(argv[2], ImageOffset, grData, 1);
    bool result;

    result = UpdateResourceW(hEXE,
        RT_ICON,
        MAKEINTRESOURCE(1),
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (buffer + *ImageOffset),
        grData->ImageSize);
    if (!result)
    {
        wprintf(L"Cannot change ico\n");
        system("pause");
        return 0;
    }

    result = UpdateResourceW(hEXE,
        RT_GROUP_ICON,
        L"MAINICON",
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        grData,
        sizeof(GROUPICON)
    );
    if (!result)
    {
        wprintf(L"Cannot change ico\n");
        system("pause");
        return 0;
    }

    delete grData;
    delete ImageOffset;
    delete buffer;

    if (!EndUpdateResource(hEXE, FALSE))
    {
        wprintf(L"Cannot change ico\n");
        system("pause");
        return 0;
    }

    for (size_t i = 1; i < argc; i++)
    {
        wprintf(L"File: %s\n", argv[i]);
        double e = FindEntropy(argv[i]);
        if (e == -1)
        {
            wprintf(L"Cannot open %s\n", argv[i]);
        }
        else
        {
            wprintf(L"Entropy: %lf\n", e);
        }
    }

    system("pause");
    return 0;
}