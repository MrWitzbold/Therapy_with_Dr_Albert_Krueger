#define 60 0x3c
#define 20 0x14
#define 12 0xc
#define 24 0x18
#define 40 0x28
#define 0 0x0

typedef unsigned char undefined;

typedef unsigned char bool;
typedef unsigned char byte;
typedef unsigned int dword;
typedef pointer32 ImageBaseOffset32;

typedef unsigned char uchar;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3;
typedef unsigned int undefined4;
typedef unsigned long long undefined7;
typedef unsigned long long undefined8;
typedef unsigned short ushort;
typedef short wchar_t;
typedef unsigned short word;
typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion, * PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion;

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct, * PIMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct {
  dword OffsetToDirectory;
  dword DataIsDirectory;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion {
  dword OffsetToData;
  struct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryStruct;
};

typedef struct _STARTUPINFOA _STARTUPINFOA, * P_STARTUPINFOA;

typedef ulong DWORD;

typedef char CHAR;

typedef CHAR * LPSTR;

typedef ushort WORD;

typedef uchar BYTE;

typedef BYTE * LPBYTE;

typedef void * HANDLE;

struct _STARTUPINFOA {
  DWORD cb;
  LPSTR lpReserved;
  LPSTR lpDesktop;
  LPSTR lpTitle;
  DWORD dwX;
  DWORD dwY;
  DWORD dwXSize;
  DWORD dwYSize;
  DWORD dwXCountChars;
  DWORD dwYCountChars;
  DWORD dwFillAttribute;
  DWORD dwFlags;
  WORD wShowWindow;
  WORD cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
};

typedef struct _STARTUPINFOA * LPSTARTUPINFOA;

typedef struct _RTL_CRITICAL_SECTION _RTL_CRITICAL_SECTION, * P_RTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef PRTL_CRITICAL_SECTION LPCRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG _RTL_CRITICAL_SECTION_DEBUG, * P_RTL_CRITICAL_SECTION_DEBUG;

typedef struct _RTL_CRITICAL_SECTION_DEBUG * PRTL_CRITICAL_SECTION_DEBUG;

typedef long LONG;

typedef ulong ULONG_PTR;

typedef struct _LIST_ENTRY _LIST_ENTRY, * P_LIST_ENTRY;

typedef struct _LIST_ENTRY LIST_ENTRY;

struct _RTL_CRITICAL_SECTION {
  PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
  LONG LockCount;
  LONG RecursionCount;
  HANDLE OwningThread;
  HANDLE LockSemaphore;
  ULONG_PTR SpinCount;
};

struct _LIST_ENTRY {
  struct _LIST_ENTRY * Flink;
  struct _LIST_ENTRY * Blink;
};

struct _RTL_CRITICAL_SECTION_DEBUG {
  WORD Type;
  WORD CreatorBackTraceIndex;
  struct _RTL_CRITICAL_SECTION * CriticalSection;
  LIST_ENTRY ProcessLocksList;
  DWORD EntryCount;
  DWORD ContentionCount;
  DWORD Flags;
  WORD CreatorBackTraceIndexHigh;
  WORD SpareWORD;
};

typedef struct _EXCEPTION_POINTERS _EXCEPTION_POINTERS, * P_EXCEPTION_POINTERS;

typedef LONG( * PTOP_LEVEL_EXCEPTION_FILTER)(struct _EXCEPTION_POINTERS * );

typedef struct _EXCEPTION_RECORD _EXCEPTION_RECORD, * P_EXCEPTION_RECORD;

typedef struct _EXCEPTION_RECORD EXCEPTION_RECORD;

typedef EXCEPTION_RECORD * PEXCEPTION_RECORD;

typedef struct _CONTEXT _CONTEXT, * P_CONTEXT;

typedef struct _CONTEXT CONTEXT;

typedef CONTEXT * PCONTEXT;

typedef void * PVOID;

typedef struct _FLOATING_SAVE_AREA _FLOATING_SAVE_AREA, * P_FLOATING_SAVE_AREA;

typedef struct _FLOATING_SAVE_AREA FLOATING_SAVE_AREA;

struct _FLOATING_SAVE_AREA {
  DWORD ControlWord;
  DWORD StatusWord;
  DWORD TagWord;
  DWORD ErrorOffset;
  DWORD ErrorSelector;
  DWORD DataOffset;
  DWORD DataSelector;
  BYTE RegisterArea[80];
  DWORD Cr0NpxState;
};

struct _CONTEXT {
  DWORD ContextFlags;
  DWORD Dr0;
  DWORD Dr1;
  DWORD Dr2;
  DWORD Dr3;
  DWORD Dr6;
  DWORD Dr7;
  FLOATING_SAVE_AREA FloatSave;
  DWORD SegGs;
  DWORD SegFs;
  DWORD SegEs;
  DWORD SegDs;
  DWORD Edi;
  DWORD Esi;
  DWORD Ebx;
  DWORD Edx;
  DWORD Ecx;
  DWORD Eax;
  DWORD Ebp;
  DWORD Eip;
  DWORD SegCs;
  DWORD EFlags;
  DWORD Esp;
  DWORD SegSs;
  BYTE ExtendedRegisters[512];
};

struct _EXCEPTION_RECORD {
  DWORD ExceptionCode;
  DWORD ExceptionFlags;
  struct _EXCEPTION_RECORD * ExceptionRecord;
  PVOID ExceptionAddress;
  DWORD NumberParameters;
  ULONG_PTR ExceptionInformation[15];
};

struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT ContextRecord;
};

typedef PTOP_LEVEL_EXCEPTION_FILTER LPTOP_LEVEL_EXCEPTION_FILTER;

typedef struct _iobuf _iobuf, * P_iobuf;

struct _iobuf {
  char * _ptr;
  int _cnt;
  char * _base;
  int _flag;
  int _file;
  int _charbuf;
  int _bufsiz;
  char * _tmpfname;
};

typedef struct _iobuf FILE;

typedef char * va_list;

typedef uint uintptr_t;

typedef uint size_t;

typedef struct _startupinfo _startupinfo, * P_startupinfo;

struct _startupinfo {
  int newmode;
};

typedef struct _MEMORY_BASIC_INFORMATION _MEMORY_BASIC_INFORMATION, * P_MEMORY_BASIC_INFORMATION;

typedef ULONG_PTR SIZE_T;

struct _MEMORY_BASIC_INFORMATION {
  PVOID BaseAddress;
  PVOID AllocationBase;
  DWORD AllocationProtect;
  SIZE_T RegionSize;
  DWORD State;
  DWORD Protect;
  DWORD Type;
};

typedef union _LARGE_INTEGER _LARGE_INTEGER, * P_LARGE_INTEGER;

typedef struct _struct_19 _struct_19, * P_struct_19;

typedef struct _struct_20 _struct_20, * P_struct_20;

typedef double LONGLONG;

struct _struct_20 {
  DWORD LowPart;
  LONG HighPart;
};

struct _struct_19 {
  DWORD LowPart;
  LONG HighPart;
};

union _LARGE_INTEGER {
  struct _struct_19 s;
  struct _struct_20 u;
  LONGLONG QuadPart;
};

typedef union _LARGE_INTEGER LARGE_INTEGER;

typedef CHAR * LPCSTR;

typedef struct _MEMORY_BASIC_INFORMATION * PMEMORY_BASIC_INFORMATION;

typedef struct IMAGE_DOS_HEADER IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

struct IMAGE_DOS_HEADER {
  char e_magic[2]; // Magic number
  word e_cblp; // Bytes of last page
  word e_cp; // Pages in file
  word e_crlc; // Relocations
  word e_cparhdr; // Size of header in paragraphs
  word e_minalloc; // Minimum extra paragraphs needed
  word e_maxalloc; // Maximum extra paragraphs needed
  word e_ss; // Initial (relative) SS value
  word e_sp; // Initial SP value
  word e_csum; // Checksum
  word e_ip; // Initial IP value
  word e_cs; // Initial (relative) CS value
  word e_lfarlc; // File address of relocation table
  word e_ovno; // Overlay number
  word e_res[4][4]; // Reserved words
  word e_oemid; // OEM identifier (for e_oeminfo)
  word e_oeminfo; // OEM information; e_oemid specific
  word e_res2[10][10]; // Reserved words
  dword e_lfanew; // File address of new exe header
  byte e_program[64]; // Actual DOS program
};

typedef struct _FILETIME _FILETIME, * P_FILETIME;

typedef struct _FILETIME * LPFILETIME;

struct _FILETIME {
  DWORD dwLowDateTime;
  DWORD dwHighDateTime;
};

typedef int( * FARPROC)(void);

typedef struct HINSTANCE__ HINSTANCE__, * PHINSTANCE__;

struct HINSTANCE__ {
  int unused;
};

typedef DWORD * PDWORD;

typedef struct HINSTANCE__ * HINSTANCE;

typedef void * LPCVOID;

typedef void * LPVOID;

typedef HINSTANCE HMODULE;

typedef int BOOL;

typedef uint UINT;

typedef struct IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_DATA_DIRECTORY IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

struct IMAGE_DATA_DIRECTORY {
  ImageBaseOffset32 VirtualAddress;
  dword Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
  word Magic;
  byte MajorLinkerVersion;
  byte MinorLinkerVersion;
  dword SizeOfCode;
  dword SizeOfInitializedData;
  dword SizeOfUninitializedData;
  ImageBaseOffset32 AddressOfEntryPoint;
  ImageBaseOffset32 BaseOfCode;
  ImageBaseOffset32 BaseOfData;
  pointer32 ImageBase;
  dword SectionAlignment;
  dword FileAlignment;
  word MajorOperatingSystemVersion;
  word MinorOperatingSystemVersion;
  word MajorImageVersion;
  word MinorImageVersion;
  word MajorSubsystemVersion;
  word MinorSubsystemVersion;
  dword Win32VersionValue;
  dword SizeOfImage;
  dword SizeOfHeaders;
  dword CheckSum;
  word Subsystem;
  word DllCharacteristics;
  dword SizeOfStackReserve;
  dword SizeOfStackCommit;
  dword SizeOfHeapReserve;
  dword SizeOfHeapCommit;
  dword LoaderFlags;
  dword NumberOfRvaAndSizes;
  struct IMAGE_DATA_DIRECTORY DataDirectory[16];
};

typedef struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct, * PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;

struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct {
  dword NameOffset;
  dword NameIsString;
};

typedef struct IMAGE_THUNK_DATA32 IMAGE_THUNK_DATA32, * PIMAGE_THUNK_DATA32;

struct IMAGE_THUNK_DATA32 {
  dword StartAddressOfRawData;
  dword EndAddressOfRawData;
  dword AddressOfIndex;
  dword AddressOfCallBacks;
  dword SizeOfZeroFill;
  dword Characteristics;
};

typedef struct IMAGE_FILE_HEADER IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

struct IMAGE_FILE_HEADER {
  word Machine; // 332
  word NumberOfSections;
  dword TimeDateStamp;
  dword PointerToSymbolTable;
  dword NumberOfSymbols;
  word SizeOfOptionalHeader;
  word Characteristics;
};

typedef struct IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

struct IMAGE_NT_HEADERS32 {
  char Signature[4];
  struct IMAGE_FILE_HEADER FileHeader;
  struct IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY IMAGE_RESOURCE_DIRECTORY_ENTRY, * PIMAGE_RESOURCE_DIRECTORY_ENTRY;

typedef union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion, * PIMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion;

union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion {
  struct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct IMAGE_RESOURCE_DIRECTORY_ENTRY_NameStruct;
  dword Name;
  word Id;
};

union IMAGE_RESOURCE_DIRECTORY_ENTRY {
  union IMAGE_RESOURCE_DIRECTORY_ENTRY_NameUnion NameUnion;
  union IMAGE_RESOURCE_DIRECTORY_ENTRY_DirectoryUnion DirectoryUnion;
};

typedef struct IMAGE_SECTION_HEADER IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef union Misc Misc, * PMisc;

typedef enum SectionFlags {
  IMAGE_SCN_TYPE_NO_PAD = 8,
    IMAGE_SCN_RESERVED_0001 = 16,
    IMAGE_SCN_CNT_CODE = 32,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 64,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 128,
    IMAGE_SCN_LNK_OTHER = 256,
    IMAGE_SCN_LNK_INFO = 512,
    IMAGE_SCN_RESERVED_0040 = 1024,
    IMAGE_SCN_LNK_REMOVE = 2048,
    IMAGE_SCN_LNK_COMDAT = 4096,
    IMAGE_SCN_GPREL = 32768,
    IMAGE_SCN_MEM_16BIT = 131072,
    IMAGE_SCN_MEM_PURGEABLE = 131072,
    IMAGE_SCN_MEM_LOCKED = 262144,
    IMAGE_SCN_MEM_PRELOAD = 524288,
    IMAGE_SCN_ALIGN_1BYTES = 1048576,
    IMAGE_SCN_ALIGN_2BYTES = 2097152,
    IMAGE_SCN_ALIGN_4BYTES = 3145728,
    IMAGE_SCN_ALIGN_8BYTES = 4194304,
    IMAGE_SCN_ALIGN_16BYTES = 5242880,
    IMAGE_SCN_ALIGN_32BYTES = 6291456,
    IMAGE_SCN_ALIGN_64BYTES = 7340032,
    IMAGE_SCN_ALIGN_128BYTES = 8388608,
    IMAGE_SCN_ALIGN_256BYTES = 9437184,
    IMAGE_SCN_ALIGN_512BYTES = 10485760,
    IMAGE_SCN_ALIGN_1024BYTES = 11534336,
    IMAGE_SCN_ALIGN_2048BYTES = 12582912,
    IMAGE_SCN_ALIGN_4096BYTES = 13631488,
    IMAGE_SCN_ALIGN_8192BYTES = 14680064,
    IMAGE_SCN_LNK_NRELOC_OVFL = 16777216,
    IMAGE_SCN_MEM_DISCARDABLE = 33554432,
    IMAGE_SCN_MEM_NOT_CACHED = 67108864,
    IMAGE_SCN_MEM_NOT_PAGED = 134217728,
    IMAGE_SCN_MEM_SHARED = 268435456,
    IMAGE_SCN_MEM_EXECUTE = 536870912,
    IMAGE_SCN_MEM_READ = 1073741824,
    IMAGE_SCN_MEM_WRITE = 2147483648
}
SectionFlags;

union Misc {
  dword PhysicalAddress;
  dword VirtualSize;
};

struct IMAGE_SECTION_HEADER {
  char Name[8];
  union Misc Misc;
  ImageBaseOffset32 VirtualAddress;
  dword SizeOfRawData;
  dword PointerToRawData;
  dword PointerToRelocations;
  dword PointerToLinenumbers;
  word NumberOfRelocations;
  word NumberOfLinenumbers;
  enum SectionFlags Characteristics;
};

typedef struct IMAGE_RESOURCE_DATA_ENTRY IMAGE_RESOURCE_DATA_ENTRY, * PIMAGE_RESOURCE_DATA_ENTRY;

struct IMAGE_RESOURCE_DATA_ENTRY {
  dword OffsetToData;
  dword Size;
  dword CodePage;
  dword Reserved;
};

typedef struct IMAGE_RESOURCE_DIRECTORY IMAGE_RESOURCE_DIRECTORY, * PIMAGE_RESOURCE_DIRECTORY;

struct IMAGE_RESOURCE_DIRECTORY {
  dword Characteristics;
  dword TimeDateStamp;
  word MajorVersion;
  word MinorVersion;
  word NumberOfNamedEntries;
  word NumberOfIdEntries;
};

typedef int( * _onexit_t)(void);

typedef void( * _invalid_parameter_handler)(wchar_t * , wchar_t * , wchar_t * , uint, uintptr_t);

// WARNING: Unable to track spacebase fully for stack

undefined4 startup_sequence(void)

{
  char cVar1;
  undefined4 uVar2;
  uint reversed_calculation;
  undefined4 * counter2;
  int loopcounter;
  char * pcVar3;
  size_t sVar4;
  void * pvVar5;
  int counter;
  undefined4 extraout_EDX;
  bool data_present;
  LPSTARTUPINFOA * startupinfo1;
  DWORD * startupinfo3;
  undefined4 * puVar6;
  void ** ppvVar7;
  undefined4 * puVar8;
  LPSTARTUPINFOA * startupinfo2;
  DWORD * pDVar9;
  int unaff_FS_OFFSET;
  undefined4 local_74;
  void * local_70;
  undefined4 local_60[11];
  byte local_34;
  ushort local_30;
  int counter_buffer;
  undefined1 initcount;

  counter2 = local_60;
  for (counter = 0x11; counter != 0; counter = counter + -1) {
    * counter2 = 0;
    counter2 = counter2 + 1;
  }
  reversed_calculation = reverse_count(initcount);
  counter2 = (undefined4 * )((int) & local_74 + -reversed_calculation + 3 & 0xfffffff0);
  * counter2 = 0xcccccccc;
  counter2[1] = 0xcccccccc;
  counter2[2] = 0xcccccccc;
  counter2[3] = 0xcccccccc;
  counter2[4] = 0xcccccccc;
  counter2[5] = 0xcccccccc;
  counter2[6] = 0xcccccccc;
  counter2[7] = 0xcccccccc;
  startupinfo1 = (LPSTARTUPINFOA * )((uint)( & stack0xffffff74 + -reversed_calculation) & 0xfffffff0);
  if (DAT_00405038 != 0) {
    * startupinfo1 = (LPSTARTUPINFOA) extraout_EDX;
    startupinfo2 = startupinfo1 + -1;
    startupinfo1[-1] = (LPSTARTUPINFOA) 0x401479;
    GetStartupInfoA( * startupinfo1);
    startupinfo1 = (LPSTARTUPINFOA * )((int) startupinfo2 + -4);
  }
  counter = * (int * )( * (int * )(unaff_FS_OFFSET + 0x18) + 4);
  while (true) {
    loopcounter = 0;
    LOCK();
    counter_buffer = counter;
    if (DAT_004053d8 != 0) {
      loopcounter = DAT_004053d8;
      counter_buffer = DAT_004053d8;
    }
    DAT_004053d8 = counter_buffer;
    UNLOCK();
    if (loopcounter == 0) {
      data_present = false;
      goto joined_r0x0040122d;
    }
    if (loopcounter == counter) break;
    * startupinfo1 = (LPSTARTUPINFOA) 0x3e8;
    startupinfo3 = (DWORD * )(startupinfo1 + -1);
    startupinfo1[-1] = (LPSTARTUPINFOA) 0x401212;
    Sleep((DWORD) * startupinfo1);
    startupinfo1 = (LPSTARTUPINFOA * )((int) startupinfo3 + -4);
  }
  data_present = true;
  joined_r0x0040122d:
    if (DAT_004053dc == 1) {
      * startupinfo1 = (LPSTARTUPINFOA) 0x1f;
      startupinfo1[-1] = (LPSTARTUPINFOA) 0x40142f;
      _amsg_exit((int) * startupinfo1);
    }
  else if (DAT_004053dc == 0) {
    DAT_004053dc = 1;
    startupinfo1[1] = (LPSTARTUPINFOA) & DAT_00407018;
    * startupinfo1 = (LPSTARTUPINFOA) & DAT_0040700c;
    pDVar9 = (DWORD * )(startupinfo1 + -1);
    startupinfo1 = startupinfo1 + -1;
    * pDVar9 = 0x40149f;
    _initterm();
  } else {
    DAT_00405004 = 1;
  }
  if (DAT_004053dc == 1) {
    startupinfo1[1] = (LPSTARTUPINFOA) & DAT_00407008;
    * startupinfo1 = (LPSTARTUPINFOA) & DAT_00407000;
    puVar8 = startupinfo1 + -1;
    startupinfo1 = startupinfo1 + -1;
    * puVar8 = 0x401451;
    _initterm();
    DAT_004053dc = 2;
  }
  if (!data_present) {
    LOCK();
    UNLOCK();
    DAT_004053d8 = 0;
  }
  startupinfo1[2] = (LPSTARTUPINFOA) 0x0;
  startupinfo1[1] = (LPSTARTUPINFOA) 0x2;
  * startupinfo1 = (LPSTARTUPINFOA) 0x0;
  puVar6 = startupinfo1 + -1;
  startupinfo1[-1] = (LPSTARTUPINFOA) 0x401282;
  tls_callback_0( * startupinfo1, (int) startupinfo1[1]);
  *(undefined4 * )((int) puVar6 + -0x10) = 0x40128a;
  initialize_memory();
  *(undefined ** )((int) puVar6 + -0xc) = & LAB_00401c20;
  ppvVar7 = (void ** )((int) puVar6 + -0x10);
  *(undefined4 * )((int) puVar6 + -0x10) = 0x401297;
  exception = SetUnhandledExceptionFilter( * (LPTOP_LEVEL_EXCEPTION_FILTER * )((int) puVar6 + -0xc));
  ppvVar7[-1] = & LAB_00401000;
  ppvVar7[-2] = (void * ) 0x4012ab;
  _set_invalid_parameter_handler((_invalid_parameter_handler) ppvVar7[-1]);
  ppvVar7[-2] = (void * ) 0x4012b0;
  empty_function3();
  counter = DAT_0040501c;
  DAT_004053cc = 0x400000;
  pcVar3 = * (char ** ) _acmdln_exref;
  if (pcVar3 != (char * ) 0x0) {
    data_present = false;
    do {
      cVar1 = * pcVar3;
      if (cVar1 < '!') {
        DAT_004053c8 = pcVar3;
        if (cVar1 == '\0') break;
        if (!data_present) goto LAB_004012f9;
        data_present = true;
      } else if (cVar1 == '\"') {
        data_present = (bool)(data_present ^ 1);
      }
      pcVar3 = pcVar3 + 1;
    } while (true);
  }
  goto LAB_00401309;
  while ( * pcVar3 != '\0') {
    LAB_004012f9: pcVar3 = pcVar3 + 1;
    DAT_004053c8 = pcVar3;
    if (' ' < * pcVar3) break;
  }
  LAB_00401309:
    if (DAT_00405038 != 0) {
      DAT_00403000 = 10;
      if ((local_34 & 1) != 0) {
        DAT_00403000 = (uint) local_30;
      }
    }
  local_74 = DAT_0040501c;
  loopcounter = DAT_0040501c * 4;
  ppvVar7[-1] = (void * )(loopcounter + 4);
  ppvVar7[-2] = (void * ) 0x401344;
  local_70 = malloc((size_t) ppvVar7[-1]);
  counter_buffer = (int) DAT_00405018;
  if (counter < 1) {
    loopcounter = 0;
  } else {
    counter = 0;
    do {
      ppvVar7[-1] = (void * ) * (undefined4 * )(counter_buffer + counter * 4);
      ppvVar7[-2] = (void * ) 0x40136b;
      sVar4 = strlen((char * ) ppvVar7[-1]);
      ppvVar7[-1] = (void * )(sVar4 + 1);
      ppvVar7[-2] = (void * ) 0x401376;
      pvVar5 = malloc((size_t) ppvVar7[-1]);
      *(void ** )((int) local_70 + counter * 4) = pvVar5;
      uVar2 = * (undefined4 * )(counter_buffer + counter * 4);
      counter = counter + 1;
      ppvVar7[1] = (void * )(sVar4 + 1);
      ppvVar7[-1] = pvVar5;
      * ppvVar7 = (void * ) uVar2;
      ppvVar7[-2] = (void * ) 0x401392;
      memcpy(ppvVar7[-1], * ppvVar7, (size_t) ppvVar7[1]);
    } while (counter != local_74);
  }
  *(undefined4 * )((int) local_70 + loopcounter) = 0;
  DAT_00405018 = local_70;
  ppvVar7[-2] = (void * ) 0x4013b2;
  dll_sequences();
  *(void ** ) __initenv_exref = DAT_00405014;
  ppvVar7[1] = DAT_00405014;
  * ppvVar7 = DAT_00405018;
  ppvVar7[-1] = (void * ) DAT_0040501c;
  ppvVar7[-2] = (void * ) 0x4013de;
  DAT_0040500c = execute_initialization_steps( * (undefined * )(ppvVar7 + -1));
  if (DAT_00405008 != 0) {
    if (DAT_00405004 == 0) {
      ppvVar7[-2] = (void * ) 0x401400;
      _cexit();
    }
    return DAT_0040500c;
  }
  ppvVar7[-1] = (void * ) DAT_0040500c;
  // WARNING: Subroutine does not return
  ppvVar7[-2] = & UNK_004014b5;
  exit((int) ppvVar7[-1]);
}

void entry(void)

{
  DAT_00405038 = 1;
  get_system_seed();
  DAT_00405038 = 0;
  get_system_seed();
  startup_sequence();
  return;
}

void register_libgcj_classes(void)

{
  HMODULE libgcj;
  FARPROC register_classes_function;

  if (DAT_00403024 != 0) {
    libgcj = GetModuleHandleA("libgcj-13.dll");
    register_classes_function = (FARPROC) 0x0;
    if (libgcj != (HMODULE) 0x0) {
      register_classes_function = GetProcAddress(libgcj, "_Jv_RegisterClasses");
    }
    if (register_classes_function != (FARPROC) 0x0) {
      ( * register_classes_function)( & DAT_00403024);
    }
  }
  return;
}

// WARNING: Unable to track spacebase fully for stack

void showmessagebox(undefined4 param_1, undefined param_2)

{
  int iVar1;
  uint uVar2;
  char * pcVar3;
  int * piVar4;
  undefined1 unaff_BP;
  undefined local_100c[2048];
  undefined local_80c[2052];
  undefined4 uStack_8;

  uStack_8 = 0x40156d;
  uVar2 = reverse_count(unaff_BP);
  iVar1 = -uVar2;
  *(undefined ** )( & param_2 + iVar1) = & param_2;
  *(undefined4 * )((int) & param_1 + iVar1) = param_1;
  *(undefined4 * )( & stack0x00000000 + iVar1) = 0x800;
  *(undefined ** )( & stack0xfffffffc + iVar1) = local_80c;
  *(undefined4 * )((int) & uStack_8 + iVar1) = 0x4015a1;
  _vsnprintf( * (char ** )( & stack0xfffffffc + iVar1), *(size_t * )( & stack0x00000000 + iVar1),
    *(char ** )((int) & param_1 + iVar1), *(va_list * )( & param_2 + iVar1));
  *(undefined4 * )( & stack0xfffffffc + iVar1) = caption;
  *(undefined4 * )((int) & uStack_8 + iVar1) = 0x4015ae;
  pcVar3 = process_locale_string( * (char ** )( & stack0xfffffffc + iVar1));
  *(char ** )( & param_2 + iVar1) = pcVar3;
  *(char ** )((int) & param_1 + iVar1) = "%s error";
  *(undefined4 * )( & stack0x00000000 + iVar1) = 0x800;
  *(undefined ** )( & stack0xfffffffc + iVar1) = local_100c;
  *(undefined4 * )((int) & uStack_8 + iVar1) = 0x4015d2;
  _snprintf( * (char ** )( & stack0xfffffffc + iVar1), *(size_t * )( & stack0x00000000 + iVar1),
    *(char ** )((int) & param_1 + iVar1));
  *(undefined4 * )( & param_2 + iVar1) = 0;
  *(undefined ** )((int) & param_1 + iVar1) = local_80c;
  *(undefined ** )( & stack0x00000000 + iVar1) = local_100c;
  *(undefined4 * )( & stack0xfffffffc + iVar1) = 0x10;
  piVar4 = (int * )((int) & uStack_8 + iVar1);
  *(undefined4 * )((int) & uStack_8 + iVar1) = 0x4015fa;
  SDL_ShowSimpleMessageBox();
  * piVar4 = 1;
  // WARNING: Subroutine does not return
  piVar4[-1] = (int) truncate_after_separator;
  exit( * piVar4);
}

char * __cdecl truncate_after_separator(char * param_1)

{
  bool bVar1;
  char * local_10;
  char * local_c;

  bVar1 = true;
  local_10 = (char * ) 0x0;
  for (local_c = param_1;* local_c != '\0'; local_c = local_c + 1) {
    if (( * local_c == '\\') || ( * local_c == '/')) {
      if (bVar1) {
        bVar1 = false;
      } else {
        local_10 = local_c;
      }
    }
  }
  if (local_10 != (char * ) 0x0) {
    * local_10 = '\0';
  }
  return param_1;
}

// WARNING: Unable to track spacebase fully for stack

void * get_path(void)

{
  undefined * puVar1;
  uint reversed_count_caption2;
  int path_sized;
  size_t sVar2;
  size_t sVar3;
  undefined4 uStack_60;
  int iStack_4c;
  undefined auStack_48[12];
  int local_3c;
  void * local_38;
  int local_34;
  size_t local_30;
  char * local_2c;
  undefined * inverted_caption_processed;
  DWORD fullpathname;
  DWORD path;
  LPCSTR caption2;
  int inverted_caption2;

  uStack_60 = 0x4016a1;
  caption2 = caption;
  fullpathname = GetFullPathNameA(caption, 0, (LPSTR) 0x0, (LPSTR * ) 0x0);
  uStack_60 = 0x4016d1;
  path = fullpathname;
  reversed_count_caption2 = reverse_count((char) caption2);
  inverted_caption2 = -reversed_count_caption2;
  inverted_caption_processed = auStack_48 + inverted_caption2;
  path_sized = path + 1;
  *(int ** )( & stack0xffffffb0 + inverted_caption2) = & local_3c;
  *(undefined ** )( & stack0xffffffac + inverted_caption2) = auStack_48 + inverted_caption2;
  *(int * )( & stack0xffffffa8 + inverted_caption2) = path_sized;
  *(LPCSTR * )( & stack0xffffffa4 + inverted_caption2) = caption;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x401706;
  GetFullPathNameA( * (LPCSTR * )( & stack0xffffffa4 + inverted_caption2),
    *(DWORD * )( & stack0xffffffa8 + inverted_caption2),
    *(LPSTR * )( & stack0xffffffac + inverted_caption2),
    *(LPSTR ** )( & stack0xffffffb0 + inverted_caption2));
  *(undefined ** )( & stack0xffffffa4 + inverted_caption2) = inverted_caption_processed;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x401714;
  local_2c = truncate_after_separator( * (char ** )( & stack0xffffffa4 + inverted_caption2));
  *(char ** )( & stack0xffffffa4 + inverted_caption2) = local_2c;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x401722;
  local_2c = truncate_after_separator( * (char ** )( & stack0xffffffa4 + inverted_caption2));
  *(char ** )( & stack0xffffffa4 + inverted_caption2) = local_2c;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x401730;
  local_2c = truncate_after_separator( * (char ** )( & stack0xffffffa4 + inverted_caption2));
  *(int * )( & stack0xffffffa4 + inverted_caption2) = local_3c;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x40173e;
  local_30 = strlen( * (char ** )( & stack0xffffffa4 + inverted_caption2));
  *(undefined * )((local_30 - 3) + local_3c) = 0x70;
  *(undefined * )((local_30 - 2) + local_3c) = 0x79;
  *(undefined * )((local_30 - 1) + local_3c) = 0;
  *(char ** )( & stack0xffffffa4 + inverted_caption2) = local_2c;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x401782;
  sVar2 = strlen( * (char ** )( & stack0xffffffa4 + inverted_caption2));
  *(int * )( & stack0xffffffa4 + inverted_caption2) = local_3c;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x40178f;
  sVar3 = strlen( * (char ** )( & stack0xffffffa4 + inverted_caption2));
  path_sized = sVar3 + sVar2 + 2;
  local_34 = path_sized;
  *(undefined4 * )( & stack0xffffffa8 + inverted_caption2) = 1;
  *(int * )( & stack0xffffffa4 + inverted_caption2) = path_sized;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x4017aa;
  local_38 = calloc( * (size_t * )( & stack0xffffffa4 + inverted_caption2),
    *(size_t * )( & stack0xffffffa8 + inverted_caption2));
  puVar1 = inverted_caption_processed;
  path_sized = local_34;
  *(int * )((int) & iStack_4c + inverted_caption2) = local_3c;
  *(undefined ** )( & stack0xffffffb0 + inverted_caption2) = puVar1;
  *(char ** )( & stack0xffffffac + inverted_caption2) = "%s\\%s";
  *(int * )( & stack0xffffffa8 + inverted_caption2) = path_sized;
  *(void ** )( & stack0xffffffa4 + inverted_caption2) = local_38;
  *(undefined4 * )((int) & uStack_60 + inverted_caption2) = 0x4017d7;
  _snprintf( * (char ** )( & stack0xffffffa4 + inverted_caption2),
    *(size_t * )( & stack0xffffffa8 + inverted_caption2),
    *(char ** )( & stack0xffffffac + inverted_caption2));
  return local_38;
}

// WARNING: Unable to track spacebase fully for stack

void initialize_python_environment(void)

{
  uint reversed_count;
  int comparecounts;
  undefined * invertedcount_added;
  int * pyflags2;
  int * previous_flag;
  char ** imports;
  FILE ** imports_trunc;
  undefined in_stack_ffffffcc;
  FILE * pFVar1;
  char * pcStack_30;
  FILE ** python_file_flags;
  int local_28;
  undefined4 local_24;
  FILE * local_20;
  undefined4 * flaglist;
  int current_flag;
  int flag_amount;
  int py_flag_index;
  int flagindex;
  int inverted_count;
  undefined4 last_flag;
  FILE ** pyflags;

  current_flag = * (int * ) __argc_exref;
  flaglist = * (undefined4 ** ) __argv_exref;
  caption = * flaglist;
  local_20 = (FILE * ) get_path();
  local_24 = fopen((char * ) local_20, "rb");
  if (local_24 == (FILE * ) 0x0) {
    pFVar1 = local_20;
    showmessagebox("%s: Could not open %s.", (char) caption);
    in_stack_ffffffcc = SUB41(pFVar1, 0);
  }
  local_28 = current_flag;
  reversed_count = reverse_count(in_stack_ffffffcc);
  inverted_count = -reversed_count;
  python_file_flags = (FILE ** )((int) & local_24 + inverted_count + 3 & 0xfffffffc);
  * python_file_flags = local_20;
  py_flag_index = 1;
  flag_amount = 1;
  do {
    if (current_flag <= flag_amount) {
      python_file_flags[py_flag_index] = (FILE * ) 0x0;
      *(int * ) Py_IgnoreEnvironmentFlag_exref = * (int * ) Py_IgnoreEnvironmentFlag_exref + 1;
      *(int * ) Py_OptimizeFlag_exref = * (int * ) Py_OptimizeFlag_exref + 1;
      *(undefined4 * )( & stack0xffffffcc + inverted_count) = caption;
      invertedcount_added = & stack0xffffffc8 + inverted_count;
      *(undefined4 * )( & stack0xffffffc8 + inverted_count) = 0x4019b3;
      Py_SetProgramName();
      pyflags2 = (int * )(invertedcount_added + -4);
      *(undefined4 * )(invertedcount_added + -4) = 0x4019ba;
      Py_Initialize();
      pyflags = python_file_flags;
      pyflags2[2] = 1;
      pyflags2[1] = (int) pyflags;
      * pyflags2 = py_flag_index;
      previous_flag = pyflags2 + -1;
      pyflags2[-1] = 0x4019d6;
      PySys_SetArgvEx();
      imports = (char ** )((int) previous_flag + -4);
      *(undefined4 * )((int) previous_flag + -4) = 0x4019dd;
      PyEval_InitThreads();
      imports[1] = (char * ) 0x0;
      * imports =
        "import sys, os\nsys.renpy_executable = sys.executable\nsys.executable = os.path.dirname(sys.executable) + \'\\\\pythonw.exe\'\n";
      imports_trunc = (FILE ** )(imports + -1);
      imports[-1] = (char * ) 0x4019f3;
      PyRun_SimpleStringFlags();
      imports_trunc[3] = (FILE * ) 0x0;
      imports_trunc[2] = (FILE * ) 0x1;
      imports_trunc[1] = local_20;
      * imports_trunc = local_24;
      imports_trunc[-1] = (FILE * ) 0x401a17;
      PyRun_SimpleFileExFlags();
      return;
    }
    last_flag = flaglist[flag_amount];
    *(undefined ** )((int) & pcStack_30 + inverted_count) = & DAT_0040404d;
    *(undefined4 * )( & stack0xffffffcc + inverted_count) = last_flag;
    *(undefined4 * )( & stack0xffffffc8 + inverted_count) = 0x4018cc;
    flagindex = strcmp( * (char ** )( & stack0xffffffcc + inverted_count),
      *(char ** )((int) & pcStack_30 + inverted_count));
    if (flagindex == 0) {
      LAB_0040193f: flag_amount = flag_amount + 1;
    }
    else {
      last_flag = flaglist[flag_amount];
      *(undefined ** )((int) & pcStack_30 + inverted_count) = & DAT_00404051;
      *(undefined4 * )( & stack0xffffffcc + inverted_count) = last_flag;
      *(undefined4 * )( & stack0xffffffc8 + inverted_count) = 0x4018f1;
      flagindex = strcmp( * (char ** )( & stack0xffffffcc + inverted_count),
        *(char ** )((int) & pcStack_30 + inverted_count));
      if (flagindex == 0) goto LAB_0040193f;
      last_flag = flaglist[flag_amount];
      *(undefined ** )((int) & pcStack_30 + inverted_count) = & DAT_00404056;
      *(undefined4 * )( & stack0xffffffcc + inverted_count) = last_flag;
      *(undefined4 * )( & stack0xffffffc8 + inverted_count) = 0x401916;
      flagindex = strcmp( * (char ** )( & stack0xffffffcc + inverted_count),
        *(char ** )((int) & pcStack_30 + inverted_count));
      if (flagindex == 0) goto LAB_0040193f;
      last_flag = flaglist[flag_amount];
      *(undefined ** )((int) & pcStack_30 + inverted_count) = & DAT_00404059;
      *(undefined4 * )( & stack0xffffffcc + inverted_count) = last_flag;
      *(undefined4 * )( & stack0xffffffc8 + inverted_count) = 0x40193b;
      comparecounts =
        strcmp( * (char ** )( & stack0xffffffcc + inverted_count),
          *(char ** )((int) & pcStack_30 + inverted_count));
      flagindex = py_flag_index;
      if (comparecounts == 0) goto LAB_0040193f;
      py_flag_index = py_flag_index + 1;
      python_file_flags[flagindex] = (FILE * ) flaglist[flag_amount];
    }
    flag_amount = flag_amount + 1;
  } while (true);
}

undefined4 tls_callback_1(undefined4 param_1, int param_2)

{
  if ((param_2 != 0) && (param_2 != 3)) {
    return 1;
  }
  manage_tls_critical_section(param_1, param_2);
  return 1;
}

// WARNING: Removing unreachable block (ram,0x00401ac0)
// WARNING: Removing unreachable block (ram,0x00401ac6)
// WARNING: Removing unreachable block (ram,0x00401ac8)
// WARNING: Removing unreachable block (ram,0x00401ad3)

undefined4 tls_callback_0(undefined4 param_1, int param_2)

{
  if (DAT_00403014 != 2) {
    DAT_00403014 = 2;
  }
  if ((param_2 != 2) && (param_2 == 1)) {
    manage_tls_critical_section(param_1, 1);
  }
  return 1;
}

undefined4 __cdecl empty_function1(undefined4 param_1)

{
  return param_1;
}

undefined4 __cdecl empty_function2(undefined4 param_1)

{
  return param_1;
}

_onexit_t __cdecl exitdll(_onexit_t param_1)

{
  _onexit_t p_Var1;
  int local_14;
  undefined4 local_10[3];

  local_14 = empty_function1(DAT_004053d4);
  if (local_14 != -1) {
    _lock(8);
    local_14 = empty_function1(DAT_004053d4);
    local_10[0] = empty_function1(DAT_004053d0);
    p_Var1 = (_onexit_t) __dllonexit(param_1, & local_14, local_10);
    DAT_004053d4 = empty_function2(local_14);
    DAT_004053d0 = empty_function2(local_10[0]);
    _unlock(8);
    return p_Var1;
  }
  p_Var1 = _onexit(param_1);
  return p_Var1;
}

int __cdecl exitdll(_onexit_t dll_name)

{
  _onexit_t p_Var1;

  p_Var1 = exitdll(dll_name);
  return -(uint)(p_Var1 == (_onexit_t) 0x0);
}

undefined4 empty_function2(void)

{
  return 0;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void handle_math_exceptions(undefined4 param_1)

{
  _DAT_0040504c = param_1;
  __setusermatherr();
  return;
}

void mingw_exception(char * param_1)

{
  fwrite("Mingw-w64 runtime failure:\n", 1, 0x1b, (FILE * )(_iob_exref + 0x40));
  vfprintf((FILE * )(_iob_exref + 0x40), param_1, & stack0x00000008);
  // WARNING: Subroutine does not return
  abort();
}

// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0040214e)
// WARNING: Removing unreachable block (ram,0x0040215b)
// WARNING: Removing unreachable block (ram,0x00402168)
// WARNING: Removing unreachable block (ram,0x0040217b)
// WARNING: Removing unreachable block (ram,0x00402145)
// WARNING: Removing unreachable block (ram,0x004022b3)
// WARNING: Removing unreachable block (ram,0x004022b8)
// WARNING: Removing unreachable block (ram,0x004022c2)
// WARNING: Removing unreachable block (ram,0x00402180)
// WARNING: Removing unreachable block (ram,0x0040218c)
// WARNING: Removing unreachable block (ram,0x00402197)
// WARNING: Removing unreachable block (ram,0x004022d2)
// WARNING: Removing unreachable block (ram,0x004022e7)
// WARNING: Removing unreachable block (ram,0x004022ea)
// WARNING: Removing unreachable block (ram,0x004021b8)
// WARNING: Removing unreachable block (ram,0x00402359)
// WARNING: Removing unreachable block (ram,0x004021c1)
// WARNING: Removing unreachable block (ram,0x004021ca)
// WARNING: Removing unreachable block (ram,0x00402321)
// WARNING: Removing unreachable block (ram,0x00402331)
// WARNING: Removing unreachable block (ram,0x00402334)
// WARNING: Removing unreachable block (ram,0x0040230d)
// WARNING: Removing unreachable block (ram,0x0040231c)
// WARNING: Removing unreachable block (ram,0x004022cd)
// WARNING: Removing unreachable block (ram,0x004021e9)
// WARNING: Removing unreachable block (ram,0x004021ee)
// WARNING: Removing unreachable block (ram,0x004021f6)
// WARNING: Removing unreachable block (ram,0x00402200)
// WARNING: Removing unreachable block (ram,0x0040222d)
// WARNING: Removing unreachable block (ram,0x0040224b)
// WARNING: Removing unreachable block (ram,0x00402262)
// WARNING: Removing unreachable block (ram,0x0040237e)
// WARNING: Removing unreachable block (ram,0x004023a3)
// WARNING: Removing unreachable block (ram,0x00402288)
// WARNING: Removing unreachable block (ram,0x00402240)
// WARNING: Removing unreachable block (ram,0x00402238)

void __fastcall copy_data_to_virtual_address(size_t data_size, void * source_address)

{
  void * current_address;
  int section_index;
  SIZE_T query_result;
  BOOL protect_result;
  uint section_count;
  int section_base;
  int section_entry;
  code * current_function;
  undefined4 * section_data;
  code * virtual_info;
  undefined stack_buffer[45];
  code * error_function;
  DWORD protect_size;
  LPVOID query_result_info[3];
  SIZE_T page_size;
  int protection_flags;
  LPCVOID query_address;
  undefined unused_stack_var;

  if ((int) DAT_00405054 < 1) goto LAB_00402090;
  current_function = (code * ) 0x0;
  section_entry = DAT_00405058;
  do {
    if (( * (void ** )(section_entry + 4) <= current_address) &&
      (virtual_info = VirtualQuery_exref,
        current_address <
        (void * )((int) * (void ** )(section_entry + 4) + * (int * )( * (int * )(section_entry + 8) + 8))))
      goto LAB_00401f6a;
    current_function = current_function + 1;
    section_entry = section_entry + 0xc;
  } while (current_function != DAT_00405054);
  do {
    section_entry = process_pe_header((int) current_address);
    if (section_entry == 0) {
      LAB_004020b7: mingw_exception("Address %p has no image-section");
      LAB_004020c7: mingw_exception("  VirtualQuery failed for %d bytes at address %p");
      if (DAT_00405050 != 0) {
        return;
      }
      DAT_00405050 = 1;
      error_function = current_function;
      get_pe_image_base();
      section_count = reverse_count(unused_stack_var);
      DAT_00405054 = (code * ) 0x0;
      DAT_00405058 = (uint)(stack_buffer + -section_count) & 0xfffffff0;
      return;
    }
    section_base = (int) current_function * 0xc;
    section_data = (undefined4 * )(section_base + DAT_00405058);
    section_data[2] = section_entry;
    * section_data = 0;
    query_address = (LPCVOID) 0x401f17;
    section_index = get_image_base();
    section_data[1] = section_index + * (int * )(section_entry + 0xc);
    current_function = VirtualQuery_exref;
    error_function = (code * ) 0x401f46;
    query_result = VirtualQuery(query_address,
      *(PMEMORY_BASIC_INFORMATION * )(DAT_00405058 + 4 + section_base),
      (SIZE_T) query_result_info);
    if (query_result == 0) {
      error_function = (code * ) 0x4020b7;
      mingw_exception("  VirtualQuery failed for %d bytes at address %p");
      goto LAB_004020b7;
    }
    if ((protection_flags == 4) || (protection_flags == 0x40)) {
      LAB_00401f63: DAT_00405054 = DAT_00405054 + 1;
      virtual_info = current_function;
      LAB_00401f6a: section_entry = ( * virtual_info)();
      current_function = virtual_info;
      if (section_entry != 0) {
        if ((protection_flags == 4) || (protection_flags == 0x40)) {
          memcpy(current_address, source_address, data_size);
        } else {
          VirtualProtect(query_result_info[0], page_size, 0x40, & protect_size);
          memcpy(current_address, source_address, data_size);
          if ((protection_flags != 0x40) && (protection_flags != 4)) {
            VirtualProtect(query_result_info[0], page_size, protect_size, & protect_size);
            return;
          }
        }
        return;
      }
      goto LAB_004020c7;
    }
    error_function = (code * ) 0x402065;
    protect_result =
      VirtualProtect(query_result_info[0], page_size, 0x40, (PDWORD)(section_base + DAT_00405058));
    if (protect_result != 0) goto LAB_00401f63;
    error_function = (code * ) 0x402079;
    GetLastError();
    error_function = (code * ) 0x402089;
    mingw_exception("  VirtualProtect failed with code 0x%x");
    LAB_00402090:
      current_function = (code * ) 0x0;
  } while (true);
}

// WARNING: Unable to track spacebase fully for stack
// WARNING: Removing unreachable block (ram,0x0040214e)
// WARNING: Removing unreachable block (ram,0x0040215b)
// WARNING: Removing unreachable block (ram,0x00402168)
// WARNING: Removing unreachable block (ram,0x0040217b)
// WARNING: Removing unreachable block (ram,0x00402145)
// WARNING: Removing unreachable block (ram,0x004022b3)
// WARNING: Removing unreachable block (ram,0x004022b8)
// WARNING: Removing unreachable block (ram,0x004022c2)
// WARNING: Removing unreachable block (ram,0x00402180)
// WARNING: Removing unreachable block (ram,0x0040218c)
// WARNING: Removing unreachable block (ram,0x00402197)
// WARNING: Removing unreachable block (ram,0x004022d2)
// WARNING: Removing unreachable block (ram,0x004022e7)
// WARNING: Removing unreachable block (ram,0x004022ea)
// WARNING: Removing unreachable block (ram,0x004021b8)
// WARNING: Removing unreachable block (ram,0x00402359)
// WARNING: Removing unreachable block (ram,0x004021c1)
// WARNING: Removing unreachable block (ram,0x004021ca)
// WARNING: Removing unreachable block (ram,0x00402321)
// WARNING: Removing unreachable block (ram,0x00402331)
// WARNING: Removing unreachable block (ram,0x00402334)
// WARNING: Removing unreachable block (ram,0x0040230d)
// WARNING: Removing unreachable block (ram,0x0040231c)
// WARNING: Removing unreachable block (ram,0x004022cd)
// WARNING: Removing unreachable block (ram,0x004021e9)
// WARNING: Removing unreachable block (ram,0x004021ee)
// WARNING: Removing unreachable block (ram,0x004021f6)
// WARNING: Removing unreachable block (ram,0x00402200)
// WARNING: Removing unreachable block (ram,0x0040222d)
// WARNING: Removing unreachable block (ram,0x0040224b)
// WARNING: Removing unreachable block (ram,0x00402262)
// WARNING: Removing unreachable block (ram,0x0040237e)
// WARNING: Removing unreachable block (ram,0x004023a3)
// WARNING: Removing unreachable block (ram,0x00402288)
// WARNING: Removing unreachable block (ram,0x00402240)
// WARNING: Removing unreachable block (ram,0x00402238)

void initialize_memory(void)

{
  uint adjusted_stack_pointer;
  undefined buffer[45];
  undefined unused_stack_value;

  if (DAT_00405050 == 0) {
    DAT_00405050 = 1;
    get_pe_image_base();
    adjusted_stack_pointer = reverse_count(unused_stack_value);
    DAT_00405054 = 0;
    DAT_00405058 = (uint)(buffer + -adjusted_stack_pointer) & 0xfffffff0;
    return;
  }
  return;
}

void empty_function3(void)

{
  return;
}

void execute_dll(void)

{
  int iVar1;
  int iVar2;

  iVar1 = 0;
  do {
    iVar2 = iVar1;
    iVar1 = iVar2 + 1;
  } while (( & DAT_00402f60)[iVar2 + 1] != 0);
  for (; iVar2 != 0; iVar2 = iVar2 + -1) {
    ( * (code * )( & DAT_00402f60)[iVar2])();
  }
  exitdll((_onexit_t) & dll_name);
  return;
}

void dll_sequences(void)

{
  if (DAT_0040505c != 0) {
    return;
  }
  DAT_0040505c = 1;
  execute_dll();
  return;
}

// WARNING: Globals starting with '_' overlap smaller symbols at the same address

void get_system_seed(void)

{
  DWORD ProcessID;
  DWORD ThreadID;
  DWORD ticks;
  uint combined_time;
  _FILETIME systemtime;
  LARGE_INTEGER local_24[2];

  systemtime.dwLowDateTime = 0;
  systemtime.dwHighDateTime = 0;
  if (randomseed != 0xbb40e64e) {
    _invertedseed = ~randomseed;
    return;
  }
  GetSystemTimeAsFileTime( & systemtime);
  combined_time = systemtime.dwLowDateTime ^ systemtime.dwHighDateTime;
  ProcessID = GetCurrentProcessId();
  ThreadID = GetCurrentThreadId();
  ticks = GetTickCount();
  QueryPerformanceCounter(local_24);
  randomseed = combined_time ^ local_24[0].s.LowPart ^ local_24[0].s.HighPart ^ ProcessID ^ ThreadID ^
    ticks;
  if (randomseed == 0xbb40e64e) {
    _invertedseed = 0x44bf19b0;
    randomseed = 0xbb40e64f;
  } else {
    _invertedseed = ~randomseed;
  }
  return;
}

void process_tls_callbacks(void)

{
  LPVOID tls_value;
  DWORD last_error;
  DWORD * callback_entry;

  EnterCriticalSection((LPCRITICAL_SECTION) & DAT_004053a8);
  for (callback_entry = DAT_004053a0; callback_entry != (DWORD * ) 0x0; callback_entry = (DWORD * ) callback_entry[2]) {
    tls_value = TlsGetValue( * callback_entry);
    last_error = GetLastError();
    if ((last_error == 0) && (tls_value != (LPVOID) 0x0)) {
      ( * (code * ) callback_entry[1])(tls_value);
    }
  }
  LeaveCriticalSection((LPCRITICAL_SECTION) & DAT_004053a8);
  return;
}

undefined4 __cdecl manage_tls_critical_section(undefined4 param_1, int param_2)

{
  if (param_2 != 1) {
    if (param_2 == 0) {
      if (DAT_004053a4 != 0) {
        process_tls_callbacks();
      }
      if (DAT_004053a4 == 1) {
        DAT_004053a4 = 0;
        DeleteCriticalSection((LPCRITICAL_SECTION) & DAT_004053a8);
      }
    } else if ((param_2 == 3) && (DAT_004053a4 != 0)) {
      process_tls_callbacks();
    }
    return 1;
  }
  if (DAT_004053a4 == 0) {
    InitializeCriticalSection((LPCRITICAL_SECTION) & DAT_004053a8);
  }
  DAT_004053a4 = 1;
  return 1;
}

bool check_pe_header(void)

{
  int base_address;
  int * header_pointer;

  header_pointer = (int * )(base_address + * (int * )(base_address + 0x3c));
  if ( * header_pointer != 0x4550) {
    return false;
  }
  return * (short * )(header_pointer + 6) == 0x10b;
}

int __cdecl find_segment_address(int param_1, uint param_2)

{
  int header_offset;
  int segment_start;
  uint index;

  segment_start = param_1 + * (int * )(param_1 + 60);
  header_offset = segment_start + 24 + (uint) * (ushort * )(segment_start + 20);
  if ( * (ushort * )(segment_start + 6) != 0) {
    index = 0;
    do {
      if (( * (uint * )(header_offset + 12) <= param_2) &&
        (param_2 < * (uint * )(header_offset + 12) + * (int * )(header_offset + 8))) {
        return header_offset;
      }
      index = index + 1;
      header_offset = header_offset + 40;
    } while (index < * (ushort * )(segment_start + 6));
  }
  return 0;
}

int __cdecl process_pe_header(int param_1)

{
  bool is_pe_header_valid;
  undefined3 unused_var;
  int segment_address;

  is_pe_header_valid = check_pe_header();
  if (CONCAT31(unused_var, is_pe_header_valid) == 0) {
    return 0;
  }
  segment_address = find_segment_address(0x400000, param_1 - 0x400000);
  return segment_address;
}

undefined4 get_pe_image_base(void)

{
  bool bVar1;
  undefined3 extraout_var;

  bVar1 = check_pe_header();
  if (CONCAT31(extraout_var, bVar1) == 0) {
    return 0;
  }
  return 8;
}

undefined4 get_image_base(void)

{
  bool is_pe_valid;
  undefined3 extra_value;

  is_pe_valid = check_pe_header();
  if (CONCAT31(extra_value, is_pe_valid) == 0) {
    return 0;
  }
  return 0x400000;
}

void SDL_ShowSimpleMessageBox(void)

{
  // WARNING: Could not recover jumptable at 0x00402b40. Too many branches
  // WARNING: Treating indirect jump as call
  SDL_ShowSimpleMessageBox();
  return;
}

uint reverse_count(undefined1 init)

{
  uint in_EAX;
  uint reversecounter;
  undefined4 * puVar1;

  puVar1 = (undefined4 * ) & init;
  reversecounter = in_EAX;
  if (0xfff < in_EAX) {
    do {
      puVar1 = puVar1 + -0x400;
      * puVar1 = * puVar1;
      reversecounter = reversecounter - 0x1000;
    } while (0x1000 < reversecounter);
  }
  *(undefined4 * )((int) puVar1 - reversecounter) = * (undefined4 * )((int) puVar1 - reversecounter);
  return in_EAX;
}

// WARNING: Unable to track spacebase fully for stack

char * __cdecl process_locale_string(char * param_1)

{
  short sVar1;
  char * locale_;
  size_t sVar2;
  uint reversed_count;
  undefined4 extraout_EDX;
  short * psVar3;
  undefined4 uStackY_40;
  undefined init;
  undefined array7[7];
  undefined * local_28;
  size_t wide_chars;
  short * short_array_index2;
  int inverted_reversed_count;
  short * short_array_index;

  uStackY_40 = 0x402ba0;
  locale_ = setlocale(2, (char * ) 0);
  if (locale_ != (char * ) 0x0) {
    uStackY_40 = 0x402bae;
    locale_ = _strdup(locale_);
  }
  uStackY_40 = 0x402bc4;
  setlocale(2, "");
  if ((param_1 != (char * ) 0x0) && ( * param_1 != '\0')) {
    init = 0;
    uStackY_40 = 0x402c5b;
    local_28 = & stack0xffffffc4;
    mbstowcs((wchar_t * ) 0x0, param_1, 0);
    uStackY_40 = 0x402c69;
    reversed_count = reverse_count(init);
    inverted_reversed_count = -reversed_count;
    short_array_index = (short * )(((uint)(array7 + inverted_reversed_count) >> 1) * 2);
    *(undefined4 * )( & stack0xffffffcc + inverted_reversed_count) = extraout_EDX;
    *(char ** )( & stack0xffffffc8 + inverted_reversed_count) = param_1;
    short_array_index2 = short_array_index;
    *(short ** )( & stack0xffffffc4 + inverted_reversed_count) = short_array_index;
    *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402c87;
    wide_chars = mbstowcs( * (wchar_t ** )( & stack0xffffffc4 + inverted_reversed_count),
      *(char ** )( & stack0xffffffc8 + inverted_reversed_count),
      *(size_t * )( & stack0xffffffcc + inverted_reversed_count));
    short_array_index = short_array_index2;
    if ((1 < wide_chars) &&
      (short_array_index = short_array_index2 + 2,
        *(short * )(((uint)(array7 + inverted_reversed_count) >> 1) * 2 + 2) != 0x3a)) {
      short_array_index = short_array_index2;
    }
    short_array_index2[wide_chars] = 0;
    sVar1 = * short_array_index;
    psVar3 = short_array_index;
    if (sVar1 != 0) {
      do {
        if (sVar1 == 0x5c) {
          sVar1 = * short_array_index;
          if (sVar1 != 0x5c) goto LAB_00402cef;
          do {
            do {
              short_array_index = short_array_index + 1;
              LAB_00402ce6:
                sVar1 = * short_array_index;
            } while (sVar1 == 0x5c);
            LAB_00402cef:
          } while (sVar1 == 0x2f);
          if (sVar1 == 0) {
            while (psVar3 < short_array_index) {
              short_array_index = short_array_index + -1;
              if (( * short_array_index != 0x2f) && ( * short_array_index != 0x5c)) break;
              * short_array_index = 0;
            }
            goto LAB_00402cc6;
          }
          sVar1 = short_array_index[1];
          psVar3 = short_array_index;
        } else {
          if (sVar1 == 0x2f) goto LAB_00402ce6;
          LAB_00402cc6:
            sVar1 = short_array_index[1];
        }
        if (sVar1 == 0) {
          if ( * psVar3 == 0) {
            *(undefined4 * )( & stack0xffffffcc + inverted_reversed_count) = 0;
            *(undefined ** )( & stack0xffffffc8 + inverted_reversed_count) = & DAT_00404316;
            *(undefined4 * )( & stack0xffffffc4 + inverted_reversed_count) = 0;
            *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402d32;
            sVar2 = wcstombs( * (char ** )( & stack0xffffffc4 + inverted_reversed_count),
              *(wchar_t ** )( & stack0xffffffc8 + inverted_reversed_count),
              *(size_t * )( & stack0xffffffcc + inverted_reversed_count));
            *(size_t * )( & stack0xffffffc8 + inverted_reversed_count) = sVar2 + 1;
            *(char ** )( & stack0xffffffc4 + inverted_reversed_count) = DAT_004053c4;
            *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402d46;
            param_1 = (char * ) realloc( * (void ** )( & stack0xffffffc4 + inverted_reversed_count),
              *(size_t * )( & stack0xffffffc8 + inverted_reversed_count));
            *(size_t * )( & stack0xffffffcc + inverted_reversed_count) = sVar2 + 1;
            *(undefined ** )( & stack0xffffffc8 + inverted_reversed_count) = & DAT_00404316;
            *(char ** )( & stack0xffffffc4 + inverted_reversed_count) = param_1;
            *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402d61;
            DAT_004053c4 = param_1;
            wcstombs( * (char ** )( & stack0xffffffc4 + inverted_reversed_count),
              *(wchar_t ** )( & stack0xffffffc8 + inverted_reversed_count),
              *(size_t * )( & stack0xffffffcc + inverted_reversed_count));
          } else {
            *(size_t * )( & stack0xffffffcc + inverted_reversed_count) = wide_chars;
            short_array_index = short_array_index2;
            *(char ** )( & stack0xffffffc4 + inverted_reversed_count) = param_1;
            *(short ** )( & stack0xffffffc8 + inverted_reversed_count) = short_array_index;
            *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402dc8;
            sVar2 = wcstombs( * (char ** )( & stack0xffffffc4 + inverted_reversed_count),
              *(wchar_t ** )( & stack0xffffffc8 + inverted_reversed_count),
              *(size_t * )( & stack0xffffffcc + inverted_reversed_count));
            if (sVar2 != 0xffffffff) {
              param_1[sVar2] = '\0';
            }
            * psVar3 = 0;
            *(undefined4 * )( & stack0xffffffcc + inverted_reversed_count) = 0;
            short_array_index = short_array_index2;
            *(undefined4 * )( & stack0xffffffc4 + inverted_reversed_count) = 0;
            *(short ** )( & stack0xffffffc8 + inverted_reversed_count) = short_array_index;
            *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402df1;
            sVar2 = wcstombs( * (char ** )( & stack0xffffffc4 + inverted_reversed_count),
              *(wchar_t ** )( & stack0xffffffc8 + inverted_reversed_count),
              *(size_t * )( & stack0xffffffcc + inverted_reversed_count));
            if (sVar2 != 0xffffffff) {
              param_1 = param_1 + sVar2;
            }
          }
          *(char ** )( & stack0xffffffc8 + inverted_reversed_count) = locale_;
          *(undefined4 * )( & stack0xffffffc4 + inverted_reversed_count) = 2;
          *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402d71;
          setlocale( * (int * )( & stack0xffffffc4 + inverted_reversed_count),
            *(char ** )( & stack0xffffffc8 + inverted_reversed_count));
          *(char ** )( & stack0xffffffc4 + inverted_reversed_count) = locale_;
          *(undefined4 * )((int) & uStackY_40 + inverted_reversed_count) = 0x402d79;
          free( * (void ** )( & stack0xffffffc4 + inverted_reversed_count));
          return param_1;
        }
        short_array_index = short_array_index + 1;
      } while (true);
    }
  }
  uStackY_40 = 0x402be9;
  sVar2 = wcstombs((char * ) 0x0, L ".", 0);
  uStackY_40 = 0x402bfd;
  DAT_004053c4 = (char * ) realloc(DAT_004053c4, sVar2 + 1);
  uStackY_40 = 0x402c16;
  wcstombs(DAT_004053c4, L ".", sVar2 + 1);
  uStackY_40 = 0x402c26;
  setlocale(2, locale_);
  uStackY_40 = 0x402c2e;
  free(locale_);
  return DAT_004053c4;
}

void __cdecl __set_app_type(int param_1)

{
  // WARNING: Could not recover jumptable at 0x00402e00. Too many branches
  // WARNING: Treating indirect jump as call
  __set_app_type(param_1);
  return;
}

_invalid_parameter_handler __cdecl
_set_invalid_parameter_handler(_invalid_parameter_handler _Handler)

{
  _invalid_parameter_handler p_Var1;

  // WARNING: Could not recover jumptable at 0x00402e10. Too many branches
  // WARNING: Treating indirect jump as call
  p_Var1 = _set_invalid_parameter_handler(_Handler);
  return p_Var1;
}

void * __cdecl malloc(size_t _Size)

{
  void * pvVar1;

  // WARNING: Could not recover jumptable at 0x00402e18. Too many branches
  // WARNING: Treating indirect jump as call
  pvVar1 = malloc(_Size);
  return pvVar1;
}

size_t __cdecl strlen(char * _Str)

{
  size_t sVar1;

  // WARNING: Could not recover jumptable at 0x00402e20. Too many branches
  // WARNING: Treating indirect jump as call
  sVar1 = strlen(_Str);
  return sVar1;
}

void * __cdecl memcpy(void * _Dst, void * _Src, size_t _Size)

{
  void * pvVar1;

  // WARNING: Could not recover jumptable at 0x00402e28. Too many branches
  // WARNING: Treating indirect jump as call
  pvVar1 = memcpy(_Dst, _Src, _Size);
  return pvVar1;
}

void __cdecl _cexit(void)

{
  // WARNING: Could not recover jumptable at 0x00402e30. Too many branches
  // WARNING: Treating indirect jump as call
  _cexit();
  return;
}

void __cdecl _amsg_exit(int param_1)

{
  // WARNING: Could not recover jumptable at 0x00402e38. Too many branches
  // WARNING: Treating indirect jump as call
  _amsg_exit(param_1);
  return;
}

void _initterm(void)

{
  // WARNING: Could not recover jumptable at 0x00402e40. Too many branches
  // WARNING: Treating indirect jump as call
  _initterm();
  return;
}

void __cdecl exit(int _Code)

{
  // WARNING: Could not recover jumptable at 0x00402e48. Too many branches
  // WARNING: Subroutine does not return
  // WARNING: Treating indirect jump as call
  exit(_Code);
  return;
}

void * __cdecl calloc(size_t _Count, size_t _Size)

{
  void * pvVar1;

  // WARNING: Could not recover jumptable at 0x00402e50. Too many branches
  // WARNING: Treating indirect jump as call
  pvVar1 = calloc(_Count, _Size);
  return pvVar1;
}

FILE * __cdecl fopen(char * _Filename, char * _Mode)

{
  FILE * pFVar1;

  // WARNING: Could not recover jumptable at 0x00402e58. Too many branches
  // WARNING: Treating indirect jump as call
  pFVar1 = fopen(_Filename, _Mode);
  return pFVar1;
}

int __cdecl strcmp(char * _Str1, char * _Str2)

{
  int iVar1;

  // WARNING: Could not recover jumptable at 0x00402e60. Too many branches
  // WARNING: Treating indirect jump as call
  iVar1 = strcmp(_Str1, _Str2);
  return iVar1;
}

void __cdecl _lock(int _File)

{
  // WARNING: Could not recover jumptable at 0x00402e68. Too many branches
  // WARNING: Treating indirect jump as call
  _lock(_File);
  return;
}

void __dllonexit(void)

{
  // WARNING: Could not recover jumptable at 0x00402e70. Too many branches
  // WARNING: Treating indirect jump as call
  __dllonexit();
  return;
}

void __cdecl _unlock(int _File)

{
  // WARNING: Could not recover jumptable at 0x00402e78. Too many branches
  // WARNING: Treating indirect jump as call
  _unlock(_File);
  return;
}

// WARNING: Unknown calling convention -- yet parameter storage is locked

void signal(int param_1)

{
  // WARNING: Could not recover jumptable at 0x00402e80. Too many branches
  // WARNING: Treating indirect jump as call
  signal(param_1);
  return;
}

void __setusermatherr(void)

{
  // WARNING: Could not recover jumptable at 0x00402e88. Too many branches
  // WARNING: Treating indirect jump as call
  __setusermatherr();
  return;
}

int __cdecl fprintf(FILE * _File, char * _Format, ...)

{
  int iVar1;

  // WARNING: Could not recover jumptable at 0x00402e90. Too many branches
  // WARNING: Treating indirect jump as call
  iVar1 = fprintf(_File, _Format);
  return iVar1;
}

size_t __cdecl fwrite(void * _Str, size_t _Size, size_t _Count, FILE * _File)

{
  size_t sVar1;

  // WARNING: Could not recover jumptable at 0x00402e98. Too many branches
  // WARNING: Treating indirect jump as call
  sVar1 = fwrite(_Str, _Size, _Count, _File);
  return sVar1;
}

int __cdecl vfprintf(FILE * _File, char * _Format, va_list _ArgList)

{
  int iVar1;

  // WARNING: Could not recover jumptable at 0x00402ea0. Too many branches
  // WARNING: Treating indirect jump as call
  iVar1 = vfprintf(_File, _Format, _ArgList);
  return iVar1;
}

void __cdecl abort(void)

{
  // WARNING: Could not recover jumptable at 0x00402ea8. Too many branches
  // WARNING: Subroutine does not return
  // WARNING: Treating indirect jump as call
  abort();
  return;
}

void __cdecl free(void * _Memory)

{
  // WARNING: Could not recover jumptable at 0x00402eb0. Too many branches
  // WARNING: Treating indirect jump as call
  free(_Memory);
  return;
}

char * __cdecl setlocale(int _Category, char * _Locale)

{
  char * pcVar1;

  // WARNING: Could not recover jumptable at 0x00402ec0. Too many branches
  // WARNING: Treating indirect jump as call
  pcVar1 = setlocale(_Category, _Locale);
  return pcVar1;
}

char * __cdecl _strdup(char * _Src)

{
  char * pcVar1;

  // WARNING: Could not recover jumptable at 0x00402ec8. Too many branches
  // WARNING: Treating indirect jump as call
  pcVar1 = _strdup(_Src);
  return pcVar1;
}

size_t __cdecl wcstombs(char * _Dest, wchar_t * _Source, size_t _MaxCount)

{
  size_t sVar1;

  // WARNING: Could not recover jumptable at 0x00402ed0. Too many branches
  // WARNING: Treating indirect jump as call
  sVar1 = wcstombs(_Dest, _Source, _MaxCount);
  return sVar1;
}

void * __cdecl realloc(void * _Memory, size_t _NewSize)

{
  void * pvVar1;

  // WARNING: Could not recover jumptable at 0x00402ed8. Too many branches
  // WARNING: Treating indirect jump as call
  pvVar1 = realloc(_Memory, _NewSize);
  return pvVar1;
}

size_t __cdecl mbstowcs(wchar_t * _Dest, char * _Source, size_t _MaxCount)

{
  size_t sVar1;

  // WARNING: Could not recover jumptable at 0x00402ee0. Too many branches
  // WARNING: Treating indirect jump as call
  sVar1 = mbstowcs(_Dest, _Source, _MaxCount);
  return sVar1;
}

void execute_initialization_steps(undefined1 param_1)

{
  dll_sequences();
  initialize_python_environment();
  return;
}
