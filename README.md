# Custom-Indirect-Syscall-Loader
Loader em C puro e Assembly x64 com foco em evasão de EDR. Implementa PEB walking via GS:[0x60], API hashing com djb2, recuperação dinâmica de SSN com Halo's Gate contra hooks na ntdll, execução via indirect syscalls, alocação estrita RW para RX e re-criptografia do payload em memória para dificultar análise forense de dumps de RAM.
