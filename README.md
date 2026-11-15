# Custom Indirect Syscall Loader

---

## O Problema

Em um ambiente corporativo, muitas das vezes um EDR vai identificar a assinatura e os padrões comportamentais de ferramentas públicas, como um Cobalt Strike por exemplo. Um código único e feito exclusivamente tem uma assinatura própria e desconhecida, fazendo com que seja muito mais difícil de ser detectado.

Soluções de EDR como o CrowdStrike monitoram o processo inserindo hooks na memória, alterando os bytes de APIs da `ntdll.dll` e adicionando uma instrução de desvio (`JMP`). Com isso, quando chamamos uma função como `NtAllocateVirtualMemory`, o sistema de segurança é rapidamente alertado sobre quem chamou a função e para qual finalidade, tornando a chamada tradicional uma armadilha.

---

## Arquitetura da Solução

### 1. Independência de Runtime e Ocultação de Strings

* **Ponto de entrada independente:** Optei por não utilizar a função `main` tradicional, pois ela acaba colocando códigos e dependências adicionais no programa através da C Runtime. Como o objetivo é que o programa rode de forma independente de onde for executado, ele não possui chamadas para APIs que dependam de uma IAT (Import Address Table). O ponto de entrada foi redefinido diretamente para a função `pic_entry` sem bibliotecas padrão (`-nostdlib`).
* **API Hashing com djb2:** Utilizei API Hashing para fazer a comparação em vez de strings soltas no código. Se for colocada uma string em texto puro como `"NtAllocateVirtualMemory"`, qualquer EDR ou analista identificaria na hora a intenção do programa de alocar e injetar payloads. Com o hash, as strings são eliminadas do binário.

---

### 2. PEB Walking e Resolução da Export Table

O código utiliza o registrador de segmento `GS:[0x60]` para obter o endereço base do PEB sem chamar APIs do sistema. Dentro do PEB, acessamos a estrutura `LDR`, que nos leva a uma lista duplamente encadeada de módulos carregados. Utilizando os ponteiros `Flink` e `Blink`, navegamos por essa lista até obter o RVA do nome das DLLs. Aplicamos a função de hash no nome encontrado e comparamos com o hash pré-definido no código. Quando encontramos a `ntdll.dll`, capturamos o seu endereço base na memória.

Com a base da DLL, navegamos diretamente na Export Directory Table (`AddressOfNames`, `AddressOfFunctions` e `AddressOfNameOrdinals`) comparando os nomes das funções exportadas por hash até encontrar a função nativa necessária.

---

### 3. Evasão de Hooks com Halo's Gate

Para contornar os hooks do EDR, o código utiliza a lógica do Halo's Gate:

1. **Checagem de integridade:** Primeiro, a função `StubEhLimpo` verifica se a função alvo está com hook, comparando os seus primeiros bytes com o padrão legítimo do Windows.
2. **Definição de deslocamento:** Caso a função esteja com hook (com um `JMP` inserido pelo EDR), o código usa o índice atual da função na tabela de exportação e cria uma variável de distância (`delta`).
3. **Varredura de vizinhos:** Somamos e subtraímos esse delta para inspecionar as funções vizinhas na tabela de exportação e verificamos se elas estão limpas usando a mesma função `StubEhLimpo`.
4. **Cálculo do SSN:** Quando encontramos um vizinho limpo, lemos o SSN (System Service Number) dele e calculamos o SSN da nossa função alvo ajustando com o valor do delta. Se o vizinho imediato também estiver hookado, incrementamos o delta em loop até achar um vizinho íntegro.

---

### 4. Syscall Indireta

Uma syscall direta disparada a partir do próprio código executável é muito suspeita, pois processos comuns quase nunca executam instruções syscall fora da `ntdll.dll`. Os sensores de segurança monitoram a pilha de chamada e identificam essa anomalia. 

Por isso, o código faz uma **syscall indireta**: configuramos os registradores e pulamos para uma instrução syscall (`0F 05`) que reside fisicamente dentro da própria `ntdll.dll` legítima. Para o sistema operacional, a chamada ocorre exatamente como se estivesse usando as APIs do Windows normalmente.

---

### 5. Higiene de Memória e Ciclo de Execução

* **Cifragem prévia:** O payload é armazenado previamente criptografado no código com uma cifra XOR de chave rotativa.
* **Alocação restrita:** A alocação de memória é realizada inicialmente com permissão estrita de leitura e escrita (`PAGE_READWRITE`), pois processos normais quase nunca alocam memória executável e gravável ao mesmo tempo.
* **Descriptografia in-memory:** O payload criptografado é copiado para a memória alocada e descriptografado com o XOR diretamente na RAM.
* **Transição de permissão:** A permissão da página é alterada para execução e leitura (`PAGE_EXECUTE_READ`), reduzindo a visibilidade da área de memória.
* **Sincronização:** Criamos a thread apontando para o endereço do payload e usamos a rotina `AguardarObjeto` (`NtWaitForSingleObject`) para aguardar a execução ser concluída sem encerrar o processo antes da hora.
* **Anti-forense:** Após o término da execução, a permissão da página volta para escrita e o código é criptografado novamente na memória antes do encerramento, evitando que um dump forense de RAM exponha o payload em texto claro.
