#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "sha256.h"

#define DIFICULDADE 4  // Número de zeros iniciais no hash do bloco

// Estrutura do Bloco
typedef struct {
    int index; //necessario para achar o bloco
    char hash[65];
    char hash_anterior[65];
    unsigned int nonce;
    char raiz_merkle[65];
    char **transacoes; 
    int cont_transacoes;
    time_t timestamp;
} Block;

// Estrutura da Blockchain
typedef struct {
    Block **blocks;
    int cont_block;
} Blockchain;

// Função para calcular SHA-256, atraves do sha256.h
void calculaSHA256(const char *input, char *output) {
    unsigned char hash[SHA256_SIZE_BYTES];
    sha256((unsigned char *)input, strlen(input), hash);
    for (int i = 0; i < SHA256_SIZE_BYTES; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]); //sprintf %02x necessario para formatar numeros hexadecimais
    }
    output[64] = '\0';
}

// Função para calcular a Merkle Root
char *calculaRaizMerkle(char **transacoes, int cont_transacoes) {
    if (cont_transacoes == 0) return strdup(""); //strdup faz uma copia da string original em memoria dinamica
    char *hashes = (char *)malloc(cont_transacoes * sizeof(char *)); //alocacao de memoria para os hashes
    for (int i = 0; i < cont_transacoes; i++) {
        hashes[i] = (char *)malloc(65);
        calculaSHA256(transacoes[i], hashes[i]);
    }
    int count = cont_transacoes;
    while (count > 1) {
        int novo_cont = (count + 1) / 2;
        char *nova_hash = (char *)malloc(novo_cont * sizeof(char *));
        for (int i = 0; i < novo_cont; i++) {
            nova_hash[i] = (char *)malloc(65);
            char combined[130] = {0}; //combined: concatena strings
            strncpy(combined, hashes[i * 2], 65); //realiza a cópia de uma string para outra, mas com uma limitação de no máximo 65 caracteres
            if (i * 2 + 1 < count) strncat(combined, hashes[i * 2 + 1], 65);
            calculaSHA256(combined, nova_hash[i]);
        }
        for (int i = 0; i < count; i++) free(hashes[i]);
        free(hashes);
        hashes = nova_hash;
        count = novo_cont;
    }
    char *raizMerkle = strdup(hashes[0]);
    free(hashes[0]);
    free(hashes);
    return raizMerkle;
}

// Função para criar um bloco
Block* criar_block(int index, char *hash_anterior, char **transacoes, int cont_transacoes) {
    Block *block = (Block *)malloc(sizeof(Block));
    block->index = index;
    strncpy(block->hash_anterior, hash_anterior, 64);
    block->hash_anterior[64] = '\0';
    block->nonce = 0;
    block->timestamp = time(NULL);
    block->cont_transacoes = cont_transacoes;
    block->transacoes = (char **)malloc(cont_transacoes * sizeof(char *));
    for (int i = 0; i < cont_transacoes; i++) {
        block->transacoes[i] = strdup(transacoes[i]);
    }
    char *raizMerkle = calculaRaizMerkle(transacoes, cont_transacoes);
    strncpy(block->raiz_merkle, raizMerkle, 64);
    block->raiz_merkle[64] = '\0';
    free(raizMerkle);
    return block;
}

// Função para calcular o hash do bloco
void calcula_blockHash(Block *block) {
    char input[512];
    snprintf(input, sizeof(input), "%d%s%s%u%ld", block->index, block->hash_anterior, block->raiz_merkle, block->nonce, block->timestamp); //formata uma string e armazená-la em um buffer, garantindo que o tamanho máximo especificado do buffer não seja excedido.
    calculaSHA256(input, block->hash);
}

// Função de mineração (Proof of Work)
void Minerador(Block *block, int dificuldade) {
    char target[65] = {0};
    memset(target, '0', dificuldade); //preenche o bloco com zeros repetindo "dificuldade" vezes
    target[dificuldade] = '\0';
    do {
        block->nonce++;
        calcula_blockHash(block);
    } while (strncmp(block->hash, target, dificuldade) != 0);
}

// Função para imprimir um bloco
void printBlock(Block *block) {
    printf("Bloco %d:\n", block->index);
    printf("Hash: %s\n", block->hash);
    printf("Hash Anterior: %s\n", block->hash_anterior);
    printf("Nonce: %u\n", block->nonce);
    printf("Timestamp: %ld\n", block->timestamp);
    printf("Transacoes:\n");
    for (int i = 0; i < block->cont_transacoes; i++) {
        printf("- %s\n", block->transacoes[i]);
    }
    printf("\n");
}

// Função para verificar Proof of Inclusion
int verificaTransacao(Block *block, const char *transacao) {
    char transHash[65];
    calculaSHA256(transacao, transHash);
    return (strstr(block->raiz_merkle, transHash) != NULL);
}

// Função para simular um ataque ( Bloco criador é imutável, pois é o bloco estruturador dos outros)
void simulaAtaque(Blockchain *blockchain) {
    int bloco_alvo;
    printf("\n\n");
    printf("\n--- Simulacao de Ataque ---\n");
    printf("Digite o indice do bloco a ser atacado: ");
    scanf("%d", &bloco_alvo);

    // Verifica se o bloco existe 
    if (bloco_alvo <= 0 || bloco_alvo >= blockchain->cont_block) {
        printf("Bloco invalido! O indice deve estar entre 0 e %d.\n", blockchain->cont_block - 1);
        printf("--- Ataque Finalizado ---\n\n\n");
        return;
    }

    printf("Modificando transacao do bloco %d...\n", bloco_alvo);
    strcpy(blockchain->blocks[bloco_alvo]->transacoes[1], "Ataque: transacao Modificada");
    calcula_blockHash(blockchain->blocks[bloco_alvo]);
    
    printf("Bloco [%d] apos o ataque:\n", blockchain->blocks[bloco_alvo]->index); //bloco original antes do ataque
    printBlock(blockchain->blocks[bloco_alvo]);
    
    printf("\nAjustando hashes dos blocos subsequentes...\n");  //bloco depois do ataque de hash
    for (int i = bloco_alvo; i < blockchain->cont_block; i++) {
        strncpy(blockchain->blocks[i]->hash_anterior, blockchain->blocks[i - 1]->hash, 64);
        Minerador(blockchain->blocks[i], DIFICULDADE);
    }
    
    printf("Hashes ajustados:\n");
    for (int i = 0; i < blockchain->cont_block; i++) {
        printBlock(blockchain->blocks[i]);
    }
    printf("--- Ataque Finalizado ---\n\n\n");
}


// Menu interativo
void menu(Blockchain *blockchain) {
    int opcao;
    do {
        printf("\n---    MENU  ---\n");
        printf("1. Inserir novas transacao em um bloco\n");
        printf("2. Minerar (adicionar) um bloco a blockchain\n");
        printf("3. Exibir todos os blocos\n");
        printf("4. Verificar se uma transacao esta em um bloco\n");
        printf("5. Simular ataque\n");
        printf("6. Sair\n");
        printf("Escolha uma opcao: ");
        scanf("%d", &opcao);

        switch (opcao) {
            case 1: {
                int num_transacoes;
                printf("\n\nQuantas transacao deseja inserir(P/ o mesmo bloco)? "); //aqui pode inserir N transacoes para um mesmo bloco
                scanf("%d", &num_transacoes);

                char *transacoes = (char *)malloc(num_transacoes * sizeof(char *));
                for (int i = 0; i < num_transacoes; i++) {
                    transacoes[i] = (char *)malloc(256 * sizeof(char)); //aqui ha a alocação das transacoes na memória
                    printf("transacao %d: ", i + 1);
                    getchar(); // Consumir o caractere '\n' pendente
                    fgets(transacoes[i], 256, stdin);
                    transacoes[i][strcspn(transacoes[i], "\n")] = '\0'; // Remover o '\n' do final
                }
                Block *ultimoBloco = blockchain->blocks[blockchain->cont_block - 1];
                Block *novoBloco = criar_block(blockchain->cont_block, ultimoBloco->hash, transacoes, num_transacoes);

                for (int i = 0; i < num_transacoes; i++){ 
                    free(transacoes[i]);
                }
                free(transacoes);

                Minerador(novoBloco, DIFICULDADE);
                blockchain->blocks = (Block **)realloc(blockchain->blocks, (blockchain->cont_block + 1) * sizeof(Block *));
                blockchain->blocks[blockchain->cont_block] = novoBloco;
                blockchain->cont_block++;
                printf("Novo bloco adicionado com sucesso!\n");
                break;
            }
            case 2: {
                // Nesse case, há a criação automática de um bloco com transações genéricas,
                // mas com todos os outros requisitos de hash
                printf("\n\nAdicionando um bloco...\n");
                
                char *transacoes[] = {"transacao automatica 1", "transacao automatica 2"};
                Block *ultimoBloco = blockchain->blocks[blockchain->cont_block - 1];
                Block *novoBloco = criar_block(blockchain->cont_block, ultimoBloco->hash, transacoes, 2);
                
                Minerador(novoBloco, DIFICULDADE);
                
                blockchain->blocks = (Block **)realloc(blockchain->blocks, (blockchain->cont_block + 1) * sizeof(Block *));
                blockchain->blocks[blockchain->cont_block] = novoBloco;
                blockchain->cont_block++;
                
                printf("Bloco minerado e adicionado com sucesso!\n");
                break;
            }

            case 3: {
                printf("\n\nExibindo blockchain:\n");
                for (int i = 0; i < blockchain->cont_block; i++) {
                    printBlock(blockchain->blocks[i]);
                }
                break;
            }
            case 4: {
                int blocoIndex;
                char transacao[256];
                printf("\n\nDigite o indice do bloco: ");
                scanf("%d", &blocoIndex);
                if (blocoIndex < 0 || blocoIndex >= blockchain->cont_block) {
                    printf("Bloco invalido!\n");
                    break;
                }
                printf("\n\nDigite a transacao a ser verificada: ");
                getchar(); // Consumir o caractere '\n' pendente
                fgets(transacao, 256, stdin);
                transacao[strcspn(transacao, "\n")] = '\0'; // Remover o '\n' do final
                if (verificaTransacao(blockchain->blocks[blocoIndex], transacao)) {
                    printf("A transacao esta no bloco %d!\n", blocoIndex);
                } else {
                    printf("A transacao NAO esta no bloco %d!\n", blocoIndex);
                }
                break;
            }
            case 5: {
                simulaAtaque(blockchain);
                break;
            }
            case 6: {
                printf("Saindo do programa...\n");
                break;
            }
            default: {
                printf("Opção inválida!\n");
                break;
            }
        }
    } while (opcao != 6);
}

// Função principal
int main() {
    Blockchain *blockchain = (Blockchain *)malloc(sizeof(Blockchain));
    blockchain->blocks = NULL;
    blockchain->cont_block = 0;

    // A criacao do Bloco Criador serve para a estruturacao dos outros blocos, pois ele nao tem Hash anterior
    //alem disso, é imutável, garantindo que a blockchain sempre tenha um ponto de partida válido e confiável(um ponto de referencia).
    char *criador_transacoes[] = {"Bloco criador"};
    Block *criador_Block = criar_block(0, "0", criador_transacoes, 1);
    Minerador(criador_Block, DIFICULDADE);
    blockchain->blocks = (Block **)malloc(sizeof(Block *));
    blockchain->blocks[0] = criador_Block;
    blockchain->cont_block = 1;

    // Executar menu interativo
    menu(blockchain);

    return 0;
}