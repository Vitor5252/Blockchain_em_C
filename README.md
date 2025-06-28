# 🔗 Blockchain em Linguagem C

Este projeto implementa uma **blockchain simplificada** em linguagem C, com funcionalidades de mineração, criação de blocos, prova de trabalho e simulação de ataques. Ideal para fins didáticos e experimentação de conceitos básicos da tecnologia blockchain.

## 🎯 Objetivo

Demonstrar o funcionamento básico de uma blockchain:

- Criação de blocos com dados
- Encadeamento via hash SHA-256
- Prova de trabalho (Proof of Work)
- Validação da cadeia
- Estrutura de árvore de Merkle para as transações
- Simulação de ataque à integridade da cadeia

## ⚙️ Tecnologias Utilizadas

- Linguagem C
- SHA-256 para hash dos blocos
- Estrutura de árvore de Merkle
- Interface de linha de comando (menu interativo)

## 🧩 Funcionalidades

- Criar novo bloco com transações aleatórias
- Verificar integridade da blockchain
- Exibir a cadeia completa
- Calcular e exibir a raiz de Merkle
- Simular ataques e corrigi-los
- Salvar e carregar a cadeia de blocos

## ▶️ Como Executar

1. Compile o programa:
   ```bash
   gcc blockchain.c -o blockchain
