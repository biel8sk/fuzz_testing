# Fuzzing com Atheris em Parser Binário

> Projeto acadêmico de teste de software com Fuzz Testing orientado por cobertura utilizando o [Atheris](https://github.com/google/atheris), fuzzer nativo da Google para Python.

---

## Sobre o Projeto

Este projeto implementa um parser de protocolo binário com falhas propositalmente introduzidas para exploração com fuzz testing. Utiliza a biblioteca `atheris` para detectar exceções inesperadas através de mutações inteligentes baseadas em cobertura de código.

---

## Estrutura de Arquivos

```plaintext
/
├── binary_parser.py        # Parser com bugs intencionais
├── fuzzer.py               # Fuzzer configurado com Atheris
├── crash-*                 # Arquivos gerados em falhas (salvos automaticamente)
├── slow-unit-*             # Entradas lentas detectadas pelo fuzzer
├── corpus/                 # Diretório de corpus persistente
├── README.md               # Este documento
```
---
### Projeto testado na versão 3.10 do python
