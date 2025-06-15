# -*- coding: utf-8 -*-
import atheris
import sys
import struct  # IMPORTANTE: struct é usado no except, precisa ser importado

# Tenta importar o parser do arquivo que fizemos upload
try:
    # Certifique-se de que binary_parser.py está no diretório raiz do Colab
    with atheris.instrument_imports():
        from binary_parser import parse_packet, ParsingError
        
except ImportError:
    print("Erro: Não foi possível encontrar binary_parser.py.")
    print("Certifique-se de que você fez o upload do arquivo para o Colab.")
    sys.exit(1)

# Função alvo para o Fuzzing (obrigatória pelo Atheris)
def TestOneInput(data):
    """
    Função que será chamada pelo fuzzer com dados gerados.

    Args:
        data: Um objeto bytes fornecido pelo fuzzer.
    """
    try:
        # Chama a função que queremos testar (o parser)
        parse_packet(data)
    except ParsingError:
        # Erros de parsing esperados (definidos em ParsingError) são ignorados.
        # O fuzzer busca por exceções NÃO esperadas (IndexError, TypeError, etc.)
        # ou crashes mais sérios.
        pass
    except (IndexError, struct.error, TypeError, OverflowError) as e:
        # Captura exceções específicas que indicam bugs potenciais e relança
        # para que o Atheris as detecte como falhas.
        print(f"\n>>> Exceção Inesperada Encontrada: {type(e).__name__}: {e}")
        print(f">>> Input Causador (hex): {data.hex()}")
        raise e
    # Qualquer outra exceção não capturada aqui também será considerada um crash pelo Atheris.

# Configuração e Inicialização do Atheris
# sys.argv é necessário para o Atheris processar seus próprios argumentos
import os

# Define um diretório para armazenar os inputs do corpus
corpus_dir = "corpus"
os.makedirs(corpus_dir, exist_ok=True)

# Insere o diretório de corpus nos argumentos
sys.argv.append(corpus_dir)

atheris.Setup(sys.argv, TestOneInput)


# Inicia o processo de fuzzing
print("Iniciando Fuzzing com Atheris... (Pressione Ctrl+C para parar)")
atheris.Fuzz()
print("Fuzzing concluído ou interrompido.")
