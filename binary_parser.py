# -*- coding: utf-8 -*-
"""
Parser para um protocolo binário simples (com bugs intencionais para fuzzing).

Formato do Pacote:
- Magic Number (2 bytes): 0xCAFE (Big Endian)
- Packet Type (1 byte): 0x01 (DATA), 0x02 (CMD), 0x03 (ACK)
- Payload Length (2 bytes): Comprimento do payload (Big Endian, uint16)
- Payload (variável): Dados (bytes)
- Checksum (1 byte): XOR de todos os bytes anteriores
"""

import struct

MAGIC_NUMBER = 0xCAFE
MAX_PAYLOAD_SIZE = 1024 # Limite artificial para simular restrições

class ParsingError(Exception):
    """Exceção customizada para erros de parsing."""
    pass

def calculate_checksum(data_bytes):
    """Calcula um checksum XOR simples."""
    checksum = 0
    for byte in data_bytes:
        checksum ^= byte
    return checksum

def parse_packet(data: bytes):
    """Faz o parsing de um pacote binário.

    Args:
        data: Os bytes brutos do pacote.

    Returns:
        Um dicionário com os campos do pacote parseado.

    Raises:
        ParsingError: Se ocorrer um erro durante o parsing.
        IndexError: Se os dados forem insuficientes (pode ser explorado por fuzzing).
        struct.error: Se os dados não puderem ser desempacotados (pode ser explorado).
    """
    if not isinstance(data, bytes):
        raise TypeError("Entrada deve ser bytes")

    # --- Vulnerabilidade Potencial 1: Verificação de tamanho insuficiente --- 
    # Faltava verificar se há bytes suficientes para o cabeçalho completo + checksum
    # if len(data) < 6: # Mínimo para cabeçalho (2+1+2) + checksum (1)
    #     raise ParsingError(f"Dados insuficientes para cabeçalho e checksum: {len(data)} bytes")
    # Correção parcial (ainda vulnerável se o payload_len for grande):
    if len(data) < 5: # Mínimo para cabeçalho (2+1+2)
         raise ParsingError(f"Dados insuficientes para cabeçalho: {len(data)} bytes")

    # 1. Verificar Magic Number
    magic = struct.unpack(">H", data[0:2])[0] # Big Endian Short
    if magic != MAGIC_NUMBER:
        raise ParsingError(f"Magic number inválido: {magic:#04x}")

    # 2. Obter Tipo do Pacote
    packet_type = data[2]
    if packet_type not in [0x01, 0x02, 0x03]:
        raise ParsingError(f"Tipo de pacote desconhecido: {packet_type:#02x}")

    # 3. Obter Comprimento do Payload
    payload_len = struct.unpack(">H", data[3:5])[0] # Big Endian Short

    # --- Vulnerabilidade Potencial 2: Verificação de limite inadequada --- 
    # Permitir payload_len > MAX_PAYLOAD_SIZE pode levar a problemas
    # if payload_len > MAX_PAYLOAD_SIZE:
    #     raise ParsingError(f"Payload excede o tamanho máximo: {payload_len} > {MAX_PAYLOAD_SIZE}")
    # Bug intencional: A verificação está comentada!

    # 4. Verificar tamanho total esperado vs. tamanho real
    expected_total_len = 2 + 1 + 2 + payload_len + 1 # Cabeçalho + Payload + Checksum
    if len(data) < expected_total_len:
         # --- Vulnerabilidade Potencial 3: Mensagem de erro pode vazar informação --- 
         # A mensagem revela o tamanho esperado, o que pode ser útil para um atacante.
         raise ParsingError(f"Dados insuficientes para payload e checksum. Esperado: {expected_total_len}, Recebido: {len(data)}")

    # 5. Extrair Payload
    payload_start = 5
    payload_end = payload_start + payload_len
    payload = data[payload_start:payload_end]

    # --- Vulnerabilidade Potencial 4: Off-by-one na leitura? --- 
    # Se payload_end for calculado incorretamente, pode ler fora dos limites.
    # Neste caso, o slice do Python protege, mas a lógica poderia estar errada.

    # 6. Verificar Checksum
    expected_checksum = calculate_checksum(data[:payload_end])
    actual_checksum = data[payload_end] # O byte *após* o payload

    if expected_checksum != actual_checksum:
        raise ParsingError(f"Checksum inválido. Esperado: {expected_checksum:#02x}, Recebido: {actual_checksum:#02x}")

    # 7. Lógica específica do tipo (Bug intencional)
    result = {
        "magic": magic,
        "type": packet_type,
        "payload_len": payload_len,
        "payload": payload,
        "checksum": actual_checksum
    }

    # --- Vulnerabilidade Potencial 5: Lógica falha baseada no tipo --- 
    if packet_type == 0x02: # CMD
        # Supõe que o payload de CMD sempre tem pelo menos 1 byte para o código do comando
        # Se payload_len for 0, isso causará um IndexError!
        if payload_len == 0 or len(payload) < 1:
            raise ParsingError("Tamanho de pacote insuficiente")

        command_code = payload[0]
        result["command_code"] = command_code
        # Poderia haver mais lógica aqui que falha com payload vazio ou malformado

    return result

# Exemplo de uso (não faz parte do fuzzing target diretamente)
if __name__ == "__main__":
    # Pacote Válido
    valid_payload = b"Hello Fuzzing!"
    valid_len = len(valid_payload)
    header = struct.pack(">HBH", MAGIC_NUMBER, 0x01, valid_len)
    packet_data_no_checksum = header + valid_payload
    checksum = calculate_checksum(packet_data_no_checksum)
    valid_packet = packet_data_no_checksum + bytes([checksum])

    print(f"Pacote Válido ({len(valid_packet)} bytes): {valid_packet.hex()}")
    try:
        parsed = parse_packet(valid_packet)
        print("Parseado com sucesso:", parsed)
    except Exception as e:
        print("Erro ao parsear pacote válido:", e)

    print("---")

    # Pacote Inválido (Checksum errado)
    invalid_packet_checksum = valid_packet[:-1] + bytes([(checksum + 1) % 256])
    print(f"Pacote Inválido (Checksum): {invalid_packet_checksum.hex()}")
    try:
        parse_packet(invalid_packet_checksum)
    except ParsingError as e:
        print("Erro esperado (Checksum):", e)
    except Exception as e:
        print("Erro inesperado (Checksum):", e)

    print("---")

    # Pacote Inválido (Tipo errado)
    invalid_packet_type = struct.pack(">HBH", MAGIC_NUMBER, 0x05, valid_len) + valid_payload
    checksum_type = calculate_checksum(invalid_packet_type)
    invalid_packet_type += bytes([checksum_type])
    print(f"Pacote Inválido (Tipo): {invalid_packet_type.hex()}")
    try:
        parse_packet(invalid_packet_type)
    except ParsingError as e:
        print("Erro esperado (Tipo):", e)
    except Exception as e:
        print("Erro inesperado (Tipo):", e)

    print("---")

    # Pacote Inválido (Curto)
    invalid_packet_short = b"\xCA\xFE\x01"
    print(f"Pacote Inválido (Curto): {invalid_packet_short.hex()}")
    try:
        parse_packet(invalid_packet_short)
    except ParsingError as e:
        print("Erro esperado (Curto):", e)
    except Exception as e:
        print("Erro inesperado (Curto):", e)

    print("---")

    # Pacote CMD com payload vazio (causa IndexError intencional)
    cmd_header = struct.pack(">HBH", MAGIC_NUMBER, 0x02, 0) # Payload Len = 0
    cmd_packet_no_checksum = cmd_header
    cmd_checksum = calculate_checksum(cmd_packet_no_checksum)
    cmd_packet_empty = cmd_packet_no_checksum + bytes([cmd_checksum])
    print(f"Pacote CMD Vazio: {cmd_packet_empty.hex()}")
    try:
        parse_packet(cmd_packet_empty)
    except IndexError as e:
         print("Erro esperado (CMD Vazio - IndexError):", e)
    except Exception as e:
        print("Erro inesperado (CMD Vazio):", e)

