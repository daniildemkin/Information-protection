import random
import struct

def generate_key(bits=64):
    """
    Генерация случайного 64-битного ключа
    
    Args:
        bits: Количество бит в ключе (по умолчанию 64)
        
    Returns:
        int: Случайный ключ
    """
    return random.getrandbits(bits)

def split_block(block):
    """
    Разделение 64-битного блока на две 32-битные половины
    
    Args:
        block: 64-битный блок данных
        
    Returns:
        tuple: (левая половина, правая половина)
    """
    # Сдвигаем вправо на 32 бита, чтобы получить левую половину
    left = (block >> 32) & 0xFFFFFFFF
    # Маскируем младшие 32 бита, чтобы получить правую половину
    right = block & 0xFFFFFFFF
    
    return left, right

def combine_halves(left, right):
    """
    Объединение двух 32-битных половин в один 64-битный блок
    
    Args:
        left: Левая 32-битная половина
        right: Правая 32-битная половина
        
    Returns:
        int: 64-битный блок
    """
    # Сдвигаем левую половину влево на 32 бита и объединяем с правой
    return (left << 32) | right

def feistel_function(half_block, round_key):
    """
    Функция Фейстеля для преобразования правой половины блока
    
    Args:
        half_block: 32-битная половина блока
        round_key: Ключ раунда
        
    Returns:
        int: Результат преобразования
    """
    # Простое преобразование с использованием XOR и циклического сдвига
    result = half_block ^ round_key
    # Циклический сдвиг вправо на 8 бит
    result = ((result >> 8) | (result << 24)) & 0xFFFFFFFF
    # Обратный циклический сдвиг влево на 3 бита
    result = ((result << 3) | (result >> 29)) & 0xFFFFFFFF
    # Еще один XOR с модифицированным ключом
    result = result ^ ((round_key << 5) & 0xFFFFFFFF)
    
    return result

def generate_round_keys(master_key, rounds=16):
    """
    Генерация ключей для каждого раунда шифрования
    
    Args:
        master_key: Основной 64-битный ключ
        rounds: Количество раундов
        
    Returns:
        list: Список ключей для каждого раунда
    """
    round_keys = []
    
    for i in range(rounds):
        # Создаем разные ключи для каждого раунда
        # путем циклического сдвига и XOR
        shifted_key = ((master_key << i) | (master_key >> (64 - i))) & 0xFFFFFFFFFFFFFFFF
        round_key = shifted_key ^ (i * 0x0123456789ABCDEF)
        # Берем только 32 бита для функции Фейстеля
        round_keys.append(round_key & 0xFFFFFFFF)
    
    return round_keys

def feistel_round(left, right, round_key):
    """
    Выполнение одного раунда шифрования сети Фейстеля
    
    Args:
        left: Левая 32-битная половина блока
        right: Правая 32-битная половина блока
        round_key: Ключ текущего раунда
        
    Returns:
        tuple: (новая левая половина, новая правая половина)
    """
    # Применяем функцию Фейстеля к правой половине
    f_result = feistel_function(right, round_key)
    
    # Новая левая половина - это старая правая половина
    new_left = right
    
    # Новая правая половина - это XOR старой левой половины и результата функции Фейстеля
    new_right = left ^ f_result
    
    return new_left, new_right

def encrypt_block(block, master_key, rounds=16):
    """
    Шифрование 64-битного блока данных с использованием сети Фейстеля
    
    Args:
        block: 64-битный блок данных
        master_key: 64-битный ключ шифрования
        rounds: Количество раундов шифрования
        
    Returns:
        int: Зашифрованный 64-битный блок
    """
    # Генерируем ключи для всех раундов
    round_keys = generate_round_keys(master_key, rounds)
    
    # Разделяем блок на две половины
    left, right = split_block(block)
    
    # Выполняем указанное количество раундов
    for i in range(rounds):
        left, right = feistel_round(left, right, round_keys[i])
    
    # Объединяем половины (с перестановкой: правая, левая)
    # Это особенность сети Фейстеля - финальная перестановка упрощает дешифрование
    return combine_halves(right, left)

def decrypt_block(block, master_key, rounds=16):
    """
    Расшифрование 64-битного блока данных с использованием сети Фейстеля
    
    Args:
        block: 64-битный блок зашифрованных данных
        master_key: 64-битный ключ шифрования
        rounds: Количество раундов шифрования
        
    Returns:
        int: Расшифрованный 64-битный блок
    """
    # Генерируем те же ключи, что и при шифровании
    round_keys = generate_round_keys(master_key, rounds)
    
    # Разделяем блок на две половины
    left, right = split_block(block)
    
    # Выполняем указанное количество раундов, используя ключи в обратном порядке
    for i in range(rounds - 1, -1, -1):
        left, right = feistel_round(left, right, round_keys[i])
    
    # Объединяем половины (с перестановкой: правая, левая)
    return combine_halves(right, left)

def text_to_blocks(text, block_size=8):
    """
    Преобразование текста в список 64-битных блоков
    
    Args:
        text: Текст для преобразования
        block_size: Размер блока в байтах (8 байт = 64 бит)
        
    Returns:
        list: Список 64-битных блоков
    """
    # Кодируем текст в байты
    bytes_data = text.encode('utf-8')
    
    # Дополняем данные до кратности размеру блока
    padding_size = block_size - (len(bytes_data) % block_size)
    if padding_size < block_size:
        # Добавляем в конец байты со значением равным размеру дополнения
        bytes_data += bytes([padding_size]) * padding_size
    
    # Преобразуем байты в 64-битные блоки
    blocks = []
    for i in range(0, len(bytes_data), block_size):
        # Используем struct для преобразования 8 байт в 64-битное целое
        block = struct.unpack('>Q', bytes_data[i:i+block_size])[0]
        blocks.append(block)
    
    return blocks

def blocks_to_text(blocks, block_size=8):
    """
    Преобразование списка 64-битных блоков обратно в текст
    
    Args:
        blocks: Список 64-битных блоков
        block_size: Размер блока в байтах (8 байт = 64 бит)
        
    Returns:
        str: Восстановленный текст
    """
    bytes_data = b''
    
    for block in blocks:
        # Преобразуем каждый 64-битный блок обратно в 8 байт
        bytes_data += struct.pack('>Q', block)
    
    # Определяем размер дополнения из последнего байта
    padding_size = bytes_data[-1]
    
    # Проверяем, что значение дополнения корректно
    if padding_size < block_size:
        # Удаляем дополнение
        bytes_data = bytes_data[:-padding_size]
    
    # Декодируем байты обратно в текст
    return bytes_data.decode('utf-8')

def encrypt_text(text, key):
    """
    Шифрование текста с использованием сети Фейстеля
    
    Args:
        text: Исходный текст
        key: 64-битный ключ шифрования
        
    Returns:
        list: Список зашифрованных 64-битных блоков
    """
    blocks = text_to_blocks(text)
    encrypted_blocks = []
    
    for block in blocks:
        encrypted_block = encrypt_block(block, key)
        encrypted_blocks.append(encrypted_block)
    
    return encrypted_blocks

def decrypt_text(encrypted_blocks, key):
    """
    Расшифрование текста с использованием сети Фейстеля
    
    Args:
        encrypted_blocks: Список зашифрованных 64-битных блоков
        key: 64-битный ключ шифрования
        
    Returns:
        str: Расшифрованный текст
    """
    decrypted_blocks = []
    
    for block in encrypted_blocks:
        decrypted_block = decrypt_block(block, key)
        decrypted_blocks.append(decrypted_block)
    
    return blocks_to_text(decrypted_blocks)

# Демонстрация работы алгоритма
if __name__ == "__main__":
    # Генерируем случайный ключ
    key = generate_key()
    print(f"Сгенерированный ключ: {key:016x}\n")
    
    # Исходное сообщение
    message = "Привет, мир!"
    print(f"Исходное сообщение: {message}\n")
    
    # Шифруем сообщение
    encrypted = encrypt_text(message, key)
    print(f"Зашифрованные блоки: {[hex(block) for block in encrypted]}\n")
    
    # Расшифровываем сообщение
    decrypted = decrypt_text(encrypted, key)
    print(f"Расшифрованное сообщение: {decrypted}\n")
    
    # Проверяем, что расшифрованное сообщение совпадает с исходным
    print(f"Результат проверки: {'Успех' if message == decrypted else 'Ошибка'}")
