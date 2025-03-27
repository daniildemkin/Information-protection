import struct
import os
import base64
import logging
from pathlib import Path

# Настройка логирования
logging.basicConfig(filename="gost.log", level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Таблица замен S-блоков для ГОСТ 28147-89 
SBOX = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 11, 2, 5, 3, 12],
    [12, 6, 15, 10, 2, 9, 1, 7, 4, 14, 0, 5, 11, 3, 8, 13],
    [11, 3, 6, 8, 15, 0, 1, 12, 2, 5, 14, 7, 9, 10, 4, 13],
    [8, 15, 2, 5, 12, 11, 7, 6, 0, 4, 14, 9, 10, 1, 13, 3],
    [10, 2, 7, 1, 13, 8, 15, 9, 12, 0, 5, 11, 6, 14, 3, 4]
]


# Функция добавления PKCS7-паддинга
def pkcs7_pad(data, block_size=8):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

# Функция удаления PKCS7-паддинга
def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len > len(data) or any(p != pad_len for p in data[-pad_len:]):
        raise ValueError("Некорректный паддинг")
    return data[:-pad_len]

# Функция загрузки и валидации ключа
def load_key(key_path):
    with open(key_path, "rb") as f:
        key_data = f.read()
    if len(key_data) != 32:
        raise ValueError("Ошибка: Неверная длина ключа! Ожидается 32 байта.")
    return struct.unpack('<8I', key_data)

# Функция шифрования одного 64-битного блока
def gost_encrypt_block(block, key):
    n1, n2 = struct.unpack('<II', block)
    for i in range(32):
        k = key[i % 8]
        s = (n1 + k) & 0xFFFFFFFF
        for j in range(8):
            s = (s & ~(0xF << (28 - j * 4))) | (SBOX[j][(s >> (28 - j * 4)) & 0xF] << (28 - j * 4))
        s = ((s << 11) | (s >> (32 - 11))) & 0xFFFFFFFF
        n1, n2 = n2 ^ s, n1
    return struct.pack('<II', n2, n1)

# Функция расшифрования одного 64-битного блока
def gost_decrypt_block(block, key):
    n1, n2 = struct.unpack('<II', block)
    for i in range(31, -1, -1):
        k = key[i % 8]
        s = (n1 + k) & 0xFFFFFFFF
        for j in range(8):
            s = (s & ~(0xF << (28 - j * 4))) | (SBOX[j][(s >> (28 - j * 4)) & 0xF] << (28 - j * 4))
        s = ((s << 11) | (s >> (32 - 11))) & 0xFFFFFFFF
        n1, n2 = n2 ^ s, n1
    return struct.pack('<II', n2, n1)

# Генерация случайного 256-битного ключа
def generate_key():
    key_path = input("Введите имя файла для ключа (по умолчанию key.bin): ") or "key.bin"
    key = os.urandom(32)
    with open(key_path, "wb") as f:
        f.write(key)
    print(f"Ключ сохранен в {key_path}")

# Функция обработки файла по блокам
def process_file(input_path, output_path, key, process_block):
    if not Path(input_path).is_file():
        print("Ошибка: файл не найден!")
        logging.error(f"Файл {input_path} не найден.")
        return
    
    try:
        with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
            while chunk := fin.read(8):
                if len(chunk) < 8:
                    chunk = pkcs7_pad(chunk)
                fout.write(process_block(chunk, key))
        print(f"Файл {input_path} обработан и сохранен как {output_path}")
    except Exception as e:
        print(f"Ошибка: {e}")
        logging.error(f"Ошибка обработки файла {input_path}: {e}")

# Функция шифрования файла
def encrypt_file(input_path, output_path, key_path):
    try:
        key = load_key(key_path)
        process_file(input_path, output_path, key, gost_encrypt_block)
    except Exception as e:
        print(f"Ошибка: {e}")
        logging.error(f"Ошибка шифрования: {e}")

# Функция расшифрования файла
def decrypt_file(input_path, output_path, key_path):
    try:
        key = load_key(key_path)
        process_file(input_path, output_path, key, gost_decrypt_block)
        # Удаление паддинга после расшифрования
        with open(output_path, "rb") as f:
            data = f.read()
        with open(output_path, "wb") as f:
            f.write(pkcs7_unpad(data))
    except ValueError:
        print("Ошибка: неверный ключ или поврежденный файл!")
        logging.error("Ошибка: неверный ключ или поврежденный файл!")
    except Exception as e:
        print(f"Ошибка: {e}")
        logging.error(f"Ошибка расшифрования: {e}")

# Функция шифрования файла с сохранением base64
def encrypt_file(input_path, output_path, key_path):
    try:
        key = load_key(key_path)
        with open(input_path, "rb") as f:
            data = f.read()
        
        data = pkcs7_pad(data)
        encrypted_data = b"".join(gost_encrypt_block(data[i:i+8], key) for i in range(0, len(data), 8))

        # Сохранение бинарного файла
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
        
        # Сохранение в base64
        encrypted_base64 = base64.b64encode(encrypted_data).decode()
        with open(output_path + ".txt", "w") as f:
            f.write(encrypted_base64)

        print(f"Файл зашифрован и сохранен как {output_path} (бинарный) и {output_path}.txt (текстовый)")
    except Exception as e:
        print(f"Ошибка: {e}")
        logging.error(f"Ошибка шифрования: {e}")

# Функция расшифрования файла с поддержкой base64
def decrypt_file(input_path, output_path, key_path):
    try:
        key = load_key(key_path)

        # Определение, является ли файл base64
        with open(input_path, "rb") as f:
            first_bytes = f.read(10)
        try:
            first_bytes.decode()  # Проверка, можно ли декодировать текст
            is_base64 = True
        except UnicodeDecodeError:
            is_base64 = False

        # Читаем данные
        if is_base64:
            with open(input_path, "r") as f:
                encrypted_data = base64.b64decode(f.read())
        else:
            with open(input_path, "rb") as f:
                encrypted_data = f.read()

        # Расшифровка
        decrypted_data = b"".join(gost_decrypt_block(encrypted_data[i:i+8], key) for i in range(0, len(encrypted_data), 8))
        decrypted_data = pkcs7_unpad(decrypted_data)

        # Сохранение расшифрованного файла
        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        print(f"Файл {input_path} расшифрован и сохранен как {output_path}")
    except Exception as e:
        print(f"Ошибка: {e}")
        logging.error(f"Ошибка расшифрования: {e}")

# Консольное меню
def console_menu():
    while True:
        print("\nГОСТ 28147-89 Шифрование")
        print("1. Сгенерировать ключ")
        print("2. Зашифровать файл")
        print("3. Расшифровать файл")
        print("4. Выйти")
        choice = input("Выберите действие: ")

        if choice == "1":
            generate_key()
        elif choice == "2":
            encrypt_file(input("Файл для шифрования: "), input("Файл для сохранения: "), input("Файл с ключом: "))
        elif choice == "3":
            decrypt_file(input("Файл для расшифрования: "), input("Файл для сохранения: "), input("Файл с ключом: "))
        elif choice == "4":
            break
        else:
            print("Ошибка: выберите корректный пункт!")

if __name__ == "__main__":
    console_menu()
