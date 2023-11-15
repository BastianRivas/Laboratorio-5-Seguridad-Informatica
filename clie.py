import socket
import random
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.number import bytes_to_long, long_to_bytes


def des_encrypt(key, plaintext):
    # Convertir el entero K2 en una cadena de bytes
    key_bytes = key.to_bytes(8, byteorder='big')

    cipher = DES.new(key_bytes, DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode('utf-8'), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def crear_llave(cliente):

    # Recibir el número generador (g) y el número primo (p) desde el servidor
    Numero_generador = cliente.recv(1024).decode('utf-8')
    Numero_primo = cliente.recv(256).decode('utf-8')

    print(f"Mensaje recibido del servidor (g): {Numero_generador}")
    print(f"Mensaje recibido del servidor (p): {Numero_primo}")

    # Generar la clave privada del cliente (b)
    b = random.randint(1, int(Numero_primo))
    print("Clave privada del cliente: ", b)

    # Calcular la clave pública del cliente (Clave_B)
    Clave_B = (int(Numero_generador) ** b) % int(Numero_primo)
    print("Clave B: ", Clave_B)

    # Enviar la clave pública del cliente (Clave_B) al servidor
    Clave_B_str = str(Clave_B)
    cliente.send(Clave_B_str.encode('utf-8'))

    # Recibir la clave pública del servidor (Clave_A)
    Clave_A = cliente.recv(256).decode('utf-8')
    print(f"Mensaje recibido del servidor (Clave_A): {Clave_A}")

    # Calcular la clave de sesión compartida (K2)
    K2 = (int(Clave_A) ** b) % int(Numero_primo)
    print("K2: ", K2)

    return K2


# Configuración del cliente
host = '127.0.0.1'
port = 5555

# Crear un socket y conectarse al servidor
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((host, port))

Key2 = crear_llave(client_socket)
print(Key2)

# Leer el mensaje desde el archivo
with open('mensajeentrada.txt', 'r') as file:
    message = file.read()
    print(f"Mensaje leído desde el archivo: {message}")

# Utilizar K2 para cifrar el mensaje y enviar el mensaje cifrado al servidor
ciphertext = des_encrypt(Key2, message)
client_socket.send(ciphertext)


# Cerrar la conexión
client_socket.close()
