from base64 import b64decode
from re import findall
from subprocess import run, PIPE
from sys import argv, platform
from typing import Optional, List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from loguru import logger

from utils.webhook_util import validate_webhooks


def decrypt(encrypted_data: bytes, key: bytes, iv: bytes) -> Optional[str]:
    try:
        cipher_text = encrypted_data[:-16]
        tag = encrypted_data[-16:]

        decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()

        return decrypted_data.decode("utf-8")
    except InvalidTag:
        logger.error("Authentication tag mismatch or invalid data.")

    return None


def extract_result_using_monodis(exe_path):
    result = run(['monodis', exe_path], stdout=PIPE, stderr=PIPE, text=True)

    base64_results = findall(r'ldstr.*?"([A-Za-z0-9=+/]{16,})"', result.stdout)
    key, iv, encrypted_discord_webhook = base64_results[:3]
    decrypted_discord_webhook = decrypt(b64decode(encrypted_discord_webhook), b64decode(key), b64decode(iv))

    logger.info(f'Extracted a webhook result: {decrypted_discord_webhook}')
    return validate_webhooks([decrypted_discord_webhook])


def umbral_decompiler(exe_path: str) -> List[str]:
    logger.info('Extracting valuable data from executable')

    strings_extraction = extract_result_using_monodis(exe_path)
    return strings_extraction


if __name__ == '__main__':
    if platform == 'win32':
        logger.error('Windows decompiling is currently not supported.')
        exit(1)

    logger.success(f'Found result: {umbral_decompiler(argv[1])}')
