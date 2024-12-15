"""
exelastealer decompiler

Author: @remiliacn

Usage: python exela_stealer_decompiler.py -f <file_path>
"""

from argparse import ArgumentParser
from base64 import b64decode
from copy import deepcopy
from dataclasses import dataclass
from re import IGNORECASE, findall
from time import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from loguru import logger

from constants.general import INVALID_TOKEN
from utils.decompile_utils import (
    clean_up_temp_files,
    decompile_pyc,
    extract_pyinstaller_exe,
    find_payload_file,
)
from utils.webhook_util import validate_webhooks


@dataclass
class GCMDecryptionObject:
    key: str
    tag: str
    iv: str
    encrypted_string: str


def aes_gcm_decrypt(obj: GCMDecryptionObject) -> str:
    cipher = Cipher(
        algorithms.AES(b64decode(obj.key)),
        modes.GCM(b64decode(obj.iv), b64decode(obj.tag)),
    )
    decryptor = cipher.decryptor()
    decrypted_data = (
        decryptor.update(b64decode(obj.encrypted_string)) + decryptor.finalize()
    )

    return decrypted_data.decode("utf-8", errors="ignore")


def extract_key_tag_iv(source_code: str) -> GCMDecryptionObject:
    matches = findall(r"'[A-Za-z0-9+/=]{18,}'", source_code)
    return GCMDecryptionObject(*matches)


def _extract_webhook_config(obfuscated_code: str):
    i = 0
    while "webhook" not in obfuscated_code and i <= 10:
        layers = obfuscated_code.split("\r\n")[-1]
        encrypted_object = extract_key_tag_iv(layers)
        obfuscated_code = aes_gcm_decrypt(encrypted_object)
        i += 1

    webhook = findall(
        r"webhook = '(https?.*?webhook.*?)'", obfuscated_code, flags=IGNORECASE
    )
    if webhook:
        return webhook


def exela_decompile(exe_path: str) -> str:
    logger.info("Extracting PyInstaller package...")
    extracted_dir = extract_pyinstaller_exe(exe_path)

    logger.info("Locating Stub file...")
    stub_file = find_payload_file(extracted_dir, "Stub.pyc", "")
    if not stub_file:
        logger.error("Error: Stub file not found.")
        return INVALID_TOKEN

    logger.success(f"Found Stub file: {stub_file}")
    logger.info("Decompiling pyc file...")
    source_code = "\n".join(decompile_pyc(stub_file).split("\n")[-50:])

    logger.info("Extracting first layer data...")
    encrypted_object = extract_key_tag_iv(source_code)

    layer1_decrypted_code = aes_gcm_decrypt(encrypted_object)
    logger.info("Extracting actual code payload...")
    webhooks = _extract_webhook_config(layer1_decrypted_code)

    webhook_string = INVALID_TOKEN
    if webhooks:
        valid_webhooks = validate_webhooks(webhooks)
        webhook_string = "\n".join(valid_webhooks)
    else:
        logger.warning("Webhook is not found.")

    clean_up_temp_files(extracted_dir)
    return webhook_string


if __name__ == "__main__":
    start_time = time()

    parser = ArgumentParser(
        prog="Exela Stealer Decompiler",
        description="A program for decompiling ExelaStealer",
        epilog="Author: Remiliacn",
    )

    parser.add_argument("-f", "--filename", required=False, default="main.exe")
    args = parser.parse_args()

    exela_decompile(args.filename)
    logger.success(f"Successfully finished all tasks in {time() - start_time:.2f}s")
