"""
amnesia stealer decompiler

Author: @remiliacn
"""

from base64 import b64decode
from io import BytesIO
from os import getcwd, mkdir, path, rename, walk
from re import fullmatch, search
from sys import argv
from time import time
from zipfile import ZipFile
from zlib import decompress

from loguru import logger
from rarfile import RarFile

from constants.general import INVALID_TOKEN
from utils.aes import AESModeOfOperationGCM
from utils.blank import blank_stage3, blank_stage4
from utils.decompile_utils import (
    clean_up_temp_files,
    decompile_pyc,
    extract_pyinstaller_exe, find_payload_file,
)


def _decompile_blank_grabber(pyc_decompiled: str, directory: str):
    pyc_decompiled_args = pyc_decompiled.split("\n")[:300]
    aes_file_index = None

    for idx, lines in enumerate(pyc_decompiled_args):
        if search(r"'.*?\.aes'", lines):
            aes_file_index = idx
            break

    payload = INVALID_TOKEN
    if aes_file_index:
        aes_file = pyc_decompiled_args[aes_file_index].strip().replace("'", "")
        logger.info(f"AES file: {aes_file}")

        stub_file_name = pyc_decompiled_args[aes_file_index + 1].strip().replace("'", "")
        key_base64_encrypted = (
            pyc_decompiled_args[aes_file_index + 2].strip().replace("'", "")
        )
        iv_based64_encrypted = (
            pyc_decompiled_args[aes_file_index + 3].strip().replace("'", "")
        )

        key = b64decode(key_base64_encrypted)
        iv = b64decode(iv_based64_encrypted)

        encryptedfile = open(path.join(directory, aes_file), "rb").read()
        try:
            reversedstr = encryptedfile[::-1]
            encryptedfile = decompress(reversedstr)
        except Exception as err:
            logger.error(f"Failed to decompress zlib: {err}")
            pass

        decryptedfile = AESModeOfOperationGCM(key, iv).decrypt(encryptedfile)
        with ZipFile(BytesIO(decryptedfile)) as aeszipe:
            aeszipe.extractall()

        with open(path.join(getcwd(), f'{stub_file_name}.pyc'), 'rb') as file:
            assembly = file.read()
            stage3 = blank_stage3(assembly)
            stage4 = blank_stage4(stage3)

            payload = '\n'.join(stage4)
            logger.success(payload)

    return payload


def _find_blank_grabber_pyc(directory: str) -> str:
    for root, _, files in walk(directory):
        for file in files:
            if file.endswith(".pyc") and fullmatch(r"(\w+-\w+)+.pyc", file):
                return path.join(root, file)


def _perform_reverse_blank_grabber(directory: str) -> str:
    blank_grabber_pyc = _find_blank_grabber_pyc(directory)
    pyc_decompiled = decompile_pyc(blank_grabber_pyc)

    return _decompile_blank_grabber(pyc_decompiled, directory)


def amnesia_layer_decompile(exe_path: str):
    logger.info("Extracting PyInstaller package...")
    extracted_dir = extract_pyinstaller_exe(exe_path)

    logger.info("locating Build.exe file...")

    build_exe_file = find_payload_file(extracted_dir, ".exe", '', blacklist_filenames=['rar.exe'])

    is_blank_grabber = False
    if not build_exe_file:
        logger.error("Error: Build.exe file not found. Maybe this is a blank grabber?")
        extracted_blank_grabber_dir = extracted_dir
        is_blank_grabber = True
    else:
        zip_file_path = path.join(extracted_dir, "Build.rar")
        rename(build_exe_file, zip_file_path)

        extracted_blank_grabber = path.join(extracted_dir, "Build")
        mkdir(extracted_blank_grabber)
        with RarFile(zip_file_path) as rar_ref:
            rar_ref.extractall(extracted_blank_grabber)

        based_exe_file = find_payload_file(extracted_blank_grabber, "based.exe")
        extracted_blank_grabber_dir = extract_pyinstaller_exe(based_exe_file)

    result = _perform_reverse_blank_grabber(extracted_blank_grabber_dir)
    clean_up_temp_files(extracted_dir)
    if not is_blank_grabber:
        clean_up_temp_files(extracted_blank_grabber_dir)
    clean_up_temp_files(path.join(getcwd(), 'dump.bin'))
    clean_up_temp_files(path.join(getcwd(), 'stub-o.pyc'))

    return result


if __name__ == "__main__":
    start_time = time()
    if len(argv) != 2:
        logger.info('No arg provided, using default file name "main.exe"')
        amnesia_layer_decompile("main.exe")
    else:
        amnesia_layer_decompile(argv[1])

    logger.success(f"Successfully finished all tasks in {time() - start_time:.2f}s")
