# -*- coding: utf-8 -*-
"""
notoken decompiler

Author: @remiliacn @xuewu
"""

from copy import deepcopy
from os import getcwd, path, remove
from shutil import move
from subprocess import PIPE
from re import findall, search
from sys import argv
from typing import Optional
from loguru import logger
from time import time
from discord_token_validator import validate
from utils.decompile_utils import clean_up_temp_files, decompile_pyc, extract_pyinstaller_exe, find_payload_file


def extract_token_from_file(source_code: str) -> Optional[str]:
    match = search(r"process\n.*?'(.*?)'", source_code)
    return match.group(1) if match else None


def _build_replace_dict_from_bytecode(string: str) -> dict:
    data_set = findall(r"\'(.{1,2})\'\n", string)
    data_set = data_set[1:len(data_set) // 4 - 1]

    replace_dict = {}
    value = ''

    for index, element in enumerate(data_set):
        if index % 2 == 0:
            value = element.strip()
        else:
            encoded_emoji = element.encode('utf-8')[:4]
            if encoded_emoji == b'\xf0\x9f\x9b\xa1\xef\xb8\x8f':
                encoded_emoji = b'\xf0\x9f\x9b\xa1'

            if encoded_emoji != b' ':
                replace_dict[encoded_emoji] = value

    return replace_dict


def notoken_decompile(exe_path: str):
    logger.info("Extracting PyInstaller package...")
    extracted_dir = extract_pyinstaller_exe(exe_path)

    logger.info("Locating pyautogui file...")
    pyautogui_file = find_payload_file(
        extracted_dir, '__init__.pyc', 'PYZ-00.pyz_extracted', 'pyautogui')
    if not pyautogui_file:
        logger.error("Error: pyautogui file not found.")
        return

    logger.success(f"Found pyautogui file: {pyautogui_file}")
    if pyautogui_file.endswith(".pyc"):
        logger.info("Decompiling pyc file...")
        source_code = decompile_pyc(pyautogui_file)

        logger.info("Extracting token...")
        token = extract_token_from_file(source_code)
        decrypted_token = deepcopy(''.join(x for x in token))
        if token:
            encryptor_pyc_file = path.join(getcwd(), 'encryptor.pyc')
            move(path.join(extracted_dir, 'PYZ-00.pyz_extracted', 'notoken887',
                 'encryptor.pyc'), encryptor_pyc_file)
            from encryptor import TokenCryptor
            c = TokenCryptor()
            decrypted_token = c.process(decrypted_token)
            # encryptor_bytecode = decompile_pyc(encryptor_pyc_file)
            
            # replace_dict = _build_replace_dict_from_bytecode(
            #     encryptor_bytecode)
 
            # for i in [x for x in token if x.strip()]:
            #     replaced_data = replace_dict.get(i.encode('utf-8'), '')
            #     if not replaced_data:
            #         logger.warning(f'{i.encode('utf-8')} is not replaced.')
            #         if i == b'\xef\xb8\x8f':
            #             decrypted_token = decrypted_token.replace(i, '')
            #     else:
            #         decrypted_token = decrypted_token.replace(i, replaced_data)

        else:
            logger.error("Error: Token not found.")

    try:
        clean_up_temp_files(extracted_dir)
        remove(path.join(getcwd(), 'encryptor.pyc'))
    except IOError:
        logger.error(
            'Failed to clean up temp files, you can do it manually :).')
    finally:
        # This is linux fuckery here.
        unfucked_linux_result = decrypted_token.strip().replace(
            '\n', '\r\n').replace('T️', 'T')
        logger.success(f"Extracted Token: {repr(unfucked_linux_result)}")

        if validate(unfucked_linux_result, True):
            logger.success('This token is valid')
        else:
            logger.warning('This bot token is NOT valid.')


if __name__ == "__main__":
    start_time = time()
    if len(argv) != 2:
        logger.info('No arg provided, using default file name "main.exe"')
        notoken_decompile('speedy-maqing.exe')
    else:
        notoken_decompile(argv[1])

    logger.success(f'Successfully finished all tasks in {time() - start_time:.2f}s')
