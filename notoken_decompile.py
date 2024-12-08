# -*- coding: utf-8 -*-
"""
notoken decompiler

Author: @remiliacn @xuewu
"""

from argparse import ArgumentParser
from os import getcwd, path, remove
from shutil import move
from re import search
from sys import argv
from typing import Optional
from loguru import logger
from time import sleep, time
from discord_token_validator import validate
from utils.decompile_utils import (
    clean_up_temp_files,
    decompile_pyc,
    extract_pyinstaller_exe,
    find_payload_file,
)


def extract_token_from_file(source_code: str) -> Optional[str]:
    match = search(r"process\n.*?'(.*?)'", source_code)
    return match.group(1) if match else None


def _build_replace_dict_from_bytecode(string: str) -> dict:
    data_set = string[string.index("'A'") : string.index("[Disassembly]")].split("\n")

    replace_dict = {}
    value = ""

    for index, element in enumerate(data_set):
        element = element.strip()
        if element.count("'") == 2:
            element = element.replace("'", "")
        if element.count('"') == 2:
            element = element.replace('"', "")

        if index % 2 == 0:
            value = element
        else:
            encoded_emoji = element.encode("utf-8")[:4]
            replace_dict[encoded_emoji] = value

    return replace_dict


def notoken_decompile(exe_path: str, unsafe=False):
    logger.info("Extracting PyInstaller package...")
    extracted_dir = extract_pyinstaller_exe(exe_path)

    logger.info("Locating pyautogui file...")
    pyautogui_file = find_payload_file(
        extracted_dir, "__init__.pyc", "PYZ-00.pyz_extracted", "pyautogui"
    )
    if not pyautogui_file:
        logger.error("Error: pyautogui file not found.")
        return

    logger.success(f"Found pyautogui file: {pyautogui_file}")
    if pyautogui_file.endswith(".pyc"):
        logger.info("Decompiling pyc file...")
        source_code = decompile_pyc(pyautogui_file)

        logger.info("Extracting token...")
        token = extract_token_from_file(source_code)
        decrypted_token = token
        if token:
            encryptor_pyc_file = path.join(getcwd(), "encryptor.pyc")
            move(
                path.join(
                    extracted_dir, "PYZ-00.pyz_extracted", "notoken887", "encryptor.pyc"
                ),
                encryptor_pyc_file,
            )
            if unsafe:
                from encryptor import TokenCryptor

                c = TokenCryptor()
                decrypted_token = c.process(decrypted_token)
            else:
                encryptor_bytecode = decompile_pyc(encryptor_pyc_file)

                replace_dict = _build_replace_dict_from_bytecode(encryptor_bytecode)

                for i in [x for x in token if x.strip()]:
                    replaced_data = replace_dict.get(i.encode("utf-8"), "")
                    if not replaced_data:
                        logger.warning(f"{i.encode('utf-8')} is not replaced.")
                        if i == b"\xef\xb8\x8f":
                            decrypted_token = decrypted_token.replace(i, "")
                    else:
                        decrypted_token = decrypted_token.replace(i, replaced_data)

        else:
            logger.error("Error: Token not found.")

    try:
        clean_up_temp_files(extracted_dir)
        remove(path.join(getcwd(), "encryptor.pyc"))
    except IOError:
        logger.error("Failed to clean up temp files, you can do it manually :).")
    finally:
        # This is linux fuckery here.
        unfucked_linux_result = decrypted_token.strip().replace("T️", "T")
        logger.success(f"Extracted Token: {repr(unfucked_linux_result)}")

        if validate(unfucked_linux_result, True):
            logger.success("This token is valid")
        else:
            logger.warning("This bot token is NOT valid.")


if __name__ == "__main__":
    start_time = time()
    
    parser = ArgumentParser(
        prog='Notoken Decompiler',
        description='A program for decompiling RayxStealer',
        epilog='Author: Remiliacn, Xuewu')
    
    parser.add_argument('filename')
    parser.add_argument('-s', '--unsafe', action="store_true", default=None)
    
    args = parser.parse_args()
    unsafe_arg = False
    
    if not args.unsafe is None:
        unsafe_arg = args.unsafe

    notoken_decompile(args.filename, unsafe_arg)
    logger.success(f"Successfully finished all tasks in {time() - start_time:.2f}s")
    
    if args.unsafe is None:
        logger.info('Safe decompilation is completed, if you want to change the behavior, add --unsafe while calling the script.')

