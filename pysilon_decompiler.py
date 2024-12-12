"""
pysilon decompiler

Author: @remiliacn
"""

from base64 import b64decode
from re import findall, search
from sys import argv
from time import time
from typing import List, Optional

from loguru import logger

from constants.general import INVALID_TOKEN
from discord_token_validator import validate
from utils.decompile_utils import clean_up_temp_files, decompile_pyc, extract_pyinstaller_exe, find_payload_file


def _analyze_pysilon_bytecode(result: str) -> Optional[List[str]]:
    trimmed_result = result[search(r'\d+:\sauto', result).start():]
    find_result = list(set(findall(r"'([A-Za-z0-9+/=]{90,})'", trimmed_result)))

    if find_result:
        logger.info('Found suspicious token that looks like bot token.')
        bot_tokens = [b64decode(base64_reversed_token[::-1]).decode('utf-8') for base64_reversed_token in find_result]

        return bot_tokens

    return None


def pysilon_decompile(exe_path: str) -> str:
    logger.info("Extracting PyInstaller package...")
    extracted_dir = extract_pyinstaller_exe(exe_path)

    logger.info("locating source_prepared file...")
    source_prepared_file = find_payload_file(extracted_dir, 'source_prepared.pyc')
    if not source_prepared_file:
        logger.error("Error: source_prepared.pyc file not found.")
        clean_up_temp_files(extracted_dir)
        return INVALID_TOKEN

    result = decompile_pyc(source_prepared_file)
    analyzed_bot_token = _analyze_pysilon_bytecode(result)

    clean_up_temp_files(extracted_dir)

    if analyzed_bot_token:
        for token in analyzed_bot_token:
            if validate(token, True):
                logger.success(f'This token is valid!: {token}')
                return '\n'.join(token)
            else:
                logger.warning(f'This bot token is NOT valid. {token}')
    else:
        logger.info('No bot token was found!')

    return INVALID_TOKEN


if __name__ == "__main__":
    start_time = time()
    if len(argv) != 2:
        logger.info('No arg provided, using default file name "source_prepared.exe"')
        pysilon_decompile('source_prepared.exe')
    else:
        pysilon_decompile(argv[1])

    logger.success(f'Successfully finished all tasks in {time() - start_time:.2f}s')
