"""
decompile utility

Author: @remiliacn
"""

from os import getcwd, listdir, path, remove, rmdir, walk
from shutil import rmtree
from subprocess import PIPE, run
from sys import platform
from typing import Optional

from loguru import logger


PYCDAS = "pycdas.exe" if platform == 'win32' else "pycdas"

def extract_pyinstaller_exe(exe_path: str) -> str:
    run(["python", "pyinstxtractor.py", exe_path], check=True)
    return path.join(getcwd(), path.basename(exe_path) + "_extracted")

def find_payload_file(extracted_dir: str, find_file: str, *file_path) -> Optional[str]:
    for root, _, files in walk(path.join(extracted_dir, *file_path)):
        for file in files:
            if find_file in file:
                return path.join(root, file)
    return None

def decompile_pyc(pyc_path: str) -> str:
    result = run([PYCDAS, pyc_path], stdout=PIPE, stderr=PIPE, text=True)
    return result.stdout

def _clean_up_temp_files(directory: str):
    for filename in listdir(directory):
        file_path = path.join(directory, filename)

        if path.isfile(file_path):
            remove(file_path)
            logger.debug(f"Removed file: {file_path}")
        elif path.isdir(file_path):
            rmtree(file_path)
            logger.debug(f"Removed directory: {file_path}")

    rmdir(directory)
