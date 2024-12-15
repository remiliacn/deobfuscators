"""
decompile utility

Author: @remiliacn
"""

from os import getcwd, path, remove, walk
from shutil import rmtree
from subprocess import DEVNULL, PIPE, run
from sys import platform
from typing import List, Optional

PYCDAS = "pycdas.exe" if platform == "win32" else "pycdas"


def extract_pyinstaller_exe(exe_path: str) -> str:
    run(["python", "pyinstxtractor.py", exe_path], check=True, stdout=DEVNULL)
    return path.join(getcwd(), path.basename(exe_path) + "_extracted")


def find_payload_files(
    extracted_dir: str, find_file: str, *file_path, blacklist_filenames=None
) -> Optional[List[str]]:
    if blacklist_filenames is None:
        blacklist_filenames = []

    all_matched_file = []
    for root, _, files in walk(path.join(extracted_dir, *file_path)):
        for file in files:
            if find_file in file:
                if file not in blacklist_filenames:
                    all_matched_file.append(path.join(root, file))

    return all_matched_file


def find_payload_file(
    extracted_dir: str, find_file: str, *file_path, blacklist_filenames=None
) -> Optional[str]:
    if files := find_payload_files(
        extracted_dir, find_file, *file_path, blacklist_filenames=blacklist_filenames
    ):
        return files[0]

    return None


def decompile_pyc(pyc_path: str) -> str:
    result = run([PYCDAS, pyc_path.strip()], stdout=PIPE, stderr=PIPE, text=True)
    return result.stdout


def clean_up_temp_files(directory: str):
    if path.isfile(directory):
        remove(directory)
        return
    
    if not path.exists(directory):
        return

    rmtree(directory)
