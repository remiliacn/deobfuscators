from os import getcwd, path
from typing import List

from loguru import logger
from yara_scanner import YaraScanner

from utils.blank import blank_stage3, blank_stage4
from utils.decompile_utils import clean_up_temp_files, extract_pyinstaller_exe, find_payload_files
from utils.webhook_util import validate_webhooks


def luna_grabber_decompiler(exe_path: str) -> List[str]:
    logger.info("Extracting PyInstaller package...")
    extracted_dir = extract_pyinstaller_exe(exe_path)
    final_result = []

    logger.info("Locating payload file...")
    yara_scanner = YaraScanner()
    yara_scanner.track_yara_file("rules/infosteal.yar")
    yara_scanner.load_rules()

    all_pyc_files = find_payload_files(extracted_dir, ".pyc", "")
    target_file = None
    for file in all_pyc_files:
        yara_scanner.scan(file)
        if scan_result := yara_scanner.scan_results:
            if "lunagrabber" in [x.get("rule", "").lower() for x in scan_result]:
                target_file = file
                break

    if target_file:
        with open(target_file, "rb") as file:
            assembly = file.read()
            stage3 = blank_stage3(assembly)
            stage4 = blank_stage4(stage3)

        final_result = validate_webhooks(stage4)
        if final_result:
            logger.success(final_result)

    clean_up_temp_files(extracted_dir)
    clean_up_temp_files(path.join(getcwd(), 'dump.bin'))

    return final_result


if __name__ == "__main__":
    luna_grabber_decompiler(f"{getcwd()}/93483434.exe")
