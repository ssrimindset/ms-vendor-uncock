#!/usr/bin/env python3
"""
test_uncocker.py: Test script for uncocker.py that processes multiple VSIX files in parallel.
"""

import logging
from pathlib import Path
from multiprocessing import Pool, cpu_count
from uncocker import main

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def process_vsix(vsix_path: str) -> None:
    """
    Process a single VSIX file by calling the main function with its path.
    This function is designed to be called by the process pool.
    """
    try:
        # Call main function with the vsix path directly
        main(vsix_path)
        logger.info(f"successfully processed: {vsix_path}")
        return True
    except Exception as e:
        logger.error(f"error processing {vsix_path}: {str(e)}")
        return False


def main_test():
    # Get the extensions-bin directory path
    extensions_dir = Path(__file__).parent / "extensions-bin"
    if not extensions_dir.exists():
        logger.error(f"extensions-bin directory not found at {extensions_dir}")
        return

    # Find all .vsix files in the directory
    vsix_files = list(extensions_dir.glob("*.vsix"))
    if not vsix_files:
        logger.error(f"no .vsix files found in {extensions_dir}")
        return

    logger.info(f"found {len(vsix_files)} vsix files to process")

    # Determine number of processes to use
    num_processes = min(cpu_count(), len(vsix_files))
    logger.info(f"using {num_processes} processes")

    # Create a process pool and process files in parallel
    with Pool(processes=num_processes) as pool:
        results = pool.map(process_vsix, [str(f) for f in vsix_files])

    # Count successes and failures
    success_count = sum(1 for r in results if r)
    failure_count = len(results) - success_count

    logger.info("processing complete:")
    logger.info(f"successfully processed: {success_count}")
    logger.info(f"failed to process: {failure_count}")


if __name__ == "__main__":
    main_test()
