#!/usr/bin/env python3
"""
    python uncocker.py <path-to-extension.vsix>
"""

import logging
from shutil import rmtree
from sys import argv
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from json import loads, dumps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# This is extension.vsixmanifest file begining, parse TargetPlatform from here, and match it to the comments and patches below
# <?xml version="1.0" encoding="utf-8"?>
# 	<PackageManifest Version="2.0.0" xmlns="http://schemas.microsoft.com/developer/vsx-schema/2011" xmlns:d="http://schemas.microsoft.com/developer/vsx-schema-design/2011">
# 		<Metadata>
# 			<Identity Language="en-US" Id="cpptools" Version="1.25.3" Publisher="ms-vscode" TargetPlatform="alpine-x64"/>

# CPPTOOLS

# win32-x64
#   vsdbg.dll -> 84 C0 74 15 83 BB ? ? ? ? 04, patch 74 15 to 74 00
#   cpptools.exe -> 40 32 FF 4C 8B 3D, loop untill first call inst E8 ? ? ? ?, patch to B8 00 00 00 00
#   cpptools.exe -> 49 83 FD 0F 49 0F 47 CE 4C 8B C6, loop untill first call inst E8 ? ? ? ?, patch to B8 00 00 00 00
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# win32-arm64
#   vsdbg.dll -> 01 81 89 9A ? ? ? ? 08 1C 00 53, patch 08 1C 00 53 to 28 00 80 52
#   cpptools.exe -> 1B 00 80 52 51 43 1B 91, loop untill first call inst (? ? ? 94), patch to (00 00 80 52)
#   cpptools.exe -> 48 03 1B 91 DF 3E 00 F1 A0 82 88 9A, loop untill first call inst (? ? ? 94), patch to (00 00 80 52)
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# linux-x64
#   vsdbg.dll -> unsupported
#   cpptools.exe -> 48 89 DA E8 ? ? ? ? 85 C0 79 DA, patch E8 ? ? ? ? to B8 00 00 00 00
#   cpptools.exe -> E8 ? ? ? ? 85 C0 0F 88 ? ? ? ? 48 8B BD ? ? ? ? 0F B6 9D, patch E8 ? ? ? ? to B8 00 00 00 00
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# linux-arm64
#   vsdbg.dll -> unsupported
#   cpptools.exe -> F9 03 00 AA E3 03 1A AA E2 03 1B AA, loop untill first call inst ? ? ? 97, patch to 00 00 80 52
#   cpptools.exe -> D6 82 04 91 3F 03 16 EB, loop untill first call inst ? ? ? 97, patch to 00 00 80 52
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# linux-armhf
#   vsdbg.dll -> unsupported
#   cpptools.exe -> 14 10 95 E5 10 00 95 E5 07 30 A0 E1 08 20 A0 E1, loop untill first call inst ? ? ? EB, patch to 00 00 A0 E3
#   cpptools.exe -> 03 00 55 E1 ? ? ? ? 14 30 95 E5 10 20 95 E5 07 10 A0 E1 08 00 A0 E1, loop untill first call inst ? ? ? EB, patch to 00 00 A0 E3
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# alpine-x64
#   vsdbg.dll -> unsupported
#   cpptools.exe -> 48 89 DA E8 ? ? ? ? 85 C0 79 DA, patch E8 ? ? ? ? to B8 00 00 00 00
#   cpptools.exe -> E8 ? ? ? ? 85 C0 0F 88 ? ? ? ? 48 8B BD ? ? ? ? 0F B6 9D, patch E8 ? ? ? ? to B8 00 00 00 00
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# alpine-arm64
#   vsdbg.dll -> unsupported
#   cpptools.exe -> F9 03 00 AA E3 03 1A AA E2 03 1B AA, loop untill first call inst ? ? ? 97, patch to 00 00 80 52
#   cpptools.exe -> D6 82 04 91 3F 03 16 EB, loop untill first call inst ? ? ? 97, patch to 00 00 80 52
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# darwin-x64
#   vsdbg.dll -> unsupported
#   cpptools.exe -> E8 ? ? ? ? 48 89 C3 4C 8D 25 ? ? ? ? 4C 39 E0, patch E8 ? ? ? ? to 48 8B 47 08 90
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",

# darwin-arm64
#   vsdbg.dll -> unsupported
#   cpptools.exe -> E0 03 15 AA ? ? ? 97 F4 03 00 AA A8 22 00 91, patch ? ? ? 97 to 1F 20 03 D5
#   package.json -> remove "when": "workspacePlatform == windows", for  "type": "cppvsdbg",


# CSSHARP

# win32-x64
#   extension\.debugger\x86_64\vsdbg.dll -> 84 C0 74 15 83 BB ? ? ? ? 04, patch 74 15 to 74 00

# win32-arm64
#   extension\.debugger\x86_64\vsdbg.dll -> 84 C0 74 15 83 BB ? ? ? ? 04, patch 74 15 to 74 00
#   extension\.debugger\arm64\vsdbg.dll -> 01 81 89 9A ? ? ? 94 ? 00 00 36, patch ? 00 00 36 to 1F 20 03 D5

# linux-x64
#   extension\.debugger\libvsdbg.so -> B9 05 00 00 00 84 C0 74 ?, patch 74 ? to 74 00

# linux-arm64
#   extension\.debugger\libvsdbg.so -> 94 ? 00 00 36 ? ? ? B9 1F 11 00 71, patch ? 00 00 36 to 1F 20 03 D5

# darwin-x64
#   extension\.debugger\x86_64\libvsdbg.dylib -> B9 05 00 00 00 84 C0 74 ?, patch 74 ? to 74 00

# darwin-arm64
#   extension\.debugger\x86_64\libvsdbg.dylib -> B9 ? ? ? ? 84 C0 74 ?, patch 74 ? to 74 00
#   extension\.debugger\arm64\libvsdbg.dylib -> 21 B1 94 9A ? ? ? ? ? ? ? ? ? ? ? 94 ? 00 00 34, patch ? 00 00 34 to 1F 20 03 D5

# alpine-x64
#   extension\.debugger\libvsdbg.so -> B9 05 00 00 00 84 C0 74 ?, patch 74 ? to 74 00

# alpine-arm64
#   extension\.debugger\libvsdbg.so -> 94 ? 00 00 36 ? ? ? B9 1F 11 00 71, patch ? 00 00 36 to 1F 20 03 D5


class UncockerError(Exception):
    """Base exception for uncocker errors."""

    pass


class ManifestError(UncockerError):
    """Exception raised for manifest parsing errors."""

    pass


class PatchError(UncockerError):
    """Exception raised for patching errors."""

    pass


def parse_manifest(manifest_path: Path) -> tuple[str, str]:
    """
    Parse the VSIX manifest file on disk to extract the TargetPlatform attribute and extension ID.
    Uses a simple text-based approach to find the TargetPlatform and Id.
    Raises ManifestError if not found or missing.
    Returns a tuple of (platform, extension_id)
    """
    logger.info(f"parsing manifest at {manifest_path}")
    with open(manifest_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Look for TargetPlatform in the Identity tag
    start = content.find('TargetPlatform="')
    if start == -1:
        raise ManifestError(
            "TargetPlatform attribute not found in extension.vsixmanifest"
        )

    start += len('TargetPlatform="')
    end = content.find('"', start)
    if end == -1:
        raise ManifestError(
            "TargetPlatform attribute value not found in extension.vsixmanifest"
        )

    platform = content[start:end]
    if not platform:
        raise ManifestError(
            "TargetPlatform attribute is empty in extension.vsixmanifest"
        )

    # Look for Id in the Identity tag
    start = content.find('Id="')
    if start == -1:
        raise ManifestError("Id attribute not found in extension.vsixmanifest")

    start += len('Id="')
    end = content.find('"', start)
    if end == -1:
        raise ManifestError("Id attribute value not found in extension.vsixmanifest")

    extension_id = content[start:end]
    if not extension_id:
        raise ManifestError("Id attribute is empty in extension.vsixmanifest")

    logger.info(f"found target platform: {platform}, extension id: {extension_id}")
    return platform, extension_id


class SigScanner:
    """
    A simple signature-based binary scanner that can match patterns with wildcards ('?').

    Patterns are space-delimited hex bytes, with '?' representing a wildcard nibble.
    The scanner splits the pattern into sequences of known bytes (bytearray) and
    wildcards (list of -1), then searches the target data for the first full match.
    """

    def __init__(self, pattern: str):
        logger.info(f"initializing sigscanner with pattern: {pattern}")
        # Convert textual pattern into internal parts; record leading wildcards
        self.start_offset = 0
        self.sig_data = self._load_pattern(pattern)

    def _load_pattern(self, pattern: str) -> list[list[int] | bytearray]:
        # Helper to parse a signature string into ints and -1 for '?'
        def parse_sig(sig_str: str) -> list[int]:
            parts = []
            for byte in sig_str.split():
                if byte == "?":
                    parts.append(-1)
                else:
                    parts.append(int(byte, 16))
            return parts

        bytes_list = parse_sig(pattern)
        segments: list[list[int] | bytearray] = []
        cur_segment = None
        # Build alternating wildcard blocks (list) and known-byte blocks (bytearray)
        for b in bytes_list:
            is_wild = b == -1
            if (
                cur_segment is None
                or (is_wild and not isinstance(cur_segment, list))
                or (not is_wild and not isinstance(cur_segment, bytearray))
            ):
                if cur_segment is not None:
                    segments.append(cur_segment)
                cur_segment = [] if is_wild else bytearray()
            cur_segment.append(b)
        if cur_segment is not None:
            segments.append(cur_segment)

        # Strip leading wildcard blocks, adjust start_offset
        while segments and isinstance(segments[0], list):
            self.start_offset += len(segments.pop(0))
        # Remove trailing wildcards
        while segments and isinstance(segments[-1], list):
            segments.pop()

        # # If we have no segments left (all wildcards), add a single wildcard segment
        # if not segments:
        #     segments = [[-1]]
        #     self.start_offset = len(bytes_list) - 1

        return segments

    def find(self, data: bytes) -> int:
        """
        Search `data` for the first occurrence of the full pattern.
        Returns the offset (including leading wildcards) or -1 if not found.
        """
        if not self.sig_data:
            return -1

        # If we only have wildcards, return the start offset
        if len(self.sig_data) == 1 and isinstance(self.sig_data[0], list):
            return self.start_offset

        first_block = self.sig_data[0]
        # Find all candidate starts of the first known block
        candidates = []
        idx = 0
        while True:
            idx = data.find(first_block, idx)
            if idx == -1:
                break
            candidates.append(idx)
            idx += 1

        # For each candidate, verify the rest of the pattern
        for base in candidates:
            offset = base + len(first_block)
            ok = True
            for segment in self.sig_data[1:]:
                if isinstance(segment, list):  # wildcard block
                    offset += len(segment)
                else:  # known-byte block
                    seg_bytes = bytes(segment)
                    if data[offset : offset + len(seg_bytes)] != seg_bytes:
                        ok = False
                        break
                    offset += len(seg_bytes)
            if ok:
                logger.info(f"found pattern match at offset {base + self.start_offset}")
                return base + self.start_offset
        logger.info("pattern not found")
        return -1


def add_directory(zip_file: ZipFile, directory: Path, root_dir: Path) -> None:
    """
    Recursively add files from `directory` into `zip_file`, preserving relative paths.
    """
    for item in directory.iterdir():
        if item.is_dir():
            add_directory(zip_file, item, root_dir)
        else:
            zip_file.write(item, item.relative_to(root_dir))


def patch_cpp_win32_64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Win32-x64 patches in-place:
      - vsdbg.dll: signature "84 C0 74 15 83 BB ? ? ? ? 04", patch 74 15 -> 74 00
      - cpptools.exe: signature prefix "40 32 FF 4C 8B 3D", then patch first call E8.. -> B8 00 00 00 00
      - cpptools.exe: signature prefix "49 83 FD 0F 49 0F 47 CE 4C 8B C6", then patch first call E8.. -> B8 00 00 00 00
    """
    logger.info("applying win32-x64 patches")

    # vsdbg.dll patch
    logger.info("patching vsdbg.dll")
    scanner_vs = SigScanner("84 C0 74 15 83 BB ? ? ? ? 04")
    off_vs = scanner_vs.find(bytes(vsdbg))
    if off_vs >= 0:
        # replace byte 74 15 starting at offset+2
        vsdbg[off_vs + 2 : off_vs + 4] = bytes.fromhex("74 00")
        logger.info(f"patched vsdbg.dll at offset {off_vs+2}")
    else:
        raise PatchError("win32-x64 vsdbg.dll patch pattern not found")

    # cpptools.exe patch 1
    logger.info("applying cpptools.exe patch 1")
    scanner_cp1 = SigScanner("40 32 FF 4C 8B 3D")
    off_cp1 = scanner_cp1.find(bytes(cpptools))
    if off_cp1 >= 0:
        # find first CALL opcode (E8) after prefix
        idx_call1 = cpptools.find(0xE8, off_cp1)
        if idx_call1 >= 0:
            cpptools[idx_call1 : idx_call1 + 5] = bytes.fromhex("B8 00 00 00 00")
            logger.info(f"patched cpptools.exe at offset {idx_call1}")
    else:
        raise PatchError("win32-x64 cpptools.exe patch 1 pattern not found")

    # cpptools.exe patch 2
    logger.info("applying cpptools.exe patch 2")
    scanner_cp2 = SigScanner("49 83 FD 0F 49 0F 47 CE 4C 8B C6")
    off_cp2 = scanner_cp2.find(bytes(cpptools))
    if off_cp2 >= 0:
        idx_call2 = cpptools.find(0xE8, off_cp2)
        if idx_call2 >= 0:
            cpptools[idx_call2 : idx_call2 + 5] = bytes.fromhex("B8 00 00 00 00")
            logger.info(f"patched cpptools.exe at offset {idx_call2}")
    else:
        raise PatchError("win32-x64 cpptools.exe patch 2 pattern not found")


def patch_cpp_win32_arm64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Win32-arm64 patches in-place:
      - vsdbg.dll: signature "01 81 89 9A ? ? ? ? 08 1C 00 53", patch 08 1C 00 53 to 28 00 80 52
      - cpptools.exe: signature "1B 00 80 52 51 43 1B 91", loop until first call inst (? ? ? 94), patch to (00 00 80 52)
      - cpptools.exe: signature "48 03 1B 91 DF 3E 00 F1 A0 82 88 9A", loop until first call inst (? ? ? 94), patch to (00 00 80 52)
    """
    # vsdbg.dll patch
    scanner_vs = SigScanner("01 81 89 9A ? ? ? ? 08 1C 00 53")
    off_vs = scanner_vs.find(bytes(vsdbg))
    if off_vs >= 0:
        # replace bytes 08 1C 00 53 starting at offset+8
        vsdbg[off_vs + 8 : off_vs + 12] = bytes.fromhex("28 00 80 52")
    else:
        raise PatchError("win32-arm64 vsdbg.dll patch pattern not found")

    # cpptools.exe patch 1
    scanner_cp1 = SigScanner("1B 00 80 52 51 43 1B 91")
    off_cp1 = scanner_cp1.find(bytes(cpptools))
    if off_cp1 >= 0:
        # find first CALL opcode (94) after prefix by checking every 4 bytes
        idx = off_cp1
        while idx < len(cpptools) - 4:
            if cpptools[idx + 3] == 0x94:  # check last byte of 4-byte sequence
                cpptools[idx : idx + 4] = bytes.fromhex("00 00 80 52")
                break
            idx += 4
        else:
            raise PatchError(
                "win32-arm64 cpptools.exe patch 1: call instruction not found"
            )
    else:
        raise PatchError("win32-arm64 cpptools.exe patch 1 pattern not found")

    # cpptools.exe patch 2
    scanner_cp2 = SigScanner("48 03 1B 91 DF 3E 00 F1 A0 82 88 9A")
    off_cp2 = scanner_cp2.find(bytes(cpptools))
    if off_cp2 >= 0:
        # find first CALL opcode (94) after prefix by checking every 4 bytes
        idx = off_cp2
        while idx < len(cpptools) - 4:
            if cpptools[idx + 3] == 0x94:  # check last byte of 4-byte sequence
                cpptools[idx : idx + 4] = bytes.fromhex("00 00 80 52")
                break
            idx += 4
        else:
            raise PatchError(
                "win32-arm64 cpptools.exe patch 2: call instruction not found"
            )
    else:
        raise PatchError("win32-arm64 cpptools.exe patch 2 pattern not found")


def patch_cpp_linux_x64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Linux-x64 patches in-place:
      - cpptools: signature "48 89 DA E8 ? ? ? ? 85 C0 79 DA", patch E8 ? ? ? ? to B8 00 00 00 00
      - cpptools: signature "E8 ? ? ? ? 85 C0 0F 88 ? ? ? ? 48 8B BD ? ? ? ? 0F B6 9D", patch E8 ? ? ? ? to B8 00 00 00 00
    """
    # cpptools patch 1
    scanner_cp1 = SigScanner("48 89 DA E8 ? ? ? ? 85 C0 79 DA")
    off_cp1 = scanner_cp1.find(bytes(cpptools))
    if off_cp1 >= 0:
        # replace E8 ? ? ? ? with B8 00 00 00 00
        cpptools[off_cp1 + 3 : off_cp1 + 8] = bytes.fromhex("B8 00 00 00 00")
    else:
        raise PatchError("linux-x64 cpptools patch 1 pattern not found")

    # cpptools patch 2
    scanner_cp2 = SigScanner("E8 ? ? ? ? 85 C0 0F 88 ? ? ? ? 48 8B BD ? ? ? ? 0F B6 9D")
    off_cp2 = scanner_cp2.find(bytes(cpptools))
    if off_cp2 >= 0:
        # replace E8 ? ? ? ? with B8 00 00 00 00
        cpptools[off_cp2 : off_cp2 + 5] = bytes.fromhex("B8 00 00 00 00")
    else:
        raise PatchError("linux-x64 cpptools patch 2 pattern not found")


def patch_cpp_linux_arm64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Linux-arm64 patches in-place:
      - cpptools: signature "F9 03 00 AA E3 03 1A AA E2 03 1B AA", loop until first call inst ? ? ? 97, patch to 00 00 80 52
      - cpptools: signature "D6 82 04 91 3F 03 16 EB", loop until first call inst ? ? ? 97, patch to 00 00 80 52
    """
    # cpptools patch 1
    scanner_cp1 = SigScanner("F9 03 00 AA E3 03 1A AA E2 03 1B AA")
    off_cp1 = scanner_cp1.find(bytes(cpptools))
    if off_cp1 >= 0:
        # find first CALL opcode (97) after prefix by checking every 4 bytes
        idx = off_cp1
        while idx < len(cpptools) - 4:
            if cpptools[idx + 3] == 0x97:  # check last byte of 4-byte sequence
                cpptools[idx : idx + 4] = bytes.fromhex("00 00 80 52")
                break
            idx += 4
        else:
            raise PatchError("linux-arm64 cpptools patch 1: call instruction not found")
    else:
        raise PatchError("linux-arm64 cpptools patch 1 pattern not found")

    # cpptools patch 2
    scanner_cp2 = SigScanner("D6 82 04 91 3F 03 16 EB")
    off_cp2 = scanner_cp2.find(bytes(cpptools))
    if off_cp2 >= 0:
        # find first CALL opcode (97) after prefix by checking every 4 bytes
        idx = off_cp2
        while idx < len(cpptools) - 4:
            if cpptools[idx + 3] == 0x97:  # check last byte of 4-byte sequence
                cpptools[idx : idx + 4] = bytes.fromhex("00 00 80 52")
                break
            idx += 4
        else:
            raise PatchError("linux-arm64 cpptools patch 2: call instruction not found")
    else:
        raise PatchError("linux-arm64 cpptools patch 2 pattern not found")


def patch_cpp_linux_armhf(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Linux-armhf patches in-place:
      - cpptools: signature "14 10 95 E5 10 00 95 E5 07 30 A0 E1 08 20 A0 E1", loop until first call inst ? ? ? EB, patch to 00 00 A0 E3
      - cpptools: signature "03 00 55 E1 ? ? ? ? 14 30 95 E5 10 20 95 E5 07 10 A0 E1 08 00 A0 E1", loop until first call inst ? ? ? EB, patch to 00 00 A0 E3
    """
    # cpptools patch 1
    scanner_cp1 = SigScanner("14 10 95 E5 10 00 95 E5 07 30 A0 E1 08 20 A0 E1")
    off_cp1 = scanner_cp1.find(bytes(cpptools))
    if off_cp1 >= 0:
        # find first CALL opcode (EB) after prefix by checking every 4 bytes
        idx = off_cp1
        while idx < len(cpptools) - 4:
            if cpptools[idx + 3] == 0xEB:  # check last byte of 4-byte sequence
                cpptools[idx : idx + 4] = bytes.fromhex("00 00 A0 E3")
                break
            idx += 4
        else:
            raise PatchError("linux-armhf cpptools patch 1: call instruction not found")
    else:
        raise PatchError("linux-armhf cpptools patch 1 pattern not found")

    # cpptools patch 2
    scanner_cp2 = SigScanner(
        "03 00 55 E1 ? ? ? ? 14 30 95 E5 10 20 95 E5 07 10 A0 E1 08 00 A0 E1"
    )
    off_cp2 = scanner_cp2.find(bytes(cpptools))
    if off_cp2 >= 0:
        # find first CALL opcode (EB) after prefix by checking every 4 bytes
        idx = off_cp2
        while idx < len(cpptools) - 4:
            if cpptools[idx + 3] == 0xEB:  # check last byte of 4-byte sequence
                cpptools[idx : idx + 4] = bytes.fromhex("00 00 A0 E3")
                break
            idx += 4
        else:
            raise PatchError("linux-armhf cpptools patch 2: call instruction not found")
    else:
        raise PatchError("linux-armhf cpptools patch 2 pattern not found")


def patch_cpp_alpine_x64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Alpine-x64 patches in-place:
      - cpptools: signature "48 89 DA E8 ? ? ? ? 85 C0 79 DA", patch E8 ? ? ? ? to B8 00 00 00 00
      - cpptools: signature "E8 ? ? ? ? 85 C0 0F 88 ? ? ? ? 48 8B BD ? ? ? ? 0F B6 9D", patch E8 ? ? ? ? to B8 00 00 00 00
    """
    # Same as linux-x64
    patch_cpp_linux_x64(vsdbg, cpptools)


def patch_cpp_alpine_arm64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Alpine-arm64 patches in-place:
      - cpptools: signature "F9 03 00 AA E3 03 1A AA E2 03 1B AA", loop until first call inst ? ? ? 97, patch to 00 00 80 52
      - cpptools: signature "D6 82 04 91 3F 03 16 EB", loop until first call inst ? ? ? 97, patch to 00 00 80 52
    """
    # Same as linux-arm64
    patch_cpp_linux_arm64(vsdbg, cpptools)


def patch_cpp_darwin_x64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Darwin-x64 patches in-place:
      - cpptools: signature "E8 ? ? ? ? 48 89 C3 4C 8D 25 ? ? ? ? 4C 39 E0", patch E8 ? ? ? ? to 48 8B 47 08 90
    """
    scanner_cp = SigScanner("E8 ? ? ? ? 48 89 C3 4C 8D 25 ? ? ? ? 4C 39 E0")
    off_cp = scanner_cp.find(bytes(cpptools))
    if off_cp >= 0:
        # replace E8 ? ? ? ? with 48 8B 47 08 90
        cpptools[off_cp : off_cp + 5] = bytes.fromhex("48 8B 47 08 90")
    else:
        raise PatchError("darwin-x64 cpptools patch pattern not found")


def patch_cpp_darwin_arm64(vsdbg: bytearray, cpptools: bytearray) -> None:
    """
    Apply Darwin-arm64 patches in-place:
      - cpptools: signature "E0 03 15 AA ? ? ? 97 F4 03 00 AA A8 22 00 91", patch ? ? ? 97 to 1F 20 03 D5
    """
    scanner_cp = SigScanner("E0 03 15 AA ? ? ? 97 F4 03 00 AA A8 22 00 91")
    off_cp = scanner_cp.find(bytes(cpptools))
    if off_cp >= 0:
        # replace ? ? ? 97 with 1F 20 03 D5
        cpptools[off_cp + 4 : off_cp + 8] = bytes.fromhex("1F 20 03 D5")
    else:
        raise PatchError("darwin-arm64 cpptools patch pattern not found")


def patch_csharp_win32_x64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Win32-x64 C# patches in-place:
      - vsdbg.dll: signature "84 C0 74 15 83 BB ? ? ? ? 04", patch 74 15 to 74 00
    """
    logger.info("applying win32-x64 C# patches")
    scanner = SigScanner("84 C0 74 15 83 BB ? ? ? ? 04")
    off = scanner.find(bytes(vsdbg))
    if off >= 0:
        vsdbg[off + 2 : off + 4] = bytes.fromhex("74 00")
        logger.info(f"patched vsdbg.dll at offset {off+2}")
    else:
        raise PatchError("win32-x64 C# vsdbg.dll patch pattern not found")


def patch_csharp_win32_arm64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Win32-arm64 C# patches in-place:
      - vsdbg.dll: signature "84 C0 74 15 83 BB ? ? ? ? 04", patch 74 15 to 74 00
      - vsdbg.dll (arm64): signature "01 81 89 9A ? ? ? 94 ? 00 00 36", patch ? 00 00 36 to 1F 20 03 D5
    """
    logger.info("applying win32-arm64 C# patches")

    # Patch x64 vsdbg
    scanner_x64 = SigScanner("84 C0 74 15 83 BB ? ? ? ? 04")
    off_x64 = scanner_x64.find(bytes(vsdbg))
    if off_x64 >= 0:
        vsdbg[off_x64 + 2 : off_x64 + 4] = bytes.fromhex("74 00")
        logger.info(f"patched x64 vsdbg.dll at offset {off_x64+2}")
    else:
        raise PatchError("win32-arm64 C# x64 vsdbg.dll patch pattern not found")

    # Patch arm64 vsdbg
    scanner_arm64 = SigScanner("01 81 89 9A ? ? ? 94 ? 00 00 36")
    off_arm64 = scanner_arm64.find(bytes(vsdbg_arm64))
    if off_arm64 >= 0:
        vsdbg_arm64[off_arm64 + 8 : off_arm64 + 12] = bytes.fromhex("1F 20 03 D5")
        logger.info(f"patched arm64 vsdbg.dll at offset {off_arm64+8}")
    else:
        raise PatchError("win32-arm64 C# arm64 vsdbg.dll patch pattern not found")


def patch_csharp_linux_x64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Linux-x64 C# patches in-place:
      - libvsdbg.so: signature "B9 05 00 00 00 84 C0 74 ?", patch 74 ? to 74 00
    """
    logger.info("applying linux-x64 C# patches")
    scanner = SigScanner("B9 05 00 00 00 84 C0 74 ?")
    off = scanner.find(bytes(vsdbg))
    if off >= 0:
        vsdbg[off + 7 : off + 8] = bytes.fromhex("00")
        logger.info(f"patched libvsdbg.so at offset {off+7}")
    else:
        raise PatchError("linux-x64 C# libvsdbg.so patch pattern not found")


def patch_csharp_linux_arm64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Linux-arm64 C# patches in-place:
      - libvsdbg.so: signature "94 ? 00 00 36 ? ? ? B9 1F 11 00 71", patch ? 00 00 36 to 1F 20 03 D5
    """
    logger.info("applying linux-arm64 C# patches")
    scanner = SigScanner("94 ? 00 00 36 ? ? ? B9 1F 11 00 71")
    off = scanner.find(bytes(vsdbg))
    if off >= 0:
        vsdbg[off + 1 : off + 5] = bytes.fromhex("1F 20 03 D5")
        logger.info(f"patched libvsdbg.so at offset {off}")
    else:
        raise PatchError("linux-arm64 C# libvsdbg.so patch pattern not found")


def patch_csharp_darwin_x64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Darwin-x64 C# patches in-place:
      - libvsdbg.dylib: signature "B9 05 00 00 00 84 C0 74 ?", patch 74 ? to 74 00
    """
    logger.info("applying darwin-x64 C# patches")
    scanner = SigScanner("B9 05 00 00 00 84 C0 74 ?")
    off = scanner.find(bytes(vsdbg))
    if off >= 0:
        vsdbg[off + 7 : off + 8] = bytes.fromhex("00")
        logger.info(f"patched libvsdbg.dylib at offset {off+7}")
    else:
        raise PatchError("darwin-x64 C# libvsdbg.dylib patch pattern not found")


def patch_csharp_darwin_arm64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Darwin-arm64 C# patches in-place:
      - libvsdbg.dylib (x64): signature "B9 ? ? ? ? 84 C0 74 ?", patch 74 ? to 74 00
      - libvsdbg.dylib (arm64): signature "21 B1 94 9A ? ? ? ? ? ? ? ? ? ? ? 94 ? 00 00 34", patch ? 00 00 34 to 1F 20 03 D5
    """
    logger.info("applying darwin-arm64 C# patches")

    # Patch x64 vsdbg
    scanner_x64 = SigScanner("B9 ? ? ? ? 84 C0 74 ?")
    off_x64 = scanner_x64.find(bytes(vsdbg))
    if off_x64 >= 0:
        vsdbg[off_x64 + 7 : off_x64 + 8] = bytes.fromhex("00")
        logger.info(f"patched x64 libvsdbg.dylib at offset {off_x64+7}")
    else:
        raise PatchError("darwin-arm64 C# x64 libvsdbg.dylib patch pattern not found")

    # Patch arm64 vsdbg
    scanner_arm64 = SigScanner("21 B1 94 9A ? ? ? ? ? ? ? ? ? ? ? 94 ? 00 00 34")
    off_arm64 = scanner_arm64.find(bytes(vsdbg_arm64))
    if off_arm64 >= 0:
        vsdbg_arm64[off_arm64 + 16 : off_arm64 + 20] = bytes.fromhex("1F 20 03 D5")
        logger.info(f"patched arm64 libvsdbg.dylib at offset {off_arm64+16}")
    else:
        raise PatchError("darwin-arm64 C# arm64 libvsdbg.dylib patch pattern not found")


def patch_csharp_alpine_x64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Alpine-x64 C# patches in-place:
      - libvsdbg.so: signature "B9 05 00 00 00 84 C0 74 ?", patch 74 ? to 74 00
    """
    # Same as linux-x64
    patch_csharp_linux_x64(vsdbg, vsdbg_arm64)


def patch_csharp_alpine_arm64(vsdbg: bytearray, vsdbg_arm64: bytearray) -> None:
    """
    Apply Alpine-arm64 C# patches in-place:
      - libvsdbg.so: signature "94 ? 00 00 36 ? ? ? B9 1F 11 00 71", patch ? 00 00 36 to 1F 20 03 D5
    """
    # Same as linux-arm64
    patch_csharp_linux_arm64(vsdbg, vsdbg_arm64)


PATCHES = {
    "csharp": {
        "win32-x64": {
            "vsdbg": Path(".debugger/x86_64/vsdbg.dll"),
            "patch_func": patch_csharp_win32_x64,
        },
        "win32-arm64": {
            "vsdbg": Path(".debugger/x86_64/vsdbg.dll"),
            "vsdbg_arm64": Path(".debugger/arm64/vsdbg.dll"),
            "patch_func": patch_csharp_win32_arm64,
        },
        "linux-x64": {
            "vsdbg": Path(".debugger/libvsdbg.so"),
            "patch_func": patch_csharp_linux_x64,
        },
        "linux-arm64": {
            "vsdbg": Path(".debugger/libvsdbg.so"),
            "patch_func": patch_csharp_linux_arm64,
        },
        "darwin-x64": {
            "vsdbg": Path(".debugger/x86_64/libvsdbg.dylib"),
            "patch_func": patch_csharp_darwin_x64,
        },
        "darwin-arm64": {
            "vsdbg": Path(".debugger/x86_64/libvsdbg.dylib"),
            "vsdbg_arm64": Path(".debugger/arm64/libvsdbg.dylib"),
            "patch_func": patch_csharp_darwin_arm64,
        },
        "alpine-x64": {
            "vsdbg": Path(".debugger/libvsdbg.so"),
            "patch_func": patch_csharp_alpine_x64,
        },
        "alpine-arm64": {
            "vsdbg": Path(".debugger/libvsdbg.so"),
            "patch_func": patch_csharp_alpine_arm64,
        },
    },
    "cpptools": {
        "win32-x64": {
            "vsdbg": Path("debugAdapters/vsdbg/bin/vsdbg.dll"),
            "cpptools": Path("bin/cpptools.exe"),
            "patch_func": patch_cpp_win32_64,
        },
        "win32-arm64": {
            "vsdbg": Path("debugAdapters/vsdbg/bin/vsdbg.dll"),
            "cpptools": Path("bin/cpptools.exe"),
            "patch_func": patch_cpp_win32_arm64,
        },
        "linux-x64": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_linux_x64,
        },
        "linux-arm64": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_linux_arm64,
        },
        "linux-armhf": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_linux_armhf,
        },
        "alpine-x64": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_alpine_x64,
        },
        "alpine-arm64": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_alpine_arm64,
        },
        "darwin-x64": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_darwin_x64,
        },
        "darwin-arm64": {
            "cpptools": Path("bin/cpptools"),
            "patch_func": patch_cpp_darwin_arm64,
        },
    },
}


def main(vsix_path: str | None = None) -> None:
    """
    Main function to process a VSIX file.
    Args:
        vsix_path: Path to the VSIX file. If None, uses sys.argv[1].
    Raises:
        UncockerError: If any error occurs during processing.
    """
    try:
        if vsix_path is None:
            if len(argv) < 2:
                raise UncockerError("usage: python uncocker.py <extension.vsix>")
            vsix_path = argv[1]

        vsix_path = Path(vsix_path)
        logger.info(f"processing vsix file: {vsix_path}")

        if not vsix_path.exists():
            raise UncockerError(f"vsix file not found at {vsix_path}")

        base_dir = Path(__file__).parent.resolve()
        unpacked = base_dir / f"{vsix_path.stem}-unpacked"
        out_vsix = base_dir / f"uncocked-{vsix_path.name}"

        logger.info(f"output will be written to: {out_vsix}")

        # Clean up any previous runs
        if unpacked.exists():
            logger.info(f"cleaning up previous unpacked directory: {unpacked}")
            rmtree(unpacked)
        if out_vsix.exists():
            logger.info(f"removing existing output file: {out_vsix}")
            out_vsix.unlink()

        logger.info("unpacking vsix archive...")
        with ZipFile(vsix_path, "r") as z:
            z.extractall(unpacked)
            logger.info(f"extracted {len(z.namelist())} files to {unpacked}")

        # Parse TargetPlatform and extension ID
        manifest = unpacked / "extension.vsixmanifest"
        platform, extension_id = parse_manifest(manifest)
        logger.info(f"target platform: {platform}, extension id: {extension_id}")

        # Get the appropriate patch configuration for the platform
        platform_patches = PATCHES.get(extension_id, {}).get(platform)
        if not platform_patches:
            raise UncockerError(
                f"no patches defined for extension {extension_id} on platform {platform}"
            )

        # Get the paths to the binaries from the patches configuration
        ext_dir = unpacked / "extension"
        vsdbg_path = ext_dir / platform_patches["vsdbg"]
        logger.info(f"looking for vsdbg binary at: {vsdbg_path}")
        if not vsdbg_path.exists():
            raise UncockerError("vsdbg binary not found")

        # Read vsdbg binary
        logger.info("reading vsdbg binary")
        with open(vsdbg_path, "rb") as f:
            vsdbg = bytearray(f.read())
            logger.info(f"read {len(vsdbg)} bytes from vsdbg binary")

        # Handle additional vsdbg if it exists in the configuration
        second_binary = None
        vsdbg_arm64_path = None
        cpptools_path = None
        if "vsdbg_arm64" in platform_patches:
            vsdbg_arm64_path = ext_dir / platform_patches["vsdbg_arm64"]
            logger.info(f"looking for additional vsdbg binary at: {second_binary}")
            if vsdbg_arm64_path.exists():
                with open(vsdbg_arm64_path, "rb") as f:
                    second_binary = bytearray(f.read())
                    logger.info(
                        f"read {len(second_binary)} bytes from additional vsdbg binary"
                    )
        elif "cpptools" in platform_patches:
            cpptools_path = ext_dir / platform_patches["cpptools"]
            logger.info(f"looking for cpptools binary at: {cpptools_path}")
            if cpptools_path.exists():
                with open(cpptools_path, "rb") as f:
                    second_binary = bytearray(f.read())
                    logger.info(f"read {len(second_binary)} bytes from cpptools")

        # Apply the patches
        logger.info(f"applying patches for {extension_id} on {platform}")
        platform_patches["patch_func"](vsdbg, second_binary)

        # Write back the patched binaries
        logger.info("writing patched binaries")
        with open(vsdbg_path, "wb") as f:
            f.write(vsdbg)
        if second_binary is not None:
            if vsdbg_arm64_path is not None:
                with open(vsdbg_arm64_path, "wb") as f:
                    f.write(second_binary)
            elif cpptools_path is not None:
                with open(cpptools_path, "wb") as f:
                    f.write(second_binary)

        # Repack into new VSIX
        logger.info("repacking to new vsix...")
        with ZipFile(out_vsix, "w", ZIP_DEFLATED) as outz:
            add_directory(outz, unpacked, unpacked)
            logger.info(f"created new vsix with {len(outz.namelist())} files")

        logger.info("cleaning up temporary files")
        rmtree(unpacked)
        logger.info(f"written uncocked vsix to {out_vsix}")

    except Exception as e:
        # Clean up on error
        if "unpacked" in locals() and unpacked.exists():
            logger.error("error occurred, cleaning up temporary files")
            rmtree(unpacked)
        raise UncockerError(str(e)) from e


if __name__ == "__main__":
    try:
        main()
    except UncockerError as e:
        logger.error(f"error: {e}")
        exit(1)