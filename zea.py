#! /usr/bin/env python3

from __future__ import annotations
import argparse
from dataclasses import dataclass
import struct

LOG_VERBOSITY = 0


def log_print(*args, **kwargs):
    if LOG_VERBOSITY > 0:
        print(*args, **kwargs)


@dataclass
class FileHeader:
    magic: bytes
    decompressed_size: int
    compressed_info_start: int
    data_start: int

    @staticmethod
    def read(input) -> FileHeader:
        return FileHeader(*struct.unpack_from(">4sIII", input))

    def write(self, output):
        struct.pack_into(
            ">4sIII",
            output,
            self.magic,
            self.decompressed_size,
            self.compressed_info_start,
            self.data_start,
        )


MIO_OFF_ADJ = 1
MIO_LEN_ADJ = 3

YAY_OFF_ADJ = 1
YAY_LEN_ADJ = 2
YAY_BIG_LEN_ADJ = 18

YAZ_OFF_ADJ = 1
YAZ_LEN_ADJ = 2
YAZ_BIG_LEN_ADJ = 18


def decompress_mio0(input: bytes, output: bytearray) -> int:
    header = FileHeader.read(input)

    if header.magic != b"MIO0":
        raise BaseException(f"Wrong magic: {header.magic!r} is not 'MIO0'")

    layout_off = layout_start = 0x10
    info_off = info_start = header.compressed_info_start
    data_off = data_start = header.data_start

    layout_bit_index = 8
    bytes_written = 0
    while bytes_written < header.decompressed_size:
        layout_bit_index -= 1

        log_print(f"{layout_off} {layout_bit_index}, ", end="")
        if input[layout_off] & (1 << layout_bit_index):
            log_print(f"APPEND {input[data_off]:X}")
            output.append(input[data_off])
            data_off += 1
            bytes_written += 1
        else:
            length = ((input[info_off] & 0xF0) >> 4) + MIO_LEN_ADJ
            offset = ((input[info_off] & 0xF) << 8) + input[info_off + 1] + MIO_OFF_ADJ

            log_print(
                f"DECOMPRESS {length}, {offset}, {output[ - offset : - offset + length]}"
            )
            num = 0
            while num < length:
                output.append(output[bytes_written - offset + num])
                num += 1

            info_off += 2
            bytes_written += length

        if layout_bit_index == 0:
            layout_bit_index = 8
            layout_off += 1

        # Consider adding checks here for offsets

    if len(output) != header.decompressed_size:
        # raise BaseException(
        print(
            f"Decompression failed: produced size {len(output)} is not equal to header-specified size {header.decompressed_size}"
        )

    return len(output)


def decompress_yay0(input: bytes, output: bytearray) -> int:
    header = FileHeader.read(input)

    if header.magic != b"YAY0":
        raise BaseException(f"Wrong magic: {header.magic!r} is not 'YAY0'")

    layout_off = layout_start = 0x10
    info_off = info_start = header.compressed_info_start
    data_off = data_start = header.data_start

    layout_bit_index = 8
    bytes_written = 0
    while bytes_written < header.decompressed_size:
        layout_bit_index -= 1

        log_print(f"{layout_off} {layout_bit_index}, ", end="")
        if input[layout_off] & (1 << layout_bit_index):
            log_print(f"APPEND {chr(input[data_off])}")
            output.append(input[data_off])
            data_off += 1
            bytes_written += 1
        else:
            length = (input[info_off] & 0xF0) >> 4
            offset = ((input[info_off] & 0xF) << 8) + input[info_off + 1] + YAY_OFF_ADJ
            if length == 0:
                length = input[data_off] + YAY_BIG_LEN_ADJ
                data_off += 1
                log_print("BIG ", end="")
            else:
                length += YAY_LEN_ADJ

            info_off += 2

            log_print(
                f"DECOMPRESS {length}, {offset}: {-offset} to {-offset + length}: {output[ - offset : - offset + length]}"
            )

            num = 0
            while num < length:
                output.append(output[bytes_written - offset + num])
                num += 1

            bytes_written += length

        if layout_bit_index == 0:
            layout_bit_index = 8
            layout_off += 1

        # Consider adding checks here for offsets

    if len(output) != header.decompressed_size:
        raise BaseException(
            f"Decompression failed: produced size {len(output)} is not equal to header-specified size {header.decompressed_size}"
        )

    return len(output)


def decompress_yaz0(input: bytes, output: bytearray) -> int:
    header = FileHeader.read(input)

    if header.magic != b"YAZ0":
        raise BaseException(f"Wrong magic: {header.magic!r} is not 'YAY0'")

    layout_off = layout_start = 0x10
    data_off = layout_off + 1

    layout_bit_index = 8
    bytes_written = 0
    while bytes_written < header.decompressed_size:
        layout_bit_index -= 1

        log_print(f"{layout_off} {layout_bit_index}, ", end="")
        if input[layout_off] & (1 << layout_bit_index):
            log_print(f"APPEND {chr(input[data_off])}")
            output.append(input[data_off])
            data_off += 1
            bytes_written += 1
        else:
            length = (input[data_off] & 0xF0) >> 4
            offset = ((input[data_off] & 0xF) << 8) + input[data_off + 1] + YAZ_OFF_ADJ
            if length == 0:
                length = input[data_off + 2] + YAZ_BIG_LEN_ADJ
                data_off += 1
                log_print("BIG ", end="")
            else:
                length += YAZ_LEN_ADJ

            data_off += 2

            log_print(
                f"DECOMPRESS {length}, {offset}: {-offset} to {-offset + length}: {output[ - offset : - offset + length]}"
            )

            num = 0
            while num < length:
                output.append(output[bytes_written - offset + num])
                num += 1

            bytes_written += length

        if layout_bit_index == 0:
            layout_bit_index = 8
            layout_off = data_off
            data_off += 1

    if len(output) != header.decompressed_size:
        raise BaseException(
            f"Decompression failed: produced size {len(output)} is not equal to header-specified size {header.decompressed_size}"
        )

    return len(output)


def compress_mio0(input: bytes, output: bytearray) -> int:
    return 0


def compress_yay0(input: bytes, output: bytearray) -> int:
    return 0


def compress_yaz0(input: bytes, output: bytearray) -> int:
    return 0


decompress_funcs = {
    "mio0": decompress_mio0,
    "yay0": decompress_yay0,
    "yaz0": decompress_yaz0,
}
compress_funcs = {
    "mio0": compress_mio0,
    "yay0": compress_yay0,
    "yaz0": compress_yaz0,
}

test_mio0_decompressed = b"An itty bitty Hello Kitty ate the Yellow Jello"
test_mio0_compressed = (
    b"MIO0"
    + bytes([0, 0, 0, 0x2E, 0, 0, 0, 0x14, 0, 0, 0, 0x1C])
    + bytes([0xFF, 0xBF, 0xBF, 0xEE])
    + bytes([0x20, 0x05, 0x20, 0x11, 0x10, 0x13, 0x10, 0x1A])
    + b"An itty bHello Kate the Yw J"
)

test_yay0_decompressed = b"An itty bitty Hello Kitty ate the Yellow Jello An itty bitty Hello Kitty ate the Yellow Jello"
test_yay0_compressed = (
    b"YAY0"
    + bytes([0, 0, 0, 0x5D, 0, 0, 0, 0x18, 0, 0, 0, 0x22])
    + bytes([0xFF, 0xBF, 0xBF, 0xEE, 0, 0, 0, 0])
    + bytes([0x30, 0x05, 0x30, 0x11, 0x20, 0x13, 0x30, 0x1A, 0, 0x2E])
    + b"An itty bHello Kate the Yw J\x1C"
)

test_yaz0_decompressed = b"An itty bitty Hello Kitty ate the Yellow Jello An itty bitty Hello Kitty ate the Yellow Jello"
test_yaz0_compressed = (
    b"YAZ0"
    + bytes([0, 0, 0, 0x5D, 0, 0, 0, 0, 0, 0, 0, 0])
    + b"\xFF"
    + b"An itty "  #
    + b"\xBF"
    + b"b"
    + b"\x30\x05"
    + b"Hello "  #
    + b"\xBF"
    + b"K"
    + b"\x30\x11"
    + b"ate th"  #
    + b"\xEE"
    + b"e Y"
    + b"\x20\x13"
    + b"w J"
    + b"\x30\x1A"
    + b"\0"
    + b"\x00\x2E"
    + b"\x1C"  #
)

tests = {
    "mio0": {
        "decompressed": test_mio0_decompressed,
        "compressed": test_mio0_compressed,
    },
    "yay0": {
        "decompressed": test_yay0_decompressed,
        "compressed": test_yay0_compressed,
    },
    "yaz0": {
        "decompressed": test_yaz0_decompressed,
        "compressed": test_yaz0_compressed,
    },
}


def test_decompression(algorithm: str):
    input = tests[algorithm]["compressed"]
    output = bytearray()
    log_print(input)
    decompress_funcs[algorithm](input, output)
    log_print(output)

    correct_output = tests[algorithm]["decompressed"]
    if output == correct_output:
        print(f"{algorithm}: decompression: SUCCESS")
    else:
        print(f"{algorithm}: decompression: FAILURE")
        raise


def main() -> None:
    # test_decompression("mio0")
    # test_decompression("yay0")
    # test_decompression("yaz0")
    # return

    description = "Compress or decompress a file with a given algorithm."
    epilog = ""

    parser = argparse.ArgumentParser(
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("mode", choices=["decompress", "compress"], help="")
    parser.add_argument("input", help="File to read")
    parser.add_argument("output", help="File to write")
    parser.add_argument(
        "-a", "--algorithm", choices=["mio0", "yay0", "yaz0"], help="Algorithm to use"
    )

    args = parser.parse_args()

    algorithm = args.algorithm

    with open(args.input, "rb") as input_file:
        with open(args.output, "wb") as output_file:
            input = input_file.read()
            output = bytearray()

            if args.mode == "decompress":
                decompress_funcs[algorithm](input, output)
            else:
                ...
            output_file.write(output)


if __name__ == "__main__":
    main()
