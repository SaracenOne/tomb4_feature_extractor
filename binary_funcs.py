import struct

def compare_data_at_address(f, start_address, data_block) -> bool:
	f.seek(start_address)
	read_bytes = f.read(len(data_block))
	if read_bytes == data_block:
		return True

	return False

def is_nop_at_range(f, start_address, end_address) -> bool:
	f.seek(start_address)
	read_bytes = f.read((end_address - start_address) + 1)
	for byte in read_bytes:
		if byte != 0x90:
			return False

	return True

def read_bgr(f) -> dict:
	bytes = f.read(3)

	return {'b':bytes[0], 'g':bytes[1], 'r':bytes[2]}

def read_rgb(f) -> dict:
	bytes = f.read(3)

	return {'r':bytes[0], 'g':bytes[1], 'b':bytes[2]}

def read_s8(f) -> int:
	return int.from_bytes(f.read(1), byteorder='little', signed=True)

def read_u8(f) -> int:
	return int.from_bytes(f.read(1), byteorder='little', signed=False)

def read_s16(f) -> int:
	return int.from_bytes(f.read(2), byteorder='little', signed=True)

def read_u16(f) -> int:
	return int.from_bytes(f.read(2), byteorder='little', signed=False)

def read_s32(f) -> int:
	return int.from_bytes(f.read(4), byteorder='little', signed=True)

def read_u32(f) -> int:
	return int.from_bytes(f.read(4), byteorder='little', signed=False)

def skip_bytes(f, bytes):
	f.seek(bytes, 1)

def read_float(f) -> int:
	return struct.unpack('f', f.read(4))[0]

def get_bgr_color_at_address(f, start_address) -> dict:
	f.seek(start_address)
	return read_bgr(f)

def get_rgb_color_at_address(f, start_address) -> dict:
	f.seek(start_address)
	return read_rgb(f)

def get_s8_at_address(f, start_address) -> int:
	f.seek(start_address)
	return read_s8(f)

def get_u8_at_address(f, start_address) -> int:
	f.seek(start_address)
	return read_u8(f)

def get_s16_at_address(f, start_address):
	f.seek(start_address)
	return read_s16(f)

def get_u16_at_address(f, start_address) -> int:
	f.seek(start_address)
	return read_u16(f)

def get_s32_at_address(f, start_address) -> int:
	f.seek(start_address)
	return read_s32(f)

def get_u32_at_address(f, start_address) -> int:
	f.seek(start_address)
	return read_u32(f)

def get_float_at_address(f, start_address) -> float:
	f.seek(start_address)
	return read_float(f)

def get_fixed_string_at(f, start_address, length) -> str:
    f.seek(start_address)
    str_buffer = f.read(length)
    str_decoded = str_buffer.split(b'\x00', 1)[0].decode('ascii')  # stop at first null character
	
    return str_decoded