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

def get_bgr_color_at_address(f, start_address) -> dict:
	f.seek(start_address)
	bytes = f.read(3)

	return {'blue':bytes[0], 'green':bytes[1], 'red':bytes[2]}

def get_s8_at_address(f, start_address) -> int:
	f.seek(start_address)
	return int.from_bytes(f.read(1), byteorder='little', signed=True)

def get_u8_at_address(f, start_address) -> int:
	f.seek(start_address)
	return int.from_bytes(f.read(1), byteorder='little', signed=False)

def get_s16_at_address(f, start_address):
	f.seek(start_address)
	return int.from_bytes(f.read(2), byteorder='little', signed=True)

def get_u16_at_address(f, start_address) -> int:
	f.seek(start_address)
	return int.from_bytes(f.read(2), byteorder='little', signed=False)

def get_s32_at_address(f, start_address) -> int:
	f.seek(start_address)
	return int.from_bytes(f.read(4), byteorder='little', signed=True)

def get_u32_at_address(f, start_address) -> int:
	f.seek(start_address)
	return int.from_bytes(f.read(4), byteorder='little', signed=False)

def get_float_at_address(f, start_address) -> float:
	f.seek(start_address)
	return struct.unpack('f', f.read(4))[0]

def get_fixed_string_at(f, start_address, length) -> float:
	f.seek(start_address)
	str_buffer = f.read(length)
	return str_buffer.decode('ascii')