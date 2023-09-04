import struct
import json
import numpy as np

VERTICAL_SPACING_ADDRESS = 0x000A7278
COMPRESSED_TEXT_FACTOR_ADDRESS = 0x000A7294
FONT_TABLE_ADDRESS = 0x000ACD98
ROUNDING_POINT = 6

def extract_font_data_from_exe(f):
	f.seek(FONT_TABLE_ADDRESS)

	font_table = []

	# Starts at 0x000ACD98
	# Ends at 0x000AD437
	for i in range(0, 106):
		u = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)
		v = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

		w = struct.unpack('<h', f.read(2))[0]
		h = struct.unpack('<h', f.read(2))[0]
		y_offset = struct.unpack('<h', f.read(2))[0]
		top_shade = struct.unpack('<b', f.read(1))[0]
		bottom_shade = struct.unpack('<b', f.read(1))[0]

		font_table.append({"u":u, "v":v, "w":w, "h":h, "y_offset":y_offset, "top_shade":top_shade, "bottom_shade":bottom_shade})

	with open("font_table.txt", "w") as wf:
		for font_table_entry in font_table:
			u = font_table_entry["u"]
			v = font_table_entry["v"]

			w = font_table_entry["w"]
			h = font_table_entry["h"]
			y_offset = font_table_entry["y_offset"]
			top_shade = font_table_entry["top_shade"]
			bottom_shade = font_table_entry["bottom_shade"]
			wf.write("{" + f"{u}F,{v}F,{w},{h},{y_offset},{top_shade},{bottom_shade}" + "},\n")

	f.seek(VERTICAL_SPACING_ADDRESS)
	vertical_spacing = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

	f.seek(COMPRESSED_TEXT_FACTOR_ADDRESS)
	compressed_text_factor = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

	with open("font_info.txt", "w") as wf:
		wf.write(f"vertical_spacing: {vertical_spacing}F")
		wf.write(f"compressed_text_factor: {compressed_text_factor}F")


def read_exe_file(exe_file_path):
	with open(exe_file_path, 'rb') as f:
		extract_font_data_from_exe(f)

read_exe_file("tomb4.exe")
