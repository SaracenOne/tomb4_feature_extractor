import struct
import numpy as np

HEIGHT_ADDRESS = 0x000A728C
WIDTH_ADDRESS = 0x000A7290

VERTICAL_SPACING_ADDRESS = 0x000A7278
COMPRESSED_TEXT_FACTOR_ADDRESS = 0x000A7294
FONT_TABLE_ADDRESS = 0x000ACD98
ROUNDING_POINT = 6

default_font_table = [
	{
		"u":0.682353,
		"v":0.203922,
		"w":4,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.384314,
		"v":0.227451,
		"w":7,
		"h":5,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":5
	},
	{
		"u":0.321569,
		"v":0.101961,
		"w":14,
		"h":12,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":11
	},
	{
		"u":0.305882,
		"v":0.14902,
		"w":10,
		"h":14,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":13
	},
	{
		"u":0.839216,
		"v":0.05098,
		"w":15,
		"h":12,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":12
	},
	{
		"u":0.156863,
		"v":0.101961,
		"w":14,
		"h":12,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":11
	},
	{
		"u":0.619608,
		"v":0.223529,
		"w":5,
		"h":5,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":4
	},
	{
		"u":0.8,
		"v":0.152941,
		"w":6,
		"h":16,
		"y_offset":-12,
		"top_shade":0,
		"bottom_shade":13
	},
	{
		"u":0.133333,
		"v":0.156863,
		"w":6,
		"h":16,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":14
	},
	{
		"u":0.721569,
		"v":0.231373,
		"w":5,
		"h":5,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":4
	},
	{
		"u":0.086275,
		"v":0.156863,
		"w":11,
		"h":11,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":11
	},
	{
		"u":0.698039,
		"v":0.231373,
		"w":5,
		"h":5,
		"y_offset":-2,
		"top_shade":8,
		"bottom_shade":12
	},
	{
		"u":0.415686,
		"v":0.235294,
		"w":8,
		"h":3,
		"y_offset":-4,
		"top_shade":6,
		"bottom_shade":9
	},
	{
		"u":0.447059,
		"v":0.235294,
		"w":5,
		"h":4,
		"y_offset":-2,
		"top_shade":8,
		"bottom_shade":11
	},
	{
		"u":0.831373,
		"v":0.14902,
		"w":9,
		"h":15,
		"y_offset":-12,
		"top_shade":0,
		"bottom_shade":12
	},
	{
		"u":0.345098,
		"v":0.192157,
		"w":10,
		"h":10,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":11
	},
	{
		"u":0.784314,
		"v":0.215686,
		"w":6,
		"h":10,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":11
	},
	{
		"u":0.180392,
		"v":0.203922,
		"w":9,
		"h":10,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":11
	},
	{
		"u":0.345098,
		"v":0.14902,
		"w":8,
		"h":11,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":12
	},
	{
		"u":0.243137,
		"v":0.156863,
		"w":11,
		"h":11,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":12
	},
	{
		"u":0.556863,
		"v":0.188235,
		"w":9,
		"h":12,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":12
	},
	{
		"u":0.909804,
		"v":0.196078,
		"w":9,
		"h":11,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":11
	},
	{
		"u":0.470588,
		"v":0.184314,
		"w":9,
		"h":12,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":12
	},
	{
		"u":0.086275,
		"v":0.2,
		"w":9,
		"h":11,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":11
	},
	{
		"u":0.431373,
		"v":0.192157,
		"w":9,
		"h":11,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":12
	},
	{
		"u":0.596078,
		"v":0.223529,
		"w":5,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.533333,
		"v":0.223529,
		"w":5,
		"h":10,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":12
	},
	{
		"u":0.698039,
		"v":0.156863,
		"w":12,
		"h":10,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":11
	},
	{
		"u":0.823529,
		"v":0.207843,
		"w":11,
		"h":7,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":9
	},
	{
		"u":0.941176,
		"v":0.156863,
		"w":12,
		"h":10,
		"y_offset":-8,
		"top_shade":3,
		"bottom_shade":11
	},
	{
		"u":0.047059,
		"v":0.152941,
		"w":10,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.258824,
		"v":0.05098,
		"w":16,
		"h":14,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":13
	},
	{
		"u":0.509804,
		"v":0.05098,
		"w":14,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.839216,
		"v":0.098039,
		"w":13,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.517647,
		"v":0.137255,
		"w":11,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.0,
		"v":0.101961,
		"w":13,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.054902,
		"v":0.101961,
		"w":13,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.258824,
		"v":0.105882,
		"w":12,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.713725,
		"v":0.105882,
		"w":12,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.784314,
		"v":0.05098,
		"w":14,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.870588,
		"v":0.211765,
		"w":5,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.219608,
		"v":0.203922,
		"w":5,
		"h":16,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":14
	},
	{
		"u":0.901961,
		"v":0.058824,
		"w":13,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.564706,
		"v":0.137255,
		"w":11,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.188235,
		"v":0.05098,
		"w":18,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.564706,
		"v":0.05098,
		"w":14,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.211765,
		"v":0.101961,
		"w":12,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.784314,
		"v":0.101961,
		"w":12,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.941176,
		"v":0.0,
		"w":14,
		"h":15,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":13
	},
	{
		"u":0.619608,
		"v":0.05098,
		"w":14,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.611765,
		"v":0.137255,
		"w":11,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.67451,
		"v":0.05098,
		"w":14,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.384314,
		"v":0.05098,
		"w":15,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.321569,
		"v":0.05098,
		"w":15,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.094118,
		"v":0.05098,
		"w":23,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.729412,
		"v":0.05098,
		"w":13,
		"h":14,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":12
	},
	{
		"u":0.447059,
		"v":0.05098,
		"w":15,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.894118,
		"v":0.109804,
		"w":12,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.243137,
		"v":0.235294,
		"w":6,
		"h":4,
		"y_offset":-4,
		"top_shade":6,
		"bottom_shade":9
	},
	{
		"u":0.972549,
		"v":0.231373,
		"w":6,
		"h":4,
		"y_offset":-4,
		"top_shade":6,
		"bottom_shade":9
	},
	{
		"u":0.345098,
		"v":0.231373,
		"w":8,
		"h":4,
		"y_offset":-4,
		"top_shade":6,
		"bottom_shade":9
	},
	{
		"u":0.556863,
		"v":0.235294,
		"w":7,
		"h":3,
		"y_offset":-3,
		"top_shade":7,
		"bottom_shade":9
	},
	{
		"u":0.470588,
		"v":0.231373,
		"w":8,
		"h":4,
		"y_offset":-4,
		"top_shade":6,
		"bottom_shade":9
	},
	{
		"u":0.94902,
		"v":0.231373,
		"w":5,
		"h":5,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":4
	},
	{
		"u":0.384314,
		"v":0.192157,
		"w":11,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.376471,
		"v":0.137255,
		"w":11,
		"h":14,
		"y_offset":-12,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.282353,
		"v":0.203922,
		"w":9,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.0,
		"v":0.152941,
		"w":11,
		"h":12,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":11
	},
	{
		"u":0.643137,
		"v":0.203922,
		"w":9,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.658824,
		"v":0.14902,
		"w":10,
		"h":14,
		"y_offset":-12,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.470588,
		"v":0.137255,
		"w":12,
		"h":12,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":14
	},
	{
		"u":0.423529,
		"v":0.137255,
		"w":11,
		"h":14,
		"y_offset":-12,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.760784,
		"v":0.105882,
		"w":6,
		"h":12,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":11
	},
	{
		"u":0.156863,
		"v":0.2,
		"w":6,
		"h":16,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":14
	},
	{
		"u":0.109804,
		"v":0.101961,
		"w":12,
		"h":14,
		"y_offset":-12,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.321569,
		"v":0.203922,
		"w":6,
		"h":13,
		"y_offset":-11,
		"top_shade":0,
		"bottom_shade":11
	},
	{
		"u":0.376471,
		"v":0.101961,
		"w":18,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.596078,
		"v":0.188235,
		"w":12,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.243137,
		"v":0.2,
		"w":10,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.956863,
		"v":0.058824,
		"w":11,
		"h":13,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":14
	},
	{
		"u":0.203922,
		"v":0.152941,
		"w":10,
		"h":13,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":14
	},
	{
		"u":0.039216,
		"v":0.203922,
		"w":10,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.745098,
		"v":0.203922,
		"w":9,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.0,
		"v":0.2,
		"w":9,
		"h":11,
		"y_offset":-9,
		"top_shade":2,
		"bottom_shade":11
	},
	{
		"u":0.698039,
		"v":0.196078,
		"w":11,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.509804,
		"v":0.188235,
		"w":12,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.517647,
		"v":0.101961,
		"w":18,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.94902,
		"v":0.196078,
		"w":11,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.156863,
		"v":0.14902,
		"w":11,
		"h":13,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":14
	},
	{
		"u":0.909804,
		"v":0.160784,
		"w":8,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.870588,
		"v":0.160784,
		"w":9,
		"h":13,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":14
	},
	{
		"u":0.509804,
		"v":0.223529,
		"w":6,
		"h":9,
		"y_offset":-7,
		"top_shade":4,
		"bottom_shade":11
	},
	{
		"u":0.760784,
		"v":0.152941,
		"w":10,
		"h":13,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":12
	},
	{
		"u":0.12549,
		"v":0.219608,
		"w":5,
		"h":12,
		"y_offset":-10,
		"top_shade":1,
		"bottom_shade":11
	},
	{
		"u":0.0,
		"v":0.05098,
		"w":24,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.752941,
		"v":0.0,
		"w":24,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.658824,
		"v":0.0,
		"w":24,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.847059,
		"v":0.0,
		"w":24,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.588235,
		"v":0.101961,
		"w":18,
		"h":9,
		"y_offset":-8,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.658824,
		"v":0.101961,
		"w":13,
		"h":12,
		"y_offset":-9,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.447059,
		"v":0.101961,
		"w":18,
		"h":9,
		"y_offset":-8,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.941176,
		"v":0.109804,
		"w":13,
		"h":12,
		"y_offset":-9,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.0,
		"v":0.0,
		"w":41,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.329412,
		"v":0.0,
		"w":41,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.164706,
		"v":0.0,
		"w":41,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	},
	{
		"u":0.494118,
		"v":0.0,
		"w":41,
		"h":13,
		"y_offset":-10,
		"top_shade":6,
		"bottom_shade":11
	}
]

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
			wf.write("{" + f"\"u\":{u},\"v\":{v},\"w\":{w},\"h\":{h},\"y_offset\":{y_offset},\"top_shade\":{top_shade},\"bottom_shade\":{bottom_shade}" + "},\n")

	f.seek(WIDTH_ADDRESS)
	width = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

	f.seek(HEIGHT_ADDRESS)
	height = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

	f.seek(VERTICAL_SPACING_ADDRESS)
	vertical_spacing = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

	f.seek(COMPRESSED_TEXT_FACTOR_ADDRESS)
	compressed_text_factor = round(struct.unpack('<f', f.read(4))[0], ROUNDING_POINT)

	font_data = {}

	if int(width) != 512:
		font_data["custom_glyph_scale_width"] = int(width)

	if int(height) != 240:
		font_data["custom_glyph_scale_height"] = int(height)

	if vertical_spacing != 0.075:
		font_data["custom_vertical_spacing"] = vertical_spacing

	if compressed_text_factor != 0.75:
		font_data["custom_compressed_text_factor"] = compressed_text_factor

	for i in range(0, len(default_font_table)):
		if \
		default_font_table[i]['u'] != font_table[i]['u'] or \
		default_font_table[i]['v'] != font_table[i]['v'] or \
		default_font_table[i]['w'] != font_table[i]['w'] or \
		default_font_table[i]['h'] != font_table[i]['h'] or \
		default_font_table[i]['y_offset'] != font_table[i]['y_offset'] or \
		default_font_table[i]['top_shade'] != font_table[i]['top_shade'] or \
		default_font_table[i]['bottom_shade'] != font_table[i]['bottom_shade']:
			font_data['custom_font_table'] = font_table
			break

	return font_data

def read_exe_file(exe_file_path):
	with open(exe_file_path, 'rb') as f:
		return extract_font_data_from_exe(f)
