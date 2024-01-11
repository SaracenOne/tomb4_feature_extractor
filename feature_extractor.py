import os
import argparse
import hashlib
import re
import pefile
import json

import binary_funcs
import trle_patch_binary
import esse
import leikkuri
import furr_syntax

EXE_DEFAULT_SIZE = 790528
EXE_TREP_EXTENDED_SIZE = 1314816

# Known a list of known hashes for untampered vanilla TRLE exe files.
trle_vanilla_hashes = ["dd351288b437ae4638db9aecca714df4"]

# Known a list of known hashes for extended TRLE exe files but which are otherwise untampered (maybe?).
trle_extended_hashes = ["e2fb8ac766ce0c2bef0e30b20b4e5b38", "0b78a6ecec28ea2725bb163c86b6b747"]

def extract_integer(s):
    numbers = re.findall(r'\d+', s)
    return int(''.join(numbers))

def contains_plus(s):
    return '+' in s

def get_file_hash(exe_path):
    # Use MD5 hash algorithm
    hasher = hashlib.md5()

    with open(exe_path, 'rb') as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b''):
            hasher.update(byte_block)

    return hasher.hexdigest()

def get_pe_file_version(pe_path):
	try:
		pe = pefile.PE(pe_path)
	except OSError as e:
		print(f"Couldn't open file: {e}")
		return None
	except pefile.PEFormatError as e:
		print(f"Invalid PE file: {e}")
		return None

	if hasattr(pe, 'FileInfo'):
		for file_info in pe.FileInfo[0]:
			if file_info.Key.decode('utf-8') == "StringFileInfo":
				for st in file_info.StringTable:
					for entry in st.entries.items():
						if entry[0].decode('utf-8') == "FileVersion":
							version_string = entry[1].decode('utf-8')
							version_split = tuple(part for part in version_string.split(', '))

							return version_split
	return None

def detect_next_generation_dll(path):
	ng_dll_path = os.path.join(path, "Tomb_NextGeneration.dll")

	# Detect if the path is valid.
	if not os.path.exists(ng_dll_path):
		print(f"No Tomb_NextGeneration.dll at {ng_dll_path}. Returning.")
		return
	
	version = get_pe_file_version(ng_dll_path)

	return version

def detect_tomb4_game(path=None, exe_file=None):
	while path is None or path == "":
		path = input("Please enter the path to the directory: ")

	# Detect if the path is valid.
	if not os.path.exists(path):
		print(f"The directory {path} does not exist.")
		return
        
	if exe_file is None:
		exe_file = input("Please enter the name of the exe file (default is tomb4.exe): ")
    
	# If we still are not provided an exe file
	if exe_file == "":
		exe_file = "tomb4.exe"

	# Check if the file has the .exe extension
	if not exe_file.lower().endswith('.exe'):
		exe_file += '.exe'
	
	exe_path = os.path.join(path, exe_file)

	if not os.path.exists(exe_path):
		print(f"The file {exe_path} does not exist.")
		return

	exe_hash = get_file_hash(exe_path)
	exe_file_size = os.path.getsize(exe_path)

	print(f"The hash of the file {exe_path} is {exe_hash} and is {exe_file_size} bytes.")

	is_extended_exe_size = False

	if exe_file_size == EXE_TREP_EXTENDED_SIZE:
		is_extended_exe_size = True
		print("File size {file_size} matches TREP extended binary size.")

	if exe_hash in trle_vanilla_hashes:
		print("The engine was detected as an unextended vanilla build.")

	if exe_hash in trle_extended_hashes:
		print("The engine was detected as an extended vanilla build.")

	# Attempt to determine if this binary is using memory remapping.
	is_using_remapped_memory = False
	with open(exe_path, 'rb') as f:
		if binary_funcs.get_u8_at_address(f, 0x00000122) == 0x76:
			is_using_remapped_memory = True

	print("Searching for NextGeneration dll...")
	trng_version = detect_next_generation_dll(path)

	print("Scanning for TREP modifications in exe file...")
	patch_data = trle_patch_binary.read_binary_file(exe_path, is_extended_exe_size, is_using_remapped_memory, False)

	patches_path = os.path.join(path, "patches.bin")
	print(f"Searching for {patches_path}...")
	if os.path.exists(patches_path):
		print(f"Found FLEP patches file at {patches_path}.")
		patch_data = trle_patch_binary.read_binary_file(patches_path, True, False, True)

	audio_info = patch_data["audio_info"]
	bars_info = patch_data["bars_info"]
	gfx_info = patch_data["gfx_info"]
	environment_info = patch_data["environment_info"]
	misc_info = patch_data["misc_info"]
	stat_info = patch_data["stat_info"]
	meta_info = patch_data["meta_info"]
	lara_info = patch_data["lara_info"]

	print("Scanning for Leikkuri modifications in exe file...")
	font_info = leikkuri.read_exe_file(exe_path)

	esse_path = os.path.join(path, "script2.dat")
	esse_result = []
	print(f"Searching for {esse_path}...")
	if os.path.exists(esse_path):
		print(f"Found eSSe script file at {esse_path}.")
		esse_result = esse.read_binary_file(esse_path, patch_data)

		print("eSSe script file content:")
		level_id = 0
		for item in esse_result:
			print(f"eSSe data for level {str(level_id)}: {str(item)}")
			level_id += 1
	else:
		print(f"No eSSe script file found.")

	furr_data = {}

	if is_extended_exe_size:
		if meta_info["furr_support"]:
			print("Scanning for FURR modifications in exe file...")
			furr_data = furr_syntax.read_exe_file(exe_path, "syntax.fln", is_using_remapped_memory)
		else:
			print("FURR support not detected. Skipping.")
	else:
		print("Unknown EXE file size, skipping FURR extraction in exe file...")

	# Generate Mod Config

	output_mod_config = {}

	global_info = {}
	global_info["trng_version_major"] = 0
	global_info["trng_version_minor"] = 0
	global_info["trng_version_maintainence"] = 0
	global_info["trng_version_build"] = 0
	global_info["trng_version_is_plus"] = 0

	global_info["furr_data"] = furr_data

	if exe_file_size != EXE_DEFAULT_SIZE and exe_file_size != EXE_TREP_EXTENDED_SIZE:
		if trng_version and len(trng_version) == 4:
			global_info["trng_version_major"] = int(trng_version[0])
			global_info["trng_version_minor"] = int(trng_version[1])
			global_info["trng_version_maintainence"] = int(trng_version[2])
			global_info["trng_version_build"] = int(extract_integer(trng_version[3]))
			global_info["trng_version_is_plus"] = contains_plus(trng_version[3])
	else:
		global_info["trng_flipeffects_enabled"] = False
		global_info["trng_rollingball_extended_ocb"] = False
		global_info["trng_statics_extended_ocb"] = False
		global_info["trng_pushable_extended_ocb"] = False

		if is_extended_exe_size:
			with open(exe_path, 'rb') as f:
				if not binary_funcs.is_nop_at_range(f, 0x000EF800, 0x000EF922):
					global_info["trep_using_extended_saves"] = True

	global_level_info = {}

	global_level_info["audio_info"] = audio_info
	global_level_info["bars_info"] = bars_info
	global_level_info["gfx_info"] = gfx_info
	global_level_info["environment_info"] = environment_info
	global_level_info["misc_info"] = misc_info
	global_level_info["stat_info"] = stat_info
	global_level_info["font_info"] = font_info
	global_level_info["lara_info"] = lara_info

	#
	output_mod_config["global_info"] = global_info
	output_mod_config["global_level_info"] = global_level_info
	output_mod_config["levels"] = esse_result

	json_data = json.dumps(output_mod_config, indent=4, separators=(',', ':'))

	# Write JSON string to a file
	with open(os.path.join(path, "game_mod_config.json"), 'w') as file:
		file.write(json_data)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Launch an exe file.')
    parser.add_argument('--path', type=str, help='The path to the directory.')
    parser.add_argument('--exe_file', type=str, help='The name of the exe file.')
    args = parser.parse_args()

    detect_tomb4_game(args.path, args.exe_file)
