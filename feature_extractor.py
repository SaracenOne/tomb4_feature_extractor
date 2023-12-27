import os
import argparse
import hashlib
import pefile

import binary_funcs
import trep
import esse
import leikkuri
import furr_syntax

EXE_DEFAULT_SIZE = 790528
EXE_TREP_EXTENDED_SIZE = 1314816

# Known a list of known hashes for untampered vanilla TRLE exe files.
trle_vanilla_hashes = ["dd351288b437ae4638db9aecca714df4"]

# Known a list of known hashes for extended TRLE exe files but which are otherwise untampered (maybe?).
trle_extended_hashes = ["e2fb8ac766ce0c2bef0e30b20b4e5b38", "0b78a6ecec28ea2725bb163c86b6b747"]

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

	os.system(f'"{exe_path}"')
	
	exe_hash = get_file_hash(exe_path)
	file_size = os.path.getsize(exe_path)

	print(f"The hash of the file {exe_path} is {exe_hash} and is {file_size} bytes.")

	is_extended_exe_size = False

	if file_size == EXE_TREP_EXTENDED_SIZE:
		is_extended_exe_size = True
		print("File size {file_size} matches TREP extended binary size.")

	if exe_hash in trle_vanilla_hashes:
		print("The engine was detected as an unextended vanilla build.")
		return

	if exe_hash in trle_extended_hashes:
		print("The engine was detected as an extended vanilla build.")
		return

	# Attempt to determine if this binary is using memory remapping.
	is_using_remapped_memory = False
	with open(exe_path, 'rb') as f:
		if binary_funcs.get_u8_at_address(f, 0x00000122) == 0x76:
			is_using_remapped_memory = True

	print("Searching for NextGeneration dll...")
	detect_next_generation_dll(path)

	print("Scanning for TREP modifications in exe file...")
	trep.read_exe_file(exe_path, is_extended_exe_size)

	print("Scanning for Leikkuri modifications in exe file...")
	leikkuri.read_exe_file(exe_path)

	if is_extended_exe_size:
		print("Scanning for FURR modifications in exe file...")
		furr_syntax.read_exe_file(exe_path, "syntax.fln", is_using_remapped_memory)
	else:
		print("Unknown EXE file size, skipping FURR extraction in exe file...")

	esse_path = os.path.join(path, "script2.dat")
	print(f"Searching for {esse_path}...")
	if os.path.exists(esse_path):
		print(f"Found eSSe script file at {esse_path}.")
		esse_result = esse.read_binary_file(esse_path)

		print("eSSe script file content:")
		level_id = 0
		for item in esse_result:
			print(f"eSSe data for level {str(level_id)}: {str(item)}")
	else:
		print(f"No eSSe script file found.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Launch an exe file.')
    parser.add_argument('--path', type=str, help='The path to the directory.')
    parser.add_argument('--exe_file', type=str, help='The name of the exe file.')
    args = parser.parse_args()

    detect_tomb4_game(args.path, args.exe_file)
