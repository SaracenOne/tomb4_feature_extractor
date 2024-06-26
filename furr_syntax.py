import os
import struct
import re

MAX_NOPS = 128

ONESHOT_OPCODE_DEFAULT = 				[bytes.fromhex("5351B900009900BB"), bytes.fromhex("2F000000"), bytes.fromhex("83EB2FC6041901595B66C705FECB4A00"), bytes.fromhex("2F00")]
ONESHOT_OPCODE_REMAPED_SCENE_MEMORY = 	[bytes.fromhex("5351B90000D900BB"), bytes.fromhex("2F000000"), bytes.fromhex("83EB2FC6041901595B66C705FECB4A00"), bytes.fromhex("2F00")]

FLIPEFFECT_TABLE_ADDRESS = 0xc1000
FLIPEFFECT_DATA_ADDRESS = 0xc3100
RACETIMER_EVENT_DATA_ADDRESS = 0x00101000

FUNCTION_ADDRESS_OFFSET = struct.unpack('<I', bytes.fromhex("FBAE7EFF"))[0] # This may be different on different binaries?

RACETIMER_EVENT_NOTIFY = bytes.fromhex("FF 05 46 77 7F 00")
RACETIMER_EVENT_START = bytes.fromhex("81 3D 46 77 7F 00")

BASE_ADDRESS_DEFAULT = 8474880
BASE_ADDRESS_REMAPPED_SCENE_MEMORY = 12669184

FIRST_CUSTOM_FLIPEFFECT = 47
LAST_CUSTOM_FLIPEFFECT = 512
	
def get_base_address(using_remapped_memory):
	if using_remapped_memory:
		return BASE_ADDRESS_REMAPPED_SCENE_MEMORY
	else:
		return BASE_ADDRESS_DEFAULT
	
def get_oneshot_opcode(using_remapped_memory):
	if using_remapped_memory:
		return ONESHOT_OPCODE_REMAPED_SCENE_MEMORY
	else:
		return ONESHOT_OPCODE_DEFAULT

# TODO: Re-examine this function!
def split_byte_array(byte_array: bytearray, positions: list, sizes: list) -> list:
	if len(positions) != len(sizes):
		raise IndexError("Positions and size arrays do not match in size.")
	
	result = []
	#sorted_indices = sorted(range(len(positions)), key=lambda i: positions[i])
	#sorted_positions = [positions[i] for i in sorted_indices]
	#sorted_sizes = [sizes[i] for i in sorted_indices]

	sorted_positions = positions
	sorted_sizes = sizes

	start = 0
	for pos, size in zip(sorted_positions, sorted_sizes):
		if pos > start:
			result.append(byte_array[start:pos])
		result.append(byte_array[pos:pos+size])
		start = pos + size
	if start < len(byte_array):
		result.append(byte_array[start:])
	return result
	
def get_size_for_variant_type(type):
	match type:
		case "ASSIGN_BYTE":
			return 1
		case "SIGNEDBYTE":
			return 1
		case "UNSIGNEDBYTE":
			return 1
		case "ASSIGN_INTEGER":
			return 2
		case "SIGNEDINTEGER":
			return 2
		case "UNSIGNEDINTEGER":
			return 2
		case "ASSIGN_LONG":
			return 4
		case "LONG":
			return 4
		case "ADDRESS":
			return 4 # 3 For // address
		case "FLIPEFFECT":
			return 4
		case "TIME":
			return 4
		case "ASSIGN_HEX":
			return 4 # Check this, might be 2
		case None:
			return None
		case _:
			raise NameError("Unknown type")
		
def read_arg(arg, type):
	match type:
		case "ASSIGN_BYTE":
			return struct.unpack('<B', arg)[0]
		case "SIGNEDBYTE":
			return struct.unpack('<b', arg)[0]
		case "UNSIGNEDBYTE":
			return struct.unpack('<B', arg)[0]
		case "ASSIGN_INTEGER":
			return struct.unpack('<H', arg)[0]
		case "SIGNEDINTEGER":
			return struct.unpack('<h', arg)[0]
		case "UNSIGNEDINTEGER":
			return struct.unpack('<H', arg)[0]
		case "ASSIGN_LONG":
			return struct.unpack('<I', arg)[0]
		case "LONG":
			return struct.unpack('<i', arg)[0]
		case "ADDRESS":
			return struct.unpack('<I', arg)[0] # TODO
		case "FLIPEFFECT":
			return struct.unpack('<I', arg)[0] # TODO
		case "TIME":
			return struct.unpack('<I', arg)[0] # TODO
		case "ASSIGN_HEX":
			return struct.unpack('<I', arg)[0] # TODO - check this, might be 2
		case None:
			return None
		case _:
			raise NameError("Unknown type")
		
def create_flipeffect_table_entry_for_opcode(opcode, first_arg, second_arg):
	if opcode["reverse_args"]:
		first_arg_typed = read_arg(first_arg, opcode["second_arg_type"])
		second_arg_typed = read_arg(second_arg, opcode["first_arg_type"])
	else:
		first_arg_typed = read_arg(first_arg, opcode["first_arg_type"])
		second_arg_typed = read_arg(second_arg, opcode["second_arg_type"])

	if opcode["reverse_args"]:
		final_opcode = [opcode["function_name"], (second_arg_typed), (first_arg_typed)]
	else:
		final_opcode = [opcode["function_name"], (first_arg_typed), (second_arg_typed)]

	return final_opcode

def get_split_byte_arrays_with_args(my_bytes, first_arg_type, second_arg_type, first_arg_pos, second_arg_pos, first_arg_is_local_offset, second_arg_is_local_offset, reverse_args):
	position_arr = []
	sizes_arr = []

	first_arg_variant_size = get_size_for_variant_type(first_arg_type)
	if first_arg_variant_size != None:
		if first_arg_is_local_offset:
			first_arg_pos -= 1
		position_arr.append(first_arg_pos)
		sizes_arr.append(first_arg_variant_size)
	second_arg_variant_size = get_size_for_variant_type(second_arg_type)
	if second_arg_variant_size != None:
		if second_arg_is_local_offset:
			second_arg_pos -= 1
		# To work around both variants being aligned next to each other
		if second_arg_pos == first_arg_pos + first_arg_variant_size:
			position_arr.append(second_arg_pos)
			sizes_arr.append(0)

		position_arr.append(second_arg_pos)
		sizes_arr.append(second_arg_variant_size)

	if reverse_args:
		position_arr.reverse()
		sizes_arr.reverse()

	final_split_result = []
	if len(position_arr) > 0:
		final_split_result = split_byte_array(my_bytes, position_arr, sizes_arr)
	else:
		final_split_result = [my_bytes]

	return final_split_result


def find_all_addresses(string):
	pattern = "//"

	modified_string = string
	counted = 0

	address_array = []

	for match in re.finditer(pattern, string):
		num = match.start()
		address_array.append(int((num - counted) / 2))
		counted += 2

	return address_array


def load_syntax_file():
	opcodes = []

	syntax_table = [
		{"filename":"syntaxTREP.fln", "description":"Final TREP FURR Syntax file"},
		{"filename":"syntaxEarly.fln", "description":"Early TREP FURR Syntax file"},
		{"filename":"syntaxT4L.fln", "description":"T4Larson Syntax file"}
	]

	syntax_file_name = ""
	selection = 0

	while True:
		count = 1
		print(
			"""Choose select the number for the FURR syntax file you wish to attempt extraction from. Different choices my yield different success rates at extracting FURR data: 
			""")
		
		for option in syntax_table:
			print(str(count) + ". " + option["description"] + (" (Default)" if count == 1 else ""))
			count += 1
		
		user_input = input("Enter your choice (1-3): ")

		if user_input in ["", "1", "2", "3"]:
			if user_input == "":
				selection = 1
			else:
				selection = int(user_input)
			break
		else:
			print("Invalid input. Please enter a number between 1 and 3, or leave it blank.")

	syntax_file_name = syntax_table[selection-1]["filename"]

	script_dir = os.path.dirname(os.path.abspath(__file__))
	full_path = os.path.join(script_dir, syntax_file_name)

	print("Attempting to open script syntax file: " + full_path)

	with open(full_path, 'r') as file:
		for line in file:
			if line.startswith(';') or line.startswith('!') or not line.strip():
				continue
			tokens = line.split()
			address_table = result = find_all_addresses(tokens[0])
			assembly_string = tokens[0].replace('//', '')
			first_arg_pos = int(tokens[1])
			second_arg_pos = int(tokens[2])
			function_name = tokens[3]

			first_arg_is_local_offset = False
			second_arg_is_local_offset = False

			# TEMPORARY HACK
			if (function_name == "CALL"):
				first_arg_is_local_offset = True

			first_arg_type = None
			second_arg_type = None
			if len(tokens) > 4:
				first_arg_type = tokens[4]
				if len(tokens) > 5:
					second_arg_type = tokens[5]

			reverse_args = True if (second_arg_pos < first_arg_pos and second_arg_type != None) else False

			assembly_bytes = bytes.fromhex(assembly_string)
			total_length = len(assembly_bytes)
			
			split_byte_arrays = get_split_byte_arrays_with_args(assembly_bytes, first_arg_type, second_arg_type, first_arg_pos, second_arg_pos, first_arg_is_local_offset, second_arg_is_local_offset, reverse_args)

			opcodes.append({
				"byte_arrays":split_byte_arrays,
				"function_name":function_name,
				"reverse_args":reverse_args,
				"address_table":address_table,
				"total_length":total_length,
				"first_arg_type":first_arg_type,
				"second_arg_type":second_arg_type})
			
	return opcodes
	
def convert_local_addresses_to_global(command_bytes, command_base_position, address_table, is_using_remapped_memory):
	command_bytes_array = bytearray(command_bytes)

	for address_offset in address_table:
		if address_offset <= len(command_bytes) - 4:			
			local_address_byte_array = command_bytes[address_offset:address_offset+4]

			local_address_as_int = struct.unpack('<I', local_address_byte_array)[0]

			if is_using_remapped_memory:
				global_address_as_int = (local_address_as_int - 0xff413000) + 0x00028105 - 0x2100 + (address_offset-1) + command_base_position
			else:
				global_address_as_int = (local_address_as_int - 0xff813000) + 0x00028105 - 0x2100 + (address_offset-1) + command_base_position
			
			if global_address_as_int > 0xffffffff:
				global_address_as_int -= 0xffffffff
			elif global_address_as_int < 0x00000000:
				global_address_as_int += 0xffffffff

			global_address_byte_array = struct.pack('>I', global_address_as_int)

			command_bytes_array[address_offset:address_offset+4] = bytearray(global_address_byte_array)
	return bytes(command_bytes_array)

def get_hex_string(buffer):
    hex_string = ''.join(f'\\x{byte:02x}' for byte in buffer)
    return hex_string

def scan_for_possible_commands(f, opcode_list, command_position, is_using_remapped_memory):
	possible_commands = []

	for opcode in opcode_list:
		f.seek(command_position)

		first_arg = ""
		second_arg = ""
			

		byte_arrays = opcode["byte_arrays"]
		total_length = opcode["total_length"]

		original_data_buffer = f.read(total_length)
		addressed_fixed_data_buffer = convert_local_addresses_to_global(original_data_buffer, command_position - FLIPEFFECT_TABLE_ADDRESS, opcode["address_table"], is_using_remapped_memory)

		if byte_arrays[0] == addressed_fixed_data_buffer[0:len(byte_arrays[0])]:
			if len(byte_arrays) > 1:
				first_arg = original_data_buffer[len(byte_arrays[0]) : len(byte_arrays[0]) + len(byte_arrays[1])]
				if len(byte_arrays) > 2:
					if byte_arrays[2] == addressed_fixed_data_buffer[len(byte_arrays[0]) + len(byte_arrays[1]) : len(byte_arrays[0]) + len(byte_arrays[1]) + len(byte_arrays[2])]:
						if len(byte_arrays) > 3:
							second_arg = original_data_buffer[len(byte_arrays[0]) + len(byte_arrays[1]) + len(byte_arrays[2]) : len(byte_arrays[0]) + len(byte_arrays[1]) + len(byte_arrays[2]) + len(byte_arrays[3])]
							if len(byte_arrays) > 4:
								if byte_arrays[4] == addressed_fixed_data_buffer[
									len(byte_arrays[0]) + len(byte_arrays[1]) + len(byte_arrays[2]) + len(byte_arrays[3]) :
									len(byte_arrays[0]) + len(byte_arrays[1]) + len(byte_arrays[2]) + len(byte_arrays[3]) + len(byte_arrays[4])
									]:
									possible_commands.append({"opcode":opcode, "first_arg":first_arg, "second_arg":second_arg})
							else:
								possible_commands.append({"opcode":opcode, "first_arg":first_arg, "second_arg":second_arg})
						else:
							possible_commands.append({"opcode":opcode, "first_arg":first_arg, "second_arg":second_arg})
				else:
					possible_commands.append({"opcode":opcode, "first_arg":first_arg, "second_arg":second_arg})
			else:
				possible_commands.append({"opcode":opcode, "first_arg":first_arg, "second_arg":second_arg})

	if len(possible_commands) == 0:
		print("Could not find any commands for buffer: " + get_hex_string(original_data_buffer))

	return possible_commands

def scan_for_optimal_command(f, opcode_list, command_position, is_using_remapped_memory):
	possible_commands = scan_for_possible_commands(f, opcode_list, command_position, is_using_remapped_memory)
	
	if len(possible_commands):
		final_command_list = sorted(possible_commands, key=lambda x: (-len(x['opcode']['byte_arrays']), x['opcode']['total_length']))

		final_command = final_command_list[len(final_command_list)-1]
		flipeffect_command_table_entry = create_flipeffect_table_entry_for_opcode(
			final_command["opcode"],
			final_command["first_arg"],
			final_command["second_arg"])

		was_nop = False
		if final_command['opcode']["function_name"] != "NOP":
			was_nop = False
		else:
			was_nop = True

		command_position += final_command['opcode']["total_length"]
		f.seek(command_position)

		return {"new_command":flipeffect_command_table_entry, "was_nop":was_nop}
	else:
		return {"new_command":None, "was_nop":False}


def extract_racetimer_events_from_exe(f, opcode_list, is_using_remapped_memory):
	print("Extracting racetimer events...")

	f.seek(RACETIMER_EVENT_DATA_ADDRESS)

	racetrack_events = []

	first_block = f.read(len(RACETIMER_EVENT_NOTIFY))
	if first_block == RACETIMER_EVENT_NOTIFY:
		first_block = f.read(len(RACETIMER_EVENT_START))
		if first_block == RACETIMER_EVENT_START:
			time = struct.unpack('<I', f.read(4))[0]
			f.seek(6, 1)
			
			current_command_list = []
			nop_count = 0

			while(1):
				if nop_count > MAX_NOPS:
					racetrack_events.append(current_command_list)
					break

				pos = f.tell()
				test_end = f.read(len(RACETIMER_EVENT_START))
				if test_end == RACETIMER_EVENT_START:
					racetrack_events.append(current_command_list)
					current_command_list = []
					time = struct.unpack('<I', f.read(4))[0]
					f.seek(6, 1)
					continue

				f.seek(pos)
				
				command_result = scan_for_optimal_command(f, opcode_list, pos, is_using_remapped_memory)
				if (command_result["was_nop"]):
					nop_count += 1
				else:
					if (command_result["new_command"]):
						current_command_list.append(command_result["new_command"])
					else:
						current_command_list.append({"new_command":["UNKNOWN COMMAND"], "was_nop":False})
					nop_count = 0
			print(racetrack_events)
	
	return racetrack_events


def extract_flipeffect_table_from_exe(f, opcode_list, is_using_remapped_memory):
	print("Extracting flipeffects table...")

	offset_table = []
	f.seek(FLIPEFFECT_TABLE_ADDRESS)
	
	for i in range(0, LAST_CUSTOM_FLIPEFFECT - FIRST_CUSTOM_FLIPEFFECT):
		address = struct.unpack('<I', f.read(4))[0]
		if (address == 0):
			offset_table.append(-1)
		else:
			offset_table.append(address - get_base_address(is_using_remapped_memory))
			
	# Add an extra entry for testing
	offset_table.append(-1)
	
	flipeffect_table = []

	nop_count = 0
	for i in range(0, LAST_CUSTOM_FLIPEFFECT - FIRST_CUSTOM_FLIPEFFECT):
		flipeffect_command_table = []
		nop_count = 0

		if (offset_table[i] != -1):
			flip_effect_function_address = FLIPEFFECT_DATA_ADDRESS
			flip_effect_function_offset = (offset_table[i])

			f.seek(flip_effect_function_address + flip_effect_function_offset)

			command_position = f.tell()

			while(1):
				# Indicates we've likely reached the end
				if nop_count > MAX_NOPS:
					break

				possible_commands = []
				
				command_position = f.tell()

				if(offset_table[i+1] > 0):
					if (command_position - FLIPEFFECT_DATA_ADDRESS) >= offset_table[i+1]:
						break

				command_result = scan_for_optimal_command(f, opcode_list, command_position, is_using_remapped_memory)
				if (command_result["was_nop"]):
					nop_count += 1
				else:
					nop_count = 0
					if (command_result["new_command"]):
						flipeffect_command_table.append(command_result["new_command"])

						# If the command is RETN, we can break out of the loop
						if command_result["new_command"][0] == "RETN":
							break
					else:
						flipeffect_command_table.append({"new_command":["UNKNOWN COMMAND"], "was_nop":False})
					nop_count = 0

		flipeffect_table.append(flipeffect_command_table)


	for i in range(0, len(flipeffect_table)):
		if len(flipeffect_table[i]) > 0:
			print("FlipEffect: " + str(i + FIRST_CUSTOM_FLIPEFFECT))
			for command in flipeffect_table[i]:
				print(command)
		else:
			print("Could not find any commands for flipeffect: " + str(i + FIRST_CUSTOM_FLIPEFFECT))
	
	return flipeffect_table
				
def postprocess_furr_data(furr_data):
	"""
	Update the opcode names in the furr_data according to the specified rules.
	"""
	for trigger in furr_data:
		for i, opcode in enumerate(trigger):
			if opcode[0] == "CHANGE_POSITION_X":
				trigger[i] = ["CHANGE_POSITION_Z", opcode[1], opcode[2]]
			elif opcode[0] == "CHANGE_POSITION_Z":
				trigger[i] = ["CHANGE_POSITION_X", opcode[1], opcode[2]]
			elif opcode[0] == "MOVE_ITEM_X":
				trigger[i] = ["MOVE_ITEM_Z", opcode[1], opcode[2]]
			elif opcode[0] == "MOVE_ITEM_Z":
				trigger[i] = ["MOVE_ITEM_X", opcode[1], opcode[2]]
			elif opcode[0] == "ADD_POSITION":
				trigger[i] = ["ADD_POSITION", opcode[2], opcode[1]]

	return furr_data

def read_exe_file(exe_file_path, is_using_remapped_memory):
	opcodes = load_syntax_file()
	
	opcodes.append({
		"byte_arrays":get_oneshot_opcode(is_using_remapped_memory),
		"function_name":"ONESHOT",
		"reverse_args":False,
		"address_table":[],
		"total_length":sum(len(b) for b in get_oneshot_opcode(is_using_remapped_memory)),
		"first_arg_type":"LONG",
		"second_arg_type":"UNSIGNEDINTEGER"})

	ret_val = {}

	with open(exe_file_path, 'rb') as f:
		ret_val["furr_flipeffects"] = extract_flipeffect_table_from_exe(f, opcodes, is_using_remapped_memory)
		ret_val["furr_racetimer_events"] = extract_racetimer_events_from_exe(f, opcodes, is_using_remapped_memory)

	ret_val["furr_flipeffect"] = postprocess_furr_data(ret_val["furr_flipeffects"])

	return ret_val