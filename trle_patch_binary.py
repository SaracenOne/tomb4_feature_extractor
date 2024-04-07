from enum import Enum

import binary_funcs
import data_tables

class GradientType(Enum):
    NORMAL = 0
    GRADIENT_TR5 = 1
    GRADIENT_FLAT = 2

class PatchBinaryType(Enum):
    TREP_EXE = 1
    FLEP_EXE = 2
    FLEP_EXTERNAL_BINARY = 3

def flep_patch_check_if_has_gun_ricochet_effect(f) -> bool:
	if binary_funcs.get_u8_at_address(f, 0x00033FC6) != 0xE9:
		return False
	if binary_funcs.get_u8_at_address(f, 0x00033FC7) != 0xB5:
		return False
	if binary_funcs.get_u8_at_address(f, 0x00033FC8) != 0x0F:
		return False
	if binary_funcs.get_u8_at_address(f, 0x00033FC9) != 0x3E:
		return False
	if binary_funcs.get_u8_at_address(f, 0x00033FCA) != 0x00:
		return False
	if binary_funcs.get_u8_at_address(f, 0x00033FCB) != 0x90:
		return False
	if binary_funcs.get_u8_at_address(f, 0x00033FCC) != 0x90:
		return False

	return True

def read_objects_info(f, patch_type):
	print("Scanning Objects Info...")

	objects_info = {}

	object_customization = []
	for i in range(0, data_tables.T4PLUS_OBJECT_COUNT):
		object_customization.append({})

	if patch_type == PatchBinaryType.TREP_EXE:
		for row in data_tables.enemy_health_table:
			f.seek(row["address"])
			enemy_name = row["name"]
			enemy_health = int.from_bytes(f.read(2), byteorder='little', signed=True)
			default_health = row["default"]
			if (enemy_health != default_health):
				print("Enemy {enemy_name} has modified health: {enemy_health}".format(enemy_name=enemy_name, enemy_health=enemy_health))
				object_customization[row["slot_number"]]["hit_points"] = enemy_health


		# Small Scorpion
		if binary_funcs.compare_data_at_address(f, 0x0005BF66, bytes([0xE9, 0x8D, 0x5A, 0x05, 0x00, 0x90, 0x90])):
			small_scorpion_health = binary_funcs.get_s16_at_address(f, 0x000B19FF)
			samll_scorpion_name = "small_scorpion"
			if small_scorpion_health != 8:
				print("Enemy {enemy_name} has modified health: {enemy_health}".format(enemy_name=samll_scorpion_name, enemy_health=small_scorpion_health))
				object_customization[106]["hit_points"] = enemy_health

	if patch_type == PatchBinaryType.TREP_EXE:
		for row in data_tables.enemy_damage_table:
			f.seek(row["address"])
			damage_name = row["name"]
			damage_value = 0
			if row["size"] == 1:
				damage_value = int.from_bytes(f.read(1), byteorder='little', signed=True)
			elif row["size"] == 2:
				damage_value = int.from_bytes(f.read(2), byteorder='little', signed=True)

			if row["invert_sign"]:
				damage_value = -damage_value

			default_damage = row["default"]
			if (damage_value != default_damage):
				print("Damage {damage_name} has modified value: {damage_value}".format(damage_name=damage_name, damage_value=damage_value))
				for slot_number in row["slot_numbers"]:
					match row["damage_id"]:
						case 1:
							object_customization[slot_number]["damage_1"] = damage_value
						case 2:
							object_customization[slot_number]["damage_2"] = damage_value
						case 3:
							object_customization[slot_number]["damage_3"] = damage_value

		beetle_dispertion = binary_funcs.get_s16_at_address(f, 0x0000E3EC)
		if beetle_dispertion != 1024:
				print("Beetle Dispertion {beetle_dispertion}".format(beetle_dispertion=beetle_dispertion))

		magical_attack_divider = binary_funcs.get_s8_at_address(f, 0x0003A7AD)
		if magical_attack_divider != 2:
				print("Magical Attack Divider: {magical_attack_divider}".format(magical_attack_divider=magical_attack_divider))


		disable_mutant_locust_attack = True if binary_funcs.get_u8_at_address(f, 0x000042CC) != 0x7F else False
		if disable_mutant_locust_attack:
			print("Mutant Locust Attack disabled")

	# Check if any objects were customized before including the array in the objects_info dict.
	for object in object_customization:
		if bool(object):
			objects_info["object_customization"] = object_customization
			break

	return objects_info

def read_font_info(f, patch_type):
	font_info = {}
    
	# Font Customizer
	text_or_critical_bar_blink_interval = binary_funcs.get_u8_at_address(f, 0x000521B0)
	if text_or_critical_bar_blink_interval != 5:
		font_info["text_or_critical_bar_blink_interval"] = text_or_critical_bar_blink_interval

	main_font_main_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADEF8)
	if main_font_main_color['r'] != 128 or main_font_main_color['g'] != 128 or main_font_main_color['b'] != 128:
		font_info["main_font_color"] = main_font_main_color
        
	main_font_fade_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADEFC)
	if main_font_fade_color['r'] != 128 or main_font_fade_color['g'] != 128 or main_font_fade_color['b'] != 128:
		font_info["main_font_fade_color"] = main_font_fade_color
        
	options_title_font_main_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADF18)
	if options_title_font_main_color['r'] != 192 or options_title_font_main_color['g'] != 128 or options_title_font_main_color['b'] != 64:
		font_info["options_title_font_main_color"] = options_title_font_main_color

	options_title_font_fade_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADF1C)
	if options_title_font_fade_color['r'] != 64 or options_title_font_fade_color['g'] != 16 or options_title_font_fade_color['b'] != 0:
		font_info["options_title_font_fade_color"] = options_title_font_fade_color
        
	inventory_title_font_main_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADF28)
	if inventory_title_font_main_color['r'] != 224 or inventory_title_font_main_color['g'] != 192 or inventory_title_font_main_color['b'] != 0:
		font_info["inventory_title_font_main_color"] = inventory_title_font_main_color

	inventory_title_font_fade_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADF2C)
	if inventory_title_font_fade_color['r'] != 64 or inventory_title_font_fade_color['g'] != 32 or inventory_title_font_fade_color['b'] != 0:
		font_info["inventory_title_font_fade_color"] = inventory_title_font_fade_color

	inventory_title_item_main_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADF10)
	if inventory_title_item_main_color['r'] != 128 or inventory_title_item_main_color['g'] != 128 or inventory_title_item_main_color['b'] != 128:
		font_info["inventory_title_item_main_color"] = inventory_title_item_main_color

	inventory_title_item_fade_color = binary_funcs.get_rgb_color_at_address(f, 0x000ADF14)
	if inventory_title_item_fade_color['r'] != 16 or inventory_title_item_fade_color['g'] != 16 or inventory_title_item_fade_color['b'] != 16:
		font_info["inventory_title_item_fade_color"] = inventory_title_item_fade_color

	return font_info

def read_misc_info(f, patch_type):
	print("Scanning Misc Info...")

	misc_info = {}

	# Font Customizer
	text_or_critical_bar_blink_interval = binary_funcs.get_u8_at_address(f, 0x000521B0)
	if text_or_critical_bar_blink_interval != 5:
		misc_info["text_or_critical_bar_blink_interval"] = text_or_critical_bar_blink_interval

	legend_timer = binary_funcs.get_u8_at_address(f, 0x00050F59)
	if legend_timer != 150:
		misc_info["legend_timer"] = legend_timer

	if patch_type == PatchBinaryType.TREP_EXE:
		# Remove Look Transparency
		look_transparency_byte = binary_funcs.get_u8_at_address(f, 0x0001d0c0)
		remove_look_transparency = True if look_transparency_byte == 0xeb else False
		if remove_look_transparency:
			print(f"Look Transparency Disabled: {str(remove_look_transparency)}.")

		# Lara impales on spikes
		if binary_funcs.is_nop_at_range(f, 0x000160ED, 0x000160EE):
			misc_info["lara_impales_on_spikes"] = True

		# Static Shatter Range
		lower_static_shatter_threshold = binary_funcs.get_u16_at_address(f, 0x0004d013)
		upper_static_shatter_threshold = binary_funcs.get_u16_at_address(f, 0x0004d019)
		if lower_static_shatter_threshold != 50 or upper_static_shatter_threshold != 58:
			print(f"Static Shatter Range: {str(lower_static_shatter_threshold)}-{str(upper_static_shatter_threshold)}.")

		# Poison Dart Bugfix
		if binary_funcs.compare_data_at_address(f, 0x00014044, bytes([0xF2])):
			misc_info["darts_poison_fix"] = True

		# Poison Dart Value
		posion_dart_posion_value = binary_funcs.get_s16_at_address(f, 0x00014048)
		if posion_dart_posion_value != 160:
			print(f"Poison Dart Poison Value: {posion_dart_posion_value}.")

		# Fix Holsters
		fix_holsters = False
		if not binary_funcs.is_nop_at_range(f, 0x0002B7C1, 0x0002B7CB) and not binary_funcs.is_nop_at_range(f, 0x0002B845, 0x0002B84F):
			fix_holsters = True
			print(f"Fix Holsters: {str(fix_holsters)}.")

		# Always Exit From Statistics Screen
		always_exit_from_statistics_screen = True if binary_funcs.get_u8_at_address(f, 0x0007AD9B) == 0xC6 and \
		binary_funcs.compare_data_at_address(f, 0x0007ADA2, bytes([0xE8, 0x99, 0x36, 0xFE, 0xFF, 0x83, 0xC4, 0x0C, 0xB0, 0x01, 0xC3])) else False
		if always_exit_from_statistics_screen:
			misc_info["always_exit_from_statistics_screen"] = True
		
	# Disable Motorbike headlights
	disable_motorbike_headlights = True if binary_funcs.get_u8_at_address(f, 0x000639F0) == 0xC3 else False
	if disable_motorbike_headlights:
		misc_info["disable_motorbike_headlights"] = disable_motorbike_headlights

	return misc_info

def read_stat_info(f, patch_type):
	print("Scanning Stat Info Info...")

	stat_info = {}

	if patch_type == PatchBinaryType.TREP_EXE:
		secret_count = int(binary_funcs.get_fixed_string_at(f, 0x000B1785, 2))
		if secret_count != 70:
			stat_info["secret_count"] = secret_count

		equipment_modifiers = []
		remove_pistols = binary_funcs.is_nop_at_range(f, 0x0005B426, 0x0005B42B)
		if remove_pistols:
			equipment_modifiers.append({"object_id":349, "amount":0})

		has_binoculars = True if binary_funcs.get_u8_at_address(f, 0x0005B455) > 0 else False
		if not has_binoculars:
			equipment_modifiers.append({"object_id":371, "amount":0})

		has_crowbar = binary_funcs.is_nop_at_range(f, 0x0005B475, 0x0005B476)
		if has_crowbar:
			equipment_modifiers.append({"object_id":246, "amount":1})

		large_medipack_count = binary_funcs.get_s16_at_address(f, 0x0005B469)
		if large_medipack_count != 1:
			equipment_modifiers.append({"object_id":368, "amount":large_medipack_count})

		small_medipack_count = 3
		flare_count = 3
		if binary_funcs.get_u8_at_address(f, 0x0005B443) == 0xB4:
			small_medipack_count = binary_funcs.get_u8_at_address(f, 0x0005B446) 
			flare_count = binary_funcs.get_u8_at_address(f, 0x0005B444)
		else:
			small_medipack_count = binary_funcs.get_s32_at_address(f, 0x0005B444)
			flare_count = binary_funcs.get_s32_at_address(f, 0x0005B444)

		if small_medipack_count != 3:
			equipment_modifiers.append({"object_id":369, "amount":small_medipack_count})
		if flare_count != 3:
			equipment_modifiers.append({"object_id":373, "amount":flare_count})
			
		# Check if any equipment objects were customized before including the array in the stat_info dict.
		if bool(equipment_modifiers):
			stat_info["equipment_modifiers"] = equipment_modifiers

	return stat_info

def update_bar_background_colors(f, bar):
	address_1 = binary_funcs.get_u8_at_address(f, 0x00079083)
	address_2 = binary_funcs.get_u8_at_address(f, 0x0007B316)
	border_1_color = 0xffffffff
	border_2_color = 0xffffffff
	if address_1 != 0x83:
		border_1_color = binary_funcs.get_bgr_color_at_address(f, 0x00079084)

	if address_2 != 0x83:
		border_2_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B317)

	if border_1_color != border_2_color:
		print(f"Border color: MISMATCH.")
		return bar
	
	if border_1_color != 0xffffffff:
		bar["border_rect"] = {}
		bar["border_rect"]["upper_left_color"] = border_1_color
		bar["border_rect"]["upper_right_color"] = border_1_color
		bar["border_rect"]["lower_right_color"] = border_1_color
		bar["border_rect"]["lower_left_color"] = border_1_color

	return bar

def construct_bar(f, bar, main_color, fade_color, type):
	bar["upper_rect"] = {}
	bar["lower_rect"] = {}

	if type == GradientType.NORMAL:
		bar["upper_rect"]["upper_left_color"] = fade_color
		bar["upper_rect"]["upper_right_color"] = fade_color
		bar["upper_rect"]["lower_right_color"] = main_color
		bar["upper_rect"]["lower_left_color"] = main_color

		bar["lower_rect"]["upper_left_color"] = main_color
		bar["lower_rect"]["upper_right_color"] = main_color
		bar["lower_rect"]["lower_right_color"] = fade_color
		bar["lower_rect"]["lower_left_color"] = fade_color
	elif type == GradientType.GRADIENT_TR5:
		black_color = {"r":0, "g":0, "b":0}

		bar["upper_rect"]["upper_left_color"] = black_color
		bar["upper_rect"]["upper_right_color"] = black_color
		bar["upper_rect"]["lower_right_color"] = fade_color
		bar["upper_rect"]["lower_left_color"] = main_color

		bar["lower_rect"]["upper_left_color"] = main_color
		bar["lower_rect"]["upper_right_color"] = fade_color
		bar["lower_rect"]["lower_right_color"] = black_color
		bar["lower_rect"]["lower_left_color"] = black_color
	elif type == GradientType.GRADIENT_FLAT:
		bar["upper_rect"]["upper_left_color"] = main_color
		bar["upper_rect"]["upper_right_color"] = fade_color
		bar["upper_rect"]["lower_right_color"] = fade_color
		bar["upper_rect"]["lower_left_color"] = main_color

		bar["lower_rect"]["upper_left_color"] = main_color
		bar["lower_rect"]["upper_right_color"] = fade_color
		bar["lower_rect"]["lower_right_color"] = fade_color
		bar["lower_rect"]["lower_left_color"] = main_color

	return bar

def read_health_bar_info(f, type):
	print("Scanning Health Bar Info...")
	
	health_bar_info = {}

	# Health Bar
	health_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5B0)
	health_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5BA)
	health_bar_alternative_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5AB)

	if health_bar_main_color['r'] != 255 or health_bar_main_color['g'] != 0 or health_bar_main_color['b'] != 0 or \
	health_bar_fade_color['r'] != 0 or health_bar_fade_color['g'] != 0 or health_bar_fade_color['b'] != 0 or \
	health_bar_alternative_color['r'] != 0 or health_bar_alternative_color['g'] != 255 or health_bar_alternative_color['b'] != 0 or \
	type != GradientType.NORMAL:
		health_bar_info = construct_bar(f, health_bar_info, health_bar_main_color, health_bar_fade_color, type)

	health_bar_info = update_bar_background_colors(f, health_bar_info)

	health_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B5C5)
	if health_bar_width != 150:
		health_bar_info["width"] = health_bar_width

	health_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B5C3)
	if health_bar_height != 12:
		health_bar_info["height"] = health_bar_height

	health_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B5CC, bytes([0x50, 0xD7]))
	if health_bar_is_animated:
		health_bar_info["is_animated"] = health_bar_is_animated

	return health_bar_info

def read_poison_bar_info(f, type):
	print("Scanning Poison Bar Info...")
	
	poison_bar_info = {}

	# Poison Bar
	poison_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5B0)
	poison_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5BA)
	poison_bar_alternative_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5AB)

	if poison_bar_main_color['r'] != 255 or poison_bar_main_color['g'] != 0 or poison_bar_main_color['b'] != 0 or \
	poison_bar_fade_color['r'] != 0 or poison_bar_fade_color['g'] != 0 or poison_bar_fade_color['b'] != 0 or \
	poison_bar_alternative_color['r'] != 0 or poison_bar_alternative_color['g'] != 255 or poison_bar_alternative_color['b'] != 0 or \
	type != GradientType.NORMAL:
		poison_bar_main_color = {"r":0, "g":0, "b":0}

		poison_bar_main_color['r'] = min(poison_bar_main_color['r'] + poison_bar_alternative_color['r'], 255)
		poison_bar_main_color['g'] = min(poison_bar_main_color['g'] + poison_bar_alternative_color['g'], 255)
		poison_bar_main_color['b'] = min(poison_bar_main_color['b'] + poison_bar_alternative_color['b'], 255)

		poison_bar_info = construct_bar(f, poison_bar_info, poison_bar_main_color, poison_bar_fade_color, type)

	poison_bar_info = update_bar_background_colors(f, poison_bar_info)

	poison_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B5C5)
	if poison_bar_width != 150:
		poison_bar_info["width"] = poison_bar_width

	poison_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B5C3)
	if poison_bar_height != 12:
		poison_bar_info["height"] = poison_bar_height

	poison_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B5CC, bytes([0x50, 0xD7]))
	if poison_bar_is_animated:
		poison_bar_info["is_animated"] = poison_bar_is_animated

	return poison_bar_info

def read_air_bar_info(f, type):
	print("Scanning Air Bar Info...")
	
	air_bar_info = {}

	# Air Bar
	air_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B565)
	air_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B56D)

	if air_bar_main_color['r'] != 0 or air_bar_main_color['g'] != 0 or air_bar_main_color['b'] != 255 or \
	air_bar_fade_color['r'] != 0 or air_bar_fade_color['g'] != 0 or air_bar_fade_color['b'] != 0 or \
	type != GradientType.NORMAL:
		air_bar_info = construct_bar(f, air_bar_info, air_bar_main_color, air_bar_fade_color, type)

	air_bar_info = update_bar_background_colors(f, air_bar_info)

	air_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B579)
	if air_bar_width != 150:
		air_bar_info["width"] = air_bar_width

	air_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B575)
	if air_bar_height != 12:
		air_bar_info["height"] = air_bar_height
		
	air_bar_x_offset = binary_funcs.get_s16_at_address(f, 0x0007B57F)
	if air_bar_x_offset != 490:
		air_bar_info["x_offset"] = air_bar_x_offset
		
	air_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B587, bytes([0x95, 0xD7]))
	if air_bar_is_animated:
		air_bar_info["is_animated"] = air_bar_is_animated

	return air_bar_info

def read_sprint_bar_info(f, type):
	print("Scanning Sprint Bar Info...")
	
	sprint_bar_info = {}

	# Sprint Bar
	sprint_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B523)
	sprint_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B528)

	if sprint_bar_main_color['r'] != 0 or sprint_bar_main_color['g'] != 255 or sprint_bar_main_color['b'] != 0 or \
	sprint_bar_fade_color['r'] != 0 or sprint_bar_fade_color['g'] != 0 or sprint_bar_fade_color['b'] != 0 or \
	type != GradientType.NORMAL:
		sprint_bar_info = construct_bar(f, sprint_bar_info, sprint_bar_main_color, sprint_bar_fade_color, type)

	sprint_bar_info = update_bar_background_colors(f, sprint_bar_info)

	sprint_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B538)
	if sprint_bar_width != 150:
		sprint_bar_info["width"] = sprint_bar_width
		
	sprint_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B536)
	if sprint_bar_height != 12:
		sprint_bar_info["height"] = sprint_bar_height

	sprint_bar_x_offset = binary_funcs.get_s16_at_address(f, 0x0007B531)
	if sprint_bar_x_offset != 490:
		sprint_bar_info["x_offset"] = sprint_bar_x_offset

	sprint_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B541, bytes([0xDB, 0xD7]))
	if sprint_bar_is_animated:
		sprint_bar_info["is_animated"] = sprint_bar_is_animated

	return sprint_bar_info

def read_loading_bar_info(f, type):
	print("Scanning Loading Bar Info...")
	
	loading_bar_info = {}

	# Loading Bar
	loading_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65A)
	loading_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65F)
	
	if loading_bar_main_color['r'] != 159 or loading_bar_main_color['g'] != 31 or loading_bar_main_color['b'] != 128 or \
	loading_bar_fade_color['r'] != 0 or loading_bar_fade_color['g'] != 0 or loading_bar_fade_color['b'] != 0 or \
	type != GradientType.NORMAL:
		loading_bar_info = construct_bar(f, loading_bar_info, loading_bar_main_color, loading_bar_fade_color, type)

	loading_bar_info = update_bar_background_colors(f, loading_bar_info)

	loading_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B693)
	if loading_bar_width != 600:
		loading_bar_info["width"] = loading_bar_width
		
	loading_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B68F)
	if loading_bar_height != 15:
		loading_bar_info["height"] = loading_bar_height

	loading_bar_hidden = binary_funcs.is_nop_at_range(f, 0x0007B601, 0x0007B604)
	if loading_bar_hidden:
		loading_bar_info["hidden"] = loading_bar_hidden

	return loading_bar_info

def read_bars_info(f, patch_type):
	print("Scanning Bar Info...")

	bars_info = {}

	if patch_type == PatchBinaryType.TREP_EXE:
		bar_type_byte = binary_funcs.get_u8_at_address(f, 0x0007b0f9)
		
		gradient_type = GradientType.NORMAL
		if bar_type_byte == 0x74:
			gradient_type = GradientType.GRADIENT_TR5
		elif bar_type_byte == 0x6c:
			gradient_type = GradientType.GRADIENT_FLAT

		health_bar = read_health_bar_info(f, gradient_type)
		if bool(health_bar):
			bars_info["health_bar"] = health_bar
		poison_bar = read_poison_bar_info(f, gradient_type)
		if bool(poison_bar):
			bars_info["poison_bar"] = poison_bar
		air_bar = read_air_bar_info(f, gradient_type)
		if bool(air_bar):
			bars_info["air_bar"] = air_bar
		sprint_bar = read_sprint_bar_info(f, gradient_type)
		if bool(sprint_bar):
			bars_info["sprint_bar"] = sprint_bar
		loading_bar = read_loading_bar_info(f, gradient_type)
		if bool(loading_bar):
			bars_info["loading_bar"] = loading_bar

	return bars_info

def read_gfx_blood_info(f, patch_type):
	blood_info = {}

	blood_size = binary_funcs.get_u8_at_address(f, 0x00038A18)
	if blood_size != 0x08:
		blood_info["blood_size"] = blood_size
		
	blood_intensity = binary_funcs.get_u8_at_address(f, 0x0003891C)
	if blood_intensity != 0x30:
		blood_info["blood_intensity"] = blood_intensity

	blood_speed = binary_funcs.get_u8_at_address(f, 0x00038894)
	if blood_speed != 0x05:
		blood_info["blood_speed"] = blood_speed
		
	blood_intensity = binary_funcs.get_u8_at_address(f, 0x0003892C)
	if blood_intensity != 0x18:
		blood_info["blood_intensity"] = blood_intensity
		
	blood_spread_factor_x = binary_funcs.get_u8_at_address(f, 0x000389A8)
	if blood_spread_factor_x != 0x07:
		blood_info["blood_spread_factor_x"] = blood_spread_factor_x
		
	blood_spread_factor_y = binary_funcs.get_u8_at_address(f, 0x000389AB)
	if blood_spread_factor_y != 0x07:
		blood_info["blood_spread_factor_y"] = blood_spread_factor_y

	return blood_info

def read_vapor_customization(f, jump_address, index) -> dict:
	vapor_info = {}
	vapor_info["start_color"] = binary_funcs.read_rgb(f)
	vapor_info["start_time"] = binary_funcs.read_s8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["end_color"] = binary_funcs.read_rgb(f)
	vapor_info["end_time"] = binary_funcs.read_s8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["blending_mode"] = binary_funcs.read_s8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["lifetime"] = binary_funcs.read_s8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["size_variation_lower_byte"] = binary_funcs.read_u8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["size_variation_higher_byte"] = binary_funcs.read_u8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["size_multiplier"] = binary_funcs.read_u8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["rotation"] = binary_funcs.read_u8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["flags"] = binary_funcs.read_u16(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["sprite_id"] = binary_funcs.read_u8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["horizontal_speed"] = binary_funcs.read_s8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["horizontal_curve"] = binary_funcs.read_s8(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["vertical_speed_1"] = binary_funcs.read_s32(f)
	binary_funcs.skip_bytes(f, 1)
	vapor_info["vertical_speed_2"] = binary_funcs.read_s8(f)

	last_position = f.tell()

	f.seek(jump_address + (index * 4))
	vapor_info["spawn_interval"] = binary_funcs.read_s8(f)
	f.seek(last_position + 10)

	return vapor_info

def read_gfx_vapor_info(f, patch_type):
	vapor_info = {}

	if patch_type == PatchBinaryType.FLEP_EXE or patch_type == PatchBinaryType.FLEP_EXTERNAL_BINARY:
		extended_vapor_emitter = not binary_funcs.is_nop_at_range(f, 0x000C53E0, 0x000C5C83)
		if extended_vapor_emitter:
			f.seek(0x000C5B21)
			steam_emitter = read_vapor_customization(f, 0x000C5498, 0)
			steam_emitters_for_ocb = []
			for i in range(0, 15):
				steam_emitters_for_ocb.append(steam_emitter)
			vapor_info["steam_emitters_for_ocb"] = steam_emitters_for_ocb

			f.seek(0x000C54E0)
			white_smoke_emitters_for_ocb = []
			for i in range(0, 15):
				white_smoke_emitters_for_ocb.append(read_vapor_customization(f, 0x000C5408, i))
			vapor_info["white_smoke_emitters_for_ocb"] = white_smoke_emitters_for_ocb

			f.seek(0x000C5805)
			black_smoke_emitters_for_ocb = []
			for i in range(0, 15):
				black_smoke_emitters_for_ocb.append(read_vapor_customization(f, 0x000C545C, i))
			vapor_info["black_smoke_emitters_for_ocb"] = black_smoke_emitters_for_ocb

	return vapor_info

def read_fog_color_table(f, patch_type) -> dict:
	fog_color_table = []

	f.seek(0xabe10)
	for i in range(0, 28):
		fog_color = binary_funcs.read_rgb(f)
		fog_color_table.append(fog_color)

	return fog_color_table

def read_gfx_info(f, patch_type):
	gfx_info = {}
	
	blood_info = read_gfx_blood_info(f, patch_type)
	if bool(blood_info):
		gfx_info["blood_info"] = blood_info

	vapor_info = read_gfx_vapor_info(f, patch_type)
	if bool(vapor_info):
		gfx_info["vapor_info"] = vapor_info

	#fog_color_table = read_fog_color_table(f, patch_type)
	#if bool(fog_color_table):
	#	gfx_info["fog_color_table"] = fog_color_table
		
	return gfx_info


def read_audio_info(f, is_using_remapped_memory, patch_type):
	print("Scanning Audio Info...")

	audio_info = {}

	# Sample Rate
	#f.seek(0x000a7309)
	#sample_rate = int.from_bytes(f.read(2), byteorder='little', signed=False)
	#print(f"Sample Rate: {str(sample_rate)}.")
	
	if patch_type == PatchBinaryType.TREP_EXE:
		if is_using_remapped_memory:
			using_bass = not binary_funcs.is_nop_at_range(f, 0x000F66C0, 0x000F6E7E)
			if using_bass:
				audio_info["new_audio_system"] = True
				audio_info["old_cd_trigger_system"] = False

		disable_lara_hit_sfx = binary_funcs.compare_data_at_address(f, 0x0000B02A, bytes([0x90, 0x90, 0x90, 0x90, 0x90]))
		if disable_lara_hit_sfx:
			audio_info["disable_lara_hit_sfx"] = disable_lara_hit_sfx

		lara_hit_sfx = binary_funcs.get_s8_at_address(f, 0x0000B029)
		if lara_hit_sfx != 50:
			audio_info["lara_hit_sfx"] = lara_hit_sfx

		disable_no_ammo_sfx = binary_funcs.compare_data_at_address(f, 0x0002D814, bytes([0x90, 0x90, 0x90, 0x90, 0x90]))
		if disable_no_ammo_sfx:
			audio_info["disable_no_ammo_sfx"] = disable_no_ammo_sfx
		
		no_ammo_sfx = binary_funcs.get_s8_at_address(f, 0x0002D813)
		if no_ammo_sfx != 48:
			audio_info["no_ammo_sfx"] = no_ammo_sfx

		inside_jeep_track = binary_funcs.get_u8_at_address(f, 0x000663FE)
		if inside_jeep_track != 98:
			audio_info["inside_jeep_track"] = inside_jeep_track

		outside_jeep_track = binary_funcs.get_u8_at_address(f, 0x00066EAD)
		if outside_jeep_track != 110:
			audio_info["outside_jeep_track"] = outside_jeep_track

		secret_track = binary_funcs.get_u8_at_address(f, 0x0004AACC)
		if secret_track != 5:
			audio_info["secret_track"] = secret_track

		change_looped_audio_track_range = binary_funcs.is_nop_at_range(f, 0x0004BE2C, 0x0004BE3C)
		if change_looped_audio_track_range:
			first_looped_audio_track = binary_funcs.get_u8_at_address(f, 0x0004BE28)
			if first_looped_audio_track != 105:
				audio_info["first_looped_audio_track"] = first_looped_audio_track
			
	return audio_info

def read_environment_info(f, patch_type):
	print("Scanning Environment Info...")

	environment_info = {}

	if patch_type == PatchBinaryType.TREP_EXE:
		if binary_funcs.get_u8_at_address(f, 0x000702A6) == 0xEB and binary_funcs.get_u8_at_address(f, 0x00070492) == 0xEB and binary_funcs.get_u8_at_address(f, 0x000706A8):
			environment_info["disable_distance_limit"] = True

		# Drawing Distance Range
		fog_end_range = int(binary_funcs.get_float_at_address(f, 0x000B249C))
		if fog_end_range != 20480:
			environment_info["far_view"] = fog_end_range
			environment_info["fog_end_range"] = fog_end_range

		# Hard Clipping Range
		hard_clipping_range_first_value = binary_funcs.get_u32_at_address(f, 0x00075107)
		hard_clipping_range_second_value = binary_funcs.get_u32_at_address(f, 0x0008CE33)

		if (hard_clipping_range_first_value == hard_clipping_range_second_value):
			if hard_clipping_range_first_value != 20480:
				print(f"Hard Clipping Range: " + str(hard_clipping_range_first_value))
		else:
			print(f"Hard Clipping Range: MISMATCH.")

		# Distant Fog Range
		fog_start_range = int(binary_funcs.get_float_at_address(f, 0x000B2498))
		if fog_start_range != 12288:
			environment_info["fog_start_range"] = fog_start_range

	return environment_info

def read_lara_info(f, patch_type):
	print("Scanning Lara Info...")

	lara_info = {}

	return lara_info

def read_extended_info(f, is_extended_exe_size, patch_data, patch_type):
	print("Scanning Extended Info...")
	
	patch_data["meta_info"]["esse_scripted_params"] = False
	patch_data["meta_info"]["esse_multiple_mirrors"] = False

	patch_data["meta_info"]["furr_support"] = False
	
	if is_extended_exe_size:
		if patch_type == PatchBinaryType.TREP_EXE:
			# FURR support
			if not binary_funcs.is_nop_at_range(f, 0x000C1000, 0x000C2FFF):
				print(f"FURR support enabled!")
				patch_data["meta_info"]["furr_support"] = True
				
			# eSSe file loading enable
			if not binary_funcs.is_nop_at_range(f, 0x000EFBA0, 0x000EFBC8) or \
			not binary_funcs.is_nop_at_range(f, 0x000EFFE0, 0x000F0002):
				print(f"eSSe file loading enabled!")
				if not binary_funcs.is_nop_at_range(f, 0x000F0010, 0x000F0A3D):
					patch_data["meta_info"]["esse_scripted_params"] = True
				if not binary_funcs.is_nop_at_range(f, 0x000F5E10, 0x000F6113):
					patch_data["meta_info"]["esse_multiple_mirrors"] = True

		# Draw Legend on Flybys
		if not binary_funcs.is_nop_at_range(f, 0x000EF7C0, 0x000EF7F3):
			patch_data["misc_info"]["draw_legend_on_flyby"] = True

		# Show HP bar in Inventory.
		show_hp_bar_in_inventory = False
		if not binary_funcs.is_nop_at_range(f, 0x000EFD90, 0x000EFDCB):
			show_hp_bar_in_inventory = True
			print(f"Show HP bar in Inventory: {str(show_hp_bar_in_inventory)}")

		if patch_type == PatchBinaryType.TREP_EXE:
			# Enable Ricochet SFX
			if not binary_funcs.is_nop_at_range(f, 0x000EE422, 0x000EE43E):
				patch_data["misc_info"]["enable_ricochet_sound_effect"] = True

			# Enable Revolver Shell Casings
			enable_revolver_shell_casings = False
			if not binary_funcs.is_nop_at_range(f, 0x000EFEC0, 0x000EFEDC):
				enable_revolver_shell_casings = True
				print(f"Enable Revolver Shell Casings: {str(enable_revolver_shell_casings)}")

			# Enable Crossbow Shell Casings
			enable_crossbow_shell_casings = False
			if not binary_funcs.is_nop_at_range(f, 0x000EFFC0, 0x000EFFDA):
				enable_crossbow_shell_casings = True
				print(f"Enable Crossbow Shell Casings: {str(enable_crossbow_shell_casings)}")

			# Enable Custom Switch Animation OCB
			enable_custom_switch_animation_ocb = False
			if not binary_funcs.is_nop_at_range(f, 0x000EFBD0, 0x000EFD2D):
				patch_data["misc_info"]["trep_switch_maker"] = True
				print(f"Enable Custom Switch Animation OCB: {str(enable_custom_switch_animation_ocb)}")

				patch_data["misc_info"]["trep_switch_on_ocb_1_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFC6E) # 1
				patch_data["misc_info"]["trep_switch_off_ocb_1_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFD00) # 2

				patch_data["misc_info"]["trep_switch_on_ocb_2_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFC00) # 3
				patch_data["misc_info"]["trep_switch_off_ocb_2_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFC96) # 4

				patch_data["misc_info"]["trep_switch_on_ocb_5_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFC42) # 5
				patch_data["misc_info"]["trep_switch_off_ocb_5_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFCD8) # 6

				patch_data["misc_info"]["trep_switch_on_ocb_6_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFC56) # 7
				patch_data["misc_info"]["trep_switch_off_ocb_6_anim"] = binary_funcs.get_s16_at_address(f, 0x000EFCEC) # 8

			# Enable Rollingball Smash and Kill
			enable_rollingball_smash_and_kill = False
			if not binary_funcs.is_nop_at_range(f, 0x000EEDE0, 0x000EEE17):
				enable_rollingball_smash_and_kill = True
				patch_data["misc_info"]["enable_smashing_and_killing_rolling_balls"] = enable_rollingball_smash_and_kill
			print(f"Enable Rollingball Smash and Kill: {str(enable_rollingball_smash_and_kill)}")

			# Enable Standing Pushables
			enable_standing_pushables = False
			if not binary_funcs.is_nop_at_range(f, 0x000EE43F, 0x000EE9DE):
				enable_standing_pushables = True
				patch_data["misc_info"]["enable_standing_pushables"] = enable_standing_pushables
			print(f"Enable Standing Pushables: {str(enable_standing_pushables)}")


			# Lara Crawlspace Jump
			if not binary_funcs.is_nop_at_range(f, 0x000EEA72, 0x000EEC3B):
				patch_data["lara_info"]["crawlspace_jump_animation"] = binary_funcs.get_s16_at_address(f, 0x000EEBB8)
				patch_data["lara_info"]["crawlspace_jump_pit_deepness_threshold"] = binary_funcs.get_s16_at_address(f, 0x000EEBAB)

			# Lara Ledge Climb Control
			if not binary_funcs.is_nop_at_range(f, 0x000EF1E0, 0x000EF22A):
				patch_data["lara_info"]["ledge_to_jump_state"] = binary_funcs.get_s16_at_address(f, 0x000EF1FC)
				patch_data["lara_info"]["ledge_to_down_state"] = binary_funcs.get_s16_at_address(f, 0x000EF224)
		else:
			# Enable Ricochet SFX
			has_gun_ricochet = flep_patch_check_if_has_gun_ricochet_effect(f)
			if has_gun_ricochet:
				patch_data["misc_info"]["enable_ricochet_sound_effect"] = True

	return patch_data

    
def read_binary_file(exe_file_path, is_extended_exe_size, is_using_remapped_memory, patch_type):
	patch_data = {}

	# Meta info is not serialized
	patch_data["meta_info"] = {}

	with open(exe_file_path, 'rb') as f:
		print("---")
		patch_data["audio_info"] = read_audio_info(f, is_using_remapped_memory, patch_type)
		print("---")
		patch_data["bars_info"] = read_bars_info(f, patch_type)
		print("---")
		patch_data["font_info"] = read_font_info(f, patch_type)
		print("---")
		patch_data["gfx_info"] = read_gfx_info(f, patch_type)
		print("---")
		patch_data["objects_info"] = read_objects_info(f, patch_type)
		print("---")
		patch_data["environment_info"] = read_environment_info(f, patch_type)
		print("---")
		patch_data["lara_info"] = read_lara_info(f, patch_type)
		print("---")
		patch_data["stat_info"] = read_stat_info(f, patch_type)
		print("---")
		patch_data["misc_info"] = read_misc_info(f, patch_type)
		print("---")
		patch_data = read_extended_info(f, is_extended_exe_size, patch_data, patch_type)
		print("---")

	return patch_data