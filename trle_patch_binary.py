import binary_funcs
import data_tables

def check_if_using_gradiant_bar(f) -> bool:
	if binary_funcs.get_u8_at_address(f, 0x0007B0F9) != 0x74:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B101) != 0x74:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B153) != 0xB4:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B16A) != 0xBC:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B20D) != 0x74:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B211) != 0x7C:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B215) != 0xB4:
		return False
	
	if binary_funcs.get_u8_at_address(f, 0x0007B244) != 0xB4:
		return False

	return True

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

def read_objects_info(f, is_patch_binary):
	print("Scanning Objects Info...")

	objects_info = {}

	objects_info["object_customization"] = []
	for i in range(0, data_tables.T4PLUS_OBJECT_COUNT):
		objects_info["object_customization"].append({})

	if not is_patch_binary:
		for row in data_tables.enemy_health_table:
			f.seek(row["address"])
			enemy_name = row["name"]
			enemy_health = int.from_bytes(f.read(2), byteorder='little', signed=True)
			default_health = row["default"]
			if (enemy_health != default_health):
				print("Enemy {enemy_name} has modified health: {enemy_health}".format(enemy_name=enemy_name, enemy_health=enemy_health))
				objects_info["object_customization"][row["slot_number"]]["hit_points"] = enemy_health


		# Small Scorpion
		if binary_funcs.compare_data_at_address(f, 0x0005BF66, bytes([0xE9, 0x8D, 0x5A, 0x05, 0x00, 0x90, 0x90])):
			small_scorpion_health = binary_funcs.get_s16_at_address(f, 0x000B19FF)
			samll_scorpion_name = "small_scorpion"
			if small_scorpion_health != 8:
				print("Enemy {enemy_name} has modified health: {enemy_health}".format(enemy_name=samll_scorpion_name, enemy_health=small_scorpion_health))
				objects_info["object_customization"][106]["hit_points"] = enemy_health

	if not is_patch_binary:
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
							objects_info["object_customization"][slot_number]["damage_1"] = damage_value
						case 2:
							objects_info["object_customization"][slot_number]["damage_2"] = damage_value
						case 3:
							objects_info["object_customization"][slot_number]["damage_3"] = damage_value

		beetle_dispertion = binary_funcs.get_s16_at_address(f, 0x0000E3EC)
		if beetle_dispertion != 1024:
				print("Beetle Dispertion {beetle_dispertion}".format(beetle_dispertion=beetle_dispertion))

		magical_attack_divider = binary_funcs.get_s8_at_address(f, 0x0003A7AD)
		if magical_attack_divider != 2:
				print("Magical Attack Divider: {magical_attack_divider}".format(magical_attack_divider=magical_attack_divider))


		disable_mutant_locust_attack = True if binary_funcs.get_u8_at_address(f, 0x000042CC) != 0x7F else False
		if disable_mutant_locust_attack:
			print("Mutant Locust Attack disabled")

	return objects_info

def read_misc_info(f, is_patch_binary):
	print("Scanning Misc Info...")

	misc_info = {}

	if not is_patch_binary:
		# Remove Look Transparency
		look_transparency_byte = binary_funcs.get_u8_at_address(f, 0x0001d0c0)
		remove_look_transparency = True if look_transparency_byte == 0xeb else False
		print(f"Look Transparency Disabled: {str(remove_look_transparency)}.")

		# Lara impales on spikes
		if binary_funcs.is_nop_at_range(f, 0x000160ED, 0x000160EE):
			misc_info["lara_impales_on_spikes"] = True

		# Static Shatter Range
		lower_static_shatter_threshold = binary_funcs.get_u16_at_address(f, 0x0004d013)
		upper_static_shatter_threshold = binary_funcs.get_u16_at_address(f, 0x0004d019)
		print(f"Static Shatter Range: {str(lower_static_shatter_threshold)}-{str(upper_static_shatter_threshold)}.")

		# Poison Dart Bugfix
		if binary_funcs.compare_data_at_address(f, 0x00014044, bytes([0xF2])):
			misc_info["darts_poison_fix"] = True

		# Poison Dart Value
		posion_dart_posion_value = binary_funcs.get_s16_at_address(f, 0x00014048)
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

def read_stat_info(f, is_patch_binary):
	print("Scanning Stat Info Info...")

	stat_info = {}

	if not is_patch_binary:
		secret_count = int(binary_funcs.get_fixed_string_at(f, 0x000B1785, 2))
		if secret_count != 70:
			stat_info["secret_count"] = secret_count

		stat_info["equipment_modifiers"] = []
		remove_pistols = binary_funcs.is_nop_at_range(f, 0x0005B426, 0x0005B42B)
		if remove_pistols:
			stat_info["equipment_modifiers"].append({"object_id":349, "amount":0})

		has_binoculars = True if binary_funcs.get_u8_at_address(f, 0x0005B455) > 0 else False
		if not has_binoculars:
			stat_info["equipment_modifiers"].append({"object_id":371, "amount":0})

		has_crowbar = binary_funcs.is_nop_at_range(f, 0x0005B475, 0x0005B476)
		if has_crowbar:
			stat_info["equipment_modifiers"].append({"object_id":246, "amount":1})

		large_medipack_count = binary_funcs.get_s16_at_address(f, 0x0005B469)
		if large_medipack_count != 1:
			stat_info["equipment_modifiers"].append({"object_id":368, "amount":large_medipack_count})

		small_medipack_count = 3
		flare_count = 3
		if binary_funcs.get_u8_at_address(f, 0x0005B443) == 0xB4:
			small_medipack_count = binary_funcs.get_u8_at_address(f, 0x0005B446) 
			flare_count = binary_funcs.get_u8_at_address(f, 0x0005B444)
		else:
			small_medipack_count = binary_funcs.get_s32_at_address(f, 0x0005B444)
			flare_count = binary_funcs.get_s32_at_address(f, 0x0005B444)

		if small_medipack_count != 3:
			stat_info["equipment_modifiers"].append({"object_id":369, "amount":small_medipack_count})
		if flare_count != 3:
			stat_info["equipment_modifiers"].append({"object_id":373, "amount":flare_count})



	return stat_info

def read_health_bar_info(f):
	print("Scanning Health Bar Info...")
	
	health_bar_info = {}

	# Health Bar
	health_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5B0)
	if health_bar_main_color['r'] != 255 or health_bar_main_color['g'] != 0 or health_bar_main_color['b'] != 0:
		health_bar_info["main_color"] = health_bar_main_color

	health_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5BA)
	if health_bar_fade_color['r'] != 0 or health_bar_fade_color['g'] != 0 or health_bar_fade_color['b'] != 0:
		health_bar_info["fade_color"] = health_bar_fade_color

	health_bar_alternative_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5AB)
	if health_bar_alternative_color['r'] != 0 or health_bar_alternative_color['g'] != 255 or health_bar_alternative_color['b'] != 0:
		health_bar_info["alternative_color"] = {"r":0, "g":0, "b":0}

		health_bar_info["alternative_color"]['r'] = min(health_bar_info["main_color"]['r'] + health_bar_info["alternative_color"]['r'], 255)
		health_bar_info["alternative_color"]['g'] = min(health_bar_info["main_color"]['g'] + health_bar_info["alternative_color"]['g'], 255)
		health_bar_info["alternative_color"]['b'] = min(health_bar_info["main_color"]['b'] + health_bar_info["alternative_color"]['b'], 255)


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

def read_air_bar_info(f):
	print("Scanning Air Bar Info...")
	
	air_bar_info = {}

	# Air Bar
	air_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B565)
	if air_bar_main_color['r'] != 0 or air_bar_main_color['g'] != 0 or air_bar_main_color['b'] != 255:
		air_bar_info["main_color"] = air_bar_main_color

	air_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B56D)
	if air_bar_fade_color['r'] != 0 or air_bar_fade_color['g'] != 0 or air_bar_fade_color['b'] != 0:
		air_bar_info["fade_color"] = air_bar_fade_color

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

def read_sprint_bar_info(f):
	print("Scanning Sprint Bar Info...")
	
	sprint_bar_info = {}

	# Sprint Bar
	sprint_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B523)
	if sprint_bar_main_color['r'] != 0 or sprint_bar_main_color['g'] != 255 or sprint_bar_main_color['b'] != 0:
		sprint_bar_info["main_color"] = sprint_bar_main_color

	sprint_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B528)
	if sprint_bar_fade_color['r'] != 0 or sprint_bar_fade_color['g'] != 0 or sprint_bar_fade_color['b'] != 0:
		sprint_bar_info["fade_color"] = sprint_bar_fade_color

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

def read_loading_bar_info(f):
	print("Scanning Loading Bar Info...")
	
	loading_bar_info = {}

	# Loading Bar
	loading_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65A)
	if loading_bar_main_color['r'] != 159 or loading_bar_main_color['g'] != 31 or loading_bar_main_color['b'] != 128:
		loading_bar_info["main_color"] = loading_bar_main_color

	loading_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65F)
	if loading_bar_fade_color['r'] != 0 or loading_bar_fade_color['g'] != 0 or loading_bar_fade_color['b'] != 0:
		loading_bar_info["fade_color"] = loading_bar_fade_color

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

def read_bars_info(f, is_patch_binary):
	print("Scanning Bar Info...")

	bars_info = {}

	if not is_patch_binary:
		bars_info["health_bar"] = read_health_bar_info(f)
		bars_info["air_bar"] = read_air_bar_info(f)
		bars_info["sprint_bar"] = read_sprint_bar_info(f)
		bars_info["loading_bar"] = read_loading_bar_info(f)

		# Gradiant
		is_gradiant_bar = check_if_using_gradiant_bar(f)
		if is_gradiant_bar:
			bars_info["health_bar"]["is_gradiant_bar"] = is_gradiant_bar
			bars_info["air_bar"]["is_gradiant_bar"] = is_gradiant_bar
			bars_info["sprint_bar"]["is_gradiant_bar"] = is_gradiant_bar
			bars_info["loading_bar"]["is_gradiant_bar"] = is_gradiant_bar

	return bars_info

def read_gfx_blood_info(f, is_patch_binary):
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

def read_gfx_info(f, is_patch_binary):
	gfx_info = {}
	
	gfx_info["blood_info"] = read_gfx_blood_info(f, is_patch_binary)
		
	return gfx_info


def read_audio_info(f, is_using_remapped_memory, is_patch_binary):
	print("Scanning Audio Info...")

	audio_info = {}

	# Sample Rate
	#f.seek(0x000a7309)
	#sample_rate = int.from_bytes(f.read(2), byteorder='little', signed=False)
	#print(f"Sample Rate: {str(sample_rate)}.")
	
	if not is_patch_binary:
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

def read_environment_info(f, is_patch_binary):
	print("Scanning Environment Info...")

	environment_info = {}

	if not is_patch_binary:
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

def read_lara_info(f, is_patch_binary):
	print("Scanning Lara Info...")

	lara_info = {}

	return lara_info

def read_extended_info(f, is_extended_exe_size, patch_data, is_patch_binary):
	print("Scanning Extended Info...")
	
	patch_data["meta_info"]["esse_scripted_params"] = False
	patch_data["meta_info"]["esse_multiple_mirrors"] = False

	patch_data["meta_info"]["furr_support"] = False
	
	if is_extended_exe_size:
		if not is_patch_binary:
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

		# Show HP bar in Inventory.
		show_hp_bar_in_inventory = False
		if not binary_funcs.is_nop_at_range(f, 0x000EFD90, 0x000EFDCB):
			show_hp_bar_in_inventory = True
		print(f"Show HP bar in Inventory: {str(show_hp_bar_in_inventory)}")

		if is_patch_binary:
			# Enable Ricochet SFX
			has_gun_ricochet = flep_patch_check_if_has_gun_ricochet_effect(f)
			if has_gun_ricochet:
				patch_data["misc_info"]["enable_ricochet_sound_effect"] = True
		else:

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
				print(f"Enable Rollingball Smash and Kill: {str(enable_rollingball_smash_and_kill)}")

			# Enable Standing Pushables
			if not binary_funcs.is_nop_at_range(f, 0x000EE43F, 0x000EE9DE):
				patch_data["misc_info"]["enable_standing_pushables"] = True

			# Lara Crawlspace Jump
			if not binary_funcs.is_nop_at_range(f, 0x000EEA72, 0x000EEC3B):
				patch_data["lara_info"]["crawlspace_jump_animation"] = binary_funcs.get_s16_at_address(f, 0x000EEBB8)
				patch_data["lara_info"]["crawlspace_jump_pit_deepness_threshold"] = binary_funcs.get_s16_at_address(f, 0x000EEBAB)

			# Lara Ledge Climb Control
			if not binary_funcs.is_nop_at_range(f, 0x000EF1E0, 0x000EF22A):
				patch_data["lara_info"]["ledge_to_jump_state"] = binary_funcs.get_s16_at_address(f, 0x000EF1FC)
				patch_data["lara_info"]["ledge_to_down_state"] = binary_funcs.get_s16_at_address(f, 0x000EF224)


	return patch_data

    
def read_binary_file(exe_file_path, is_extended_exe_size, is_using_remapped_memory, is_patch_binary):
	patch_data = {}

	# Meta info is not serialized
	patch_data["meta_info"] = {}

	with open(exe_file_path, 'rb') as f:
		print("---")
		patch_data["audio_info"] = read_audio_info(f, is_using_remapped_memory, is_patch_binary)
		print("---")
		patch_data["bars_info"] = read_bars_info(f, is_patch_binary)
		print("---")
		patch_data["gfx_info"] = read_gfx_info(f, is_patch_binary)
		print("---")
		patch_data["objects_info"] = read_objects_info(f, is_patch_binary)
		print("---")
		patch_data["environment_info"] = read_environment_info(f, is_patch_binary)
		print("---")
		patch_data["lara_info"] = read_lara_info(f, is_patch_binary)
		print("---")
		patch_data["stat_info"] = read_stat_info(f, is_patch_binary)
		print("---")
		patch_data["misc_info"] = read_misc_info(f, is_patch_binary)
		print("---")
		patch_data = read_extended_info(f, is_extended_exe_size, patch_data, is_patch_binary)
		print("---")

	return patch_data