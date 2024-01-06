import struct
import binary_funcs

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

def read_enemy_info(f, is_patch_binary):
	print("Scanning Enemy Info...")

	enemy_health_dictionary = {}

	if not is_patch_binary:

		# Enemy Health Table
		enemy_health_table = [
			{"address": 0x0005B770, "name": "skeleton", "default": 0x0f00},
			{"address": 0x0005BB30, "name": "baddy_1", "default": 0x1900},
			{"address": 0x0005BD1D, "name": "baddy_2", "default": 0x2300},
			{"address": 0x0005BEFF, "name": "big_scorpion", "default": 0x5000},
			{"address": 0x0005BFE9, "name": "mummy", "default": 0x0f00},
			{"address": 0x0005C087, "name": "knights_templer", "default": 0x0f00},
			{"address": 0x0005C105, "name": "sphinx", "default": 0xe803},
			{"address": 0x0005C167, "name": "set", "default": 0xf401},
			{"address": 0x0005C21C, "name": "horseman", "default": 0x1900},
			{"address": 0x0005C28D, "name": "hammerhead", "default": 0x2d00},
			{"address": 0x0005C33D, "name": "crocodile", "default": 0x2400},
			{"address": 0x0005C5FE, "name": "mutant", "default": 0x0f00},
			{"address": 0x0005B99A, "name": "guide", "default": 0x00c0},
			{"address": 0x0005C3F7, "name": "demigod_1", "default": 0xc800},
			{"address": 0x0005C4A3, "name": "demigod_2", "default": 0xc800},
			{"address": 0x0005C54F, "name": "demigod_3", "default": 0xc800},
			{"address": 0x0005C69E, "name": "troops", "default": 0x2800},
			{"address": 0x0005C74E, "name": "sas", "default": 0x2800},
			{"address": 0x0005C7E9, "name": "harpy", "default": 0x3c00},
			{"address": 0x0005C86C, "name": "wild_boar", "default": 0x2800},
			{"address": 0x0005C911, "name": "dog", "default": 0x1000},
			{"address": 0x0005C9A4, "name": "ahmet", "default": 0x5000},
			{"address": 0x0005CA03, "name": "baboon", "default": 0x1e00},
			{"address": 0x0005CB54, "name": "bat", "default": 0x0500},
			{"address": 0x0005CBB9, "name": "big_beetle", "default": 0x1e00},
			{"address": 0x0005B804, "name": "von_croy", "default": 0x0f00},
			#{"address": 0x000B19FF, "name": "small_scorpion", "default": 0x0800},
		]
		
		for row in enemy_health_table:
			f.seek(row["address"])
			enemy_health = int.from_bytes(f.read(2), byteorder='little', signed=True)
			
			print(row['name'] + ": " + str(enemy_health))
			
	return enemy_health_dictionary

def read_misc_info(f, is_patch_binary):
	print("Scanning Misc Info...")

	misc_info = {}

	if not is_patch_binary:
		# Remove Look Transparency
		look_transparency_byte = binary_funcs.get_u8_at_address(f, 0x0001d0c0)
		remove_look_transparency = True if look_transparency_byte == 0xeb else False
		print(f"Look Transparency Disabled: {str(remove_look_transparency)}.")

		# Lara impales on spikes
		lara_impales_on_spikes = False
		if binary_funcs.is_nop_at_range(f, 0x000160ED, 0x000160EE):
			lara_impales_on_spikes = True
		print(f"Lara Impales on Spikes: {str(lara_impales_on_spikes)}.")

		# Static Shatter Range
		lower_static_shatter_threshold = binary_funcs.get_u16_at_address(f, 0x0004d013)
		upper_static_shatter_threshold = binary_funcs.get_u16_at_address(f, 0x0004d019)
		print(f"Static Shatter Range: {str(lower_static_shatter_threshold)}-{str(upper_static_shatter_threshold)}.")

		# Poison Dart Bugfix
		poison_dart_bugfix = binary_funcs.compare_data_at_address(f, 0x00014044, bytes([0xF2]))
		print(f"Poison Dart Bugfix: {poison_dart_bugfix}.")

		# Poison Dart Value
		posion_dart_posion_value = binary_funcs.get_s16_at_address(f, 0x00014048)
		print(f"Poison Dart Poison Value: {posion_dart_posion_value}.")

		# Fix Holsters
		fix_holsters = False
		if not binary_funcs.is_nop_at_range(f, 0x0002B7C1, 0x0002B7CB) and not binary_funcs.is_nop_at_range(f, 0x0002B845, 0x0002B84F):
			fix_holsters = True
			print(f"Fix Holsters: {str(fix_holsters)}.")
		
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

	return stat_info

def read_bar_info(f, is_patch_binary):
	print("Scanning Bar Info...")

	bar_info = {}

	if not is_patch_binary:
		# Health Bar
		health_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5B0)
		if health_bar_main_color['r'] != 255 or health_bar_main_color['g'] != 0 or health_bar_main_color['b'] != 0:
			bar_info["health_bar_main_color"] = health_bar_main_color

		health_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5BA)
		if health_bar_fade_color['r'] != 0 or health_bar_fade_color['g'] != 0 or health_bar_fade_color['b'] != 0:
			bar_info["health_bar_fade_color"] = health_bar_fade_color

		health_bar_poison_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5AB)
		if health_bar_poison_color['r'] != 0 or health_bar_poison_color['g'] != 255 or health_bar_poison_color['b'] != 0:
			bar_info["health_bar_poison_color"] = {"r":0, "g":0, "b":0}

			bar_info["health_bar_poison_color"]['r'] = min(bar_info["health_bar_main_color"]['r'] + bar_info["health_bar_poison_color"]['r'], 255)
			bar_info["health_bar_poison_color"]['g'] = min(bar_info["health_bar_main_color"]['g'] + bar_info["health_bar_poison_color"]['g'], 255)
			bar_info["health_bar_poison_color"]['b'] = min(bar_info["health_bar_main_color"]['b'] + bar_info["health_bar_poison_color"]['b'], 255)


		health_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B5C5)
		if health_bar_width != 150:
			bar_info["health_bar_width"] = health_bar_width


		health_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B5C3)
		if health_bar_height != 12:
			bar_info["health_bar_height"] = health_bar_height

		health_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B5CC, bytes([0x50, 0xD7]))
		if health_bar_is_animated:
			bar_info["health_bar_is_animated"] = health_bar_is_animated

		# Air Bar
		air_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B565)
		if air_bar_main_color['r'] != 0 or air_bar_main_color['g'] != 0 or air_bar_main_color['b'] != 255:
			bar_info["air_bar_main_color"] = air_bar_main_color

		air_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B56D)
		if air_bar_fade_color['r'] != 0 or air_bar_fade_color['g'] != 0 or air_bar_fade_color['b'] != 0:
			bar_info["air_bar_fade_color"] = air_bar_fade_color

		air_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B579)
		if air_bar_width != 150:
			bar_info["air_bar_width"] = air_bar_width


		air_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B575)
		if air_bar_height != 12:
			bar_info["air_bar_height"] = air_bar_height
		
		air_bar_x_offset = binary_funcs.get_s16_at_address(f, 0x0007B57F)
		if air_bar_x_offset != 490:
			bar_info["air_bar_x_offset"] = air_bar_x_offset
		
		air_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B587, bytes([0x95, 0xD7]))
		if air_bar_is_animated:
			bar_info["air_bar_is_animated"] = air_bar_is_animated
		
		# Sprint Bar
		sprint_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B523)
		if sprint_bar_main_color['r'] != 0 or sprint_bar_main_color['g'] != 255 or sprint_bar_main_color['b'] != 0:
			bar_info["sprint_bar_main_color"] = sprint_bar_main_color


		sprint_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B528)
		if sprint_bar_fade_color['r'] != 0 or sprint_bar_fade_color['g'] != 0 or sprint_bar_fade_color['b'] != 0:
			bar_info["sprint_bar_fade_color"] = sprint_bar_fade_color

		sprint_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B538)
		if sprint_bar_width != 150:
			bar_info["sprint_bar_width"] = sprint_bar_width
		
		
		sprint_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B536)
		if sprint_bar_height != 12:
			bar_info["sprint_bar_height"] = sprint_bar_height

		sprint_bar_x_offset = binary_funcs.get_s16_at_address(f, 0x0007B531)
		if sprint_bar_x_offset != 490:
			bar_info["sprint_bar_x_offset"] = sprint_bar_x_offset

		sprint_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B541, bytes([0xDB, 0xD7]))
		if sprint_bar_is_animated:
			bar_info["sprint_bar_is_animated"] = sprint_bar_is_animated
		
		# Loading Bar
		loading_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65A)
		if loading_bar_main_color['r'] != 159 or loading_bar_main_color['g'] != 31 or loading_bar_main_color['b'] != 128:
			bar_info["loading_bar_main_color"] = loading_bar_main_color


		loading_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65F)
		if loading_bar_fade_color['r'] != 0 or loading_bar_fade_color['g'] != 0 or loading_bar_fade_color['b'] != 0:
			bar_info["loading_bar_fade_color"] = loading_bar_fade_color

		loading_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B693)
		if loading_bar_width != 600:
			bar_info["loading_bar_width"] = loading_bar_width
		
		loading_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B68F)
		if loading_bar_height != 15:
			bar_info["loading_bar_height"] = loading_bar_height

		loading_bar_hidden = binary_funcs.is_nop_at_range(f, 0x0007B601, 0x0007B604)
		if loading_bar_hidden:
			bar_info["loading_bar_hidden"] = loading_bar_hidden

		# Gradiant
		is_gradiant_bar = check_if_using_gradiant_bar(f)
		if is_gradiant_bar:
			bar_info["is_gradiant_bar"] = is_gradiant_bar

	return bar_info


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
			environment_info["fog_end_range"] = fog_end_range

		# Hard Clipping Range
		hard_clipping_range_first_value = binary_funcs.get_u32_at_address(f, 0x00075107)
		hard_clipping_range_second_value = binary_funcs.get_u32_at_address(f, 0x0008CE33)

		if (hard_clipping_range_first_value == hard_clipping_range_second_value):
			if hard_clipping_range_first_value != 20480:
				environment_info["far_view"] = int(hard_clipping_range_first_value)
		else:
			print(f"Hard Clipping Range: MISMATCH.")

		# Distant Fog Range
		fog_start_range = int(binary_funcs.get_float_at_address(f, 0x000B2498))
		if fog_start_range != 12288:
			environment_info["fog_start_range"] = fog_start_range

	return environment_info

def read_extended_info(f, is_extended_exe_size, patch_data, is_patch_binary):
	print("Scanning Extended Info...")
	
	patch_data["meta_info"]["esse_scripted_params"] = False
	patch_data["meta_info"]["esse_multiple_mirrors"] = False

	patch_data["meta_info"]["furr_support"] = False
	
	if is_extended_exe_size:
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

		if not is_patch_binary:
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
				enable_custom_switch_animation_ocb = True
				print(f"Enable Custom Switch Animation OCB: {str(enable_custom_switch_animation_ocb)}")

				switch_on_ocb1_anim = binary_funcs.get_s16_at_address(f, 0x000EFC6E) # 1
				switch_off_ocb1_anim = binary_funcs.get_s16_at_address(f, 0x000EFD00) # 2

				switch_on_ocb2_anim = binary_funcs.get_s16_at_address(f, 0x000EFC00) # 3
				switch_off_ocb2_anim = binary_funcs.get_s16_at_address(f, 0x000EFC96) # 4

				switch_on_ocb5_anim = binary_funcs.get_s16_at_address(f, 0x000EFC42) # 5
				switch_off_ocb5_anim = binary_funcs.get_s16_at_address(f, 0x000EFCD8) # 6

				switch_on_ocb6_anim = binary_funcs.get_s16_at_address(f, 0x000EFC56) # 7
				switch_off_ocb6_anim = binary_funcs.get_s16_at_address(f, 0x000EFCEC) # 8

			# Enable Rollingball Smash and Kill
			enable_rollingball_smash_and_kill = False
			if not binary_funcs.is_nop_at_range(f, 0x000EEDE0, 0x000EEE17):
				enable_rollingball_smash_and_kill = True
				print(f"Enable Rollingball Smash and Kill: {str(enable_rollingball_smash_and_kill)}")

		# Enable Ricochet SFX
		if not binary_funcs.is_nop_at_range(f, 0x000EE422, 0x000EE43E):
			patch_data["misc_info"]["enable_ricochet_sound_effect"] = True

		# Enable Ricochet SFX
		if not binary_funcs.is_nop_at_range(f, 0x000EE43F, 0x000EE9DE):
			patch_data["misc_info"]["enable_standing_pushables"] = True

	return patch_data

    
def read_binary_file(exe_file_path, is_extended_exe_size, is_using_remapped_memory, is_patch_binary):
	patch_data = {}

	# Meta info is not serialized
	patch_data["meta_info"] = {}

	with open(exe_file_path, 'rb') as f:
		print("---")
		patch_data["audio_info"] = read_audio_info(f, is_using_remapped_memory, is_patch_binary)
		print("---")
		patch_data["bar_info"] = read_bar_info(f, is_patch_binary)
		print("---")
		read_enemy_info(f, is_patch_binary)
		print("---")
		patch_data["environment_info"] = read_environment_info(f, is_patch_binary)
		print("---")
		patch_data["stat_info"] = read_stat_info(f, is_patch_binary)
		print("---")
		patch_data["misc_info"] = read_misc_info(f, is_patch_binary)
		print("---")
		patch_data = read_extended_info(f, is_extended_exe_size, patch_data, is_patch_binary)
		print("---")

	return patch_data