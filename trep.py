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

def read_enemy_info(f):
	print("Scanning Misc Info...")

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

	enemy_health_dictionary = {}

	for row in enemy_health_table:
		f.seek(row["address"])
		enemy_health = int.from_bytes(f.read(2), byteorder='little', signed=True)
		
		print(row['name'] + ": " + str(enemy_health))
		
	return enemy_health_dictionary

def read_misc_info(f):
	print("Scanning Misc Info...")

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

	posion_dart_posion_value = binary_funcs.get_s16_at_address(f, 0x00014048)
	print(f"Poison Dart Poison Value: {posion_dart_posion_value}.")

	# Max Secrets
	max_secrets_string = binary_funcs.get_fixed_string_at(f, 0x000B1785, 2)
	print(f"Max Secrets: {max_secrets_string}.")

	# Fix Holsters
	fix_holsters = False
	if not binary_funcs.is_nop_at_range(f, 0x0002B7C1, 0x0002B7CB) and not binary_funcs.is_nop_at_range(f, 0x0002B845, 0x0002B84F):
		fix_holsters = True
		print(f"Fix Holsters: {str(fix_holsters)}.")

def read_bar_info(f):
	print("Scanning Bar Info...")

	# Health Bar
	health_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5B0)
	print(f"Health Bar Main Color: {str(health_bar_main_color)}.")
 
	health_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5bA)
	print(f"Health Bar Fade Color: {str(health_bar_fade_color)}.")

	health_bar_posion_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B5AB)
	print(f"Health Bar Poison Color: {str(health_bar_posion_color)}.")

	health_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B5C5)
	print(f"Health Bar Width: {str(health_bar_width)}.")

	health_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B5C3)
	print(f"Health Bar Height: {str(health_bar_height)}.")

	health_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B5CC, bytes([0x50, 0xD7]))
	print(f"Health Bar Is Animated: {str(health_bar_is_animated)}.")

	# Air Bar
	air_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B565)
	print(f"Air Bar Main Color: {str(air_bar_main_color)}.")

	air_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B56D)
	print(f"Air Bar Fade Color: {str(air_bar_fade_color)}.")

	air_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B579)
	print(f"Air Bar Width: {str(air_bar_width)}.")

	air_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B575)
	print(f"Air Bar Height: {str(air_bar_height)}.")
	
	air_bar_x_offset = binary_funcs.get_s16_at_address(f, 0x0007B57F)
	print(f"Air Bar X Offset: {str(air_bar_x_offset)}.")
	
	air_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B587, bytes([0xD5, 0xF9]))
	print(f"Air Bar Is Animated: {str(air_bar_is_animated)}.")
	
	# Sprint Bar
	sprint_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B523)
	print(f"Sprint Bar Main Color: {str(sprint_bar_main_color)}.")

	sprint_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B528)
	print(f"Sprint Bar Fade Color: {str(sprint_bar_fade_color)}.")

	sprint_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B538)
	print(f"Sprint Bar Width: {str(sprint_bar_width)}.")

	sprint_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B536)
	print(f"Sprint Bar Height: {str(sprint_bar_height)}.")

	sprint_bar_x_offset = binary_funcs.get_u8_at_address(f, 0x0007B531)
	print(f"Sprint Bar X Offset: {str(sprint_bar_x_offset)}.")

	sprint_bar_is_animated = binary_funcs.compare_data_at_address(f, 0x0007B541, bytes([0xDB, 0xD7]))
	print(f"Sprint Bar Is Animated: {str(sprint_bar_is_animated)}.")
	
	# Loading Bar
	loading_bar_main_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65A)
	print(f"Loading Bar Main Color: {str(loading_bar_main_color)}.")

	loading_bar_fade_color = binary_funcs.get_bgr_color_at_address(f, 0x0007B65F)
	print(f"Loading Bar Main Color: {str(loading_bar_fade_color)}.")

	loading_bar_width = binary_funcs.get_s16_at_address(f, 0x0007B693)
	print(f"Loading Bar Width: {str(loading_bar_width)}.")

	loading_bar_height = binary_funcs.get_u8_at_address(f, 0x0007B68F)
	print(f"Loading Bar Height: {str(loading_bar_height)}.")

	loading_bar_hidden = False
	if not binary_funcs.is_nop_at_range(f, 0x0007B601, 0x0007B604):
		loading_bar_hidden = True
		print(f"Loading Bar Is Hidden: {str(loading_bar_hidden)}.")

	# Gradiant
	is_gradiant_bar = check_if_using_gradiant_bar(f)
	print(f"Is Using Gradiant Bar: {str(is_gradiant_bar)}.")


def read_audio_info(f):
	print("Scanning Audio Info...")

	# Sample Rate
	#f.seek(0x000a7309)
	#sample_rate = int.from_bytes(f.read(2), byteorder='little', signed=False)
	#print(f"Sample Rate: {str(sample_rate)}.")
	
	disable_lara_hit_sfx = binary_funcs.compare_data_at_address(f, 0x0000B02A, bytes([0x90, 0x90, 0x90, 0x90, 0x90]))
	print(f"Disable Lara Hit SFX: {str(disable_lara_hit_sfx)}.")

	lara_hit_sfx = binary_funcs.get_s8_at_address(f, 0x0000B029)
	print(f"Lara Hit SFX: {str(lara_hit_sfx)}.")
	
	disable_no_ammo_sfx = binary_funcs.compare_data_at_address(f, 0x0002D814, bytes([0x90, 0x90, 0x90, 0x90, 0x90]))
	print(f"Disable Lara Hit SFX: {str(disable_no_ammo_sfx)}.")

	no_ammo_sfx = binary_funcs.get_s8_at_address(f, 0x0002D813)
	print(f"No Ammo SFX: {str(no_ammo_sfx)}.")

def read_distance_info(f):
	print("Scanning Distance Info...")

	turn_off_distance_limit_completely = False
	if binary_funcs.get_u8_at_address(f, 0x000702A6) == 0xEB and binary_funcs.get_u8_at_address(f, 0x00070492) == 0xEB and binary_funcs.get_u8_at_address(f, 0x000706A8):
		turn_off_distance_limit_completely = True
	print(f"Turn Off Distance Limit Completely: {str(turn_off_distance_limit_completely)}")

	# Drawing Distance Range
	drawing_distance_range = binary_funcs.get_float_at_address(f, 0x000B249C)
	print(f"Drawing Distance Range: {str(drawing_distance_range)}")

	# Hard Clipping Range
	hard_clipping_range_first_value = binary_funcs.get_u32_at_address(f, 0x00075107)
	hard_clipping_range_second_value = binary_funcs.get_u32_at_address(f, 0x0008CE33)

	if (hard_clipping_range_first_value == hard_clipping_range_second_value):
		print(f"Hard Clipping Range: {str(hard_clipping_range_first_value)}")
	else:
		print(f"Hard Clipping Range: MISMATCH.")

	# Distant Fog Range
	distance_fog_range = binary_funcs.get_float_at_address(f, 0x000B2498)
	print(f"Distance Fog Range: {str(distance_fog_range)}")

def read_extended_info(f, is_extended_exe_size):
	print("Scanning Extended Info...")
	
	if is_extended_exe_size:
		# Show HP bar in Inventory.
		show_hp_bar_in_inventory = False
		if not binary_funcs.is_nop_at_range(f, 0x000EFD90, 0x000EFDCB):
			show_hp_bar_in_inventory = True
		print(f"Show HP bar in Inventory: {str(show_hp_bar_in_inventory)}")

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

		# Enable Ricochet SFX
		enable_ricochet_sfx = False
		if not binary_funcs.is_nop_at_range(f, 0x000EE422, 0x000EE43E):
			enable_ricochet_sfx = True
		print(f"Enable Ricochet SFX: {str(enable_ricochet_sfx)}")

		# Enable Custom Switch Animation OCB
		enable_custom_switch_animation_ocb = False
		if not binary_funcs.is_nop_at_range(f, 0x000EFBD0, 0x000EFD2D):
			enable_custom_switch_animation_ocb = True
			print(f"Enable Custom Switch Animation OCB: {str(enable_ricochet_sfx)}")

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

    
def read_exe_file(exe_file_path, is_extended_exe_size):
    with open(exe_file_path, 'rb') as f:
        print("---")
        read_audio_info(f)
        print("---")
        read_bar_info(f)
        print("---")
        read_enemy_info(f)
        print("---")
        read_distance_info(f)
        print("---")
        read_misc_info(f)
        print("---")
        read_extended_info(f, is_extended_exe_size)
        print("---")