import os
import struct

def read_data(f, d, key_name, base_offset, offset, max_block_size, type, string_width, default_value):
    data = None

    f.seek(base_offset + offset)
    
    if type == 'FLOAT':
        if (offset + 4) <= max_block_size:
            data = struct.unpack('f', f.read(4))[0]
        else:
            data = struct.unpack('f', struct.pack('I', default_value))
    elif type == 'BOOL':
        if (offset + 1) <= max_block_size:
            data = bool(struct.unpack('?', f.read(1))[0])
        else:
            data = default_value
    elif type == 'BYTE':
        if (offset + 1) <= max_block_size:
            data = struct.unpack('B', f.read(1))[0]
        else:
            data = default_value
    elif type == 'BYTEI':
        if (offset + 1) <= max_block_size:
            data = struct.unpack('b', f.read(1))[0]
        else:
            data = default_value
    elif type == 'WORD':
        if (offset + 2) <= max_block_size:
            data = struct.unpack('H', f.read(2))[0]
        else:
            data = default_value
    elif type == 'WORDI':
        if (offset + 2) <= max_block_size:
            data = struct.unpack('h', f.read(2))[0]
        else:
            data = default_value
    elif type == 'DWORD':
        if (offset + 4) <= max_block_size:
            data = struct.unpack('I', f.read(4))[0]
        else:
            data = default_value
    elif type == 'HEX':
        if (offset + 3) <= max_block_size:
            data = '#{:02x}{:02x}{:02x}'.format(*struct.unpack('BBB', f.read(3)))
        else:
            return '#000000'
    elif type == 'STRING':
        data = f.read().decode('ascii')
    elif type == 'FIXED_STRING':
        if (offset + string_width) <= max_block_size:
            data = f.read(string_width).decode('ascii')
        else:
            data = str(default_value)
    else:
        data = default_value

    d[key_name] = data

    return d

def read_binary_file(file_path, patch_data):
    if not os.path.exists(file_path):
        print(f"The file {file_path} does not exist.")
        return None

    with open(file_path, 'rb') as f:
        level_count = struct.unpack('B', f.read(1))[0]
        f.seek(1)
        level_block_size = struct.unpack('I', f.read(4))[0]

        level_array = []

        for i in range(0, level_count):
            data = {}
            
            base_offset = 5 + (level_block_size * i)

            f.seek(0)

            data = read_data(f, data, 'DD', base_offset, 0, level_block_size, "FLOAT", 0, 20480)
            data = read_data(f, data, 'DF', base_offset, 4, level_block_size, "FLOAT", 0, 12288)
            data = read_data(f, data, 'VolFX', base_offset, 8, level_block_size, "BOOL", 0, True)

            # Weapon Data
            # Pistols
            data = read_data(f, data, 'PistolDmg', base_offset, 9, level_block_size, "BYTE", 0, 1)
            data = read_data(f, data, 'PistolRate', base_offset, 10, level_block_size, "BYTE", 0, 9)
            data = read_data(f, data, 'PistolDisp', base_offset, 10, level_block_size, "BYTE", 0, 5)
            data = read_data(f, data, 'PistolFlashDur', base_offset, 12, level_block_size, "BYTE", 0, 3)

            # Uzis
            data = read_data(f, data, 'UziDmg', base_offset, 13, level_block_size, "BYTE", 0, 1)
            data = read_data(f, data, 'UziRate', base_offset, 14, level_block_size, "BYTE", 0, 3)
            data = read_data(f, data, 'UziDisp', base_offset, 15, level_block_size, "BYTE", 0, 5)
            data = read_data(f, data, 'UziFlashDur', base_offset, 16, level_block_size, "BYTE", 0, 3)

            # Revolver
            data = read_data(f, data, 'RevolverDmg', base_offset, 17, level_block_size, "BYTE", 0, 21)
            data = read_data(f, data, 'RevolverRate', base_offset, 18, level_block_size, "BYTE", 0, 16)
            data = read_data(f, data, 'RevolverDisp', base_offset, 19, level_block_size, "BYTE", 0, 2)
            data = read_data(f, data, 'RevolverFlashDur', base_offset, 20, level_block_size, "BYTE", 0, 3)

            # Shotgun
            data = read_data(f, data, 'ShotgunDmg', base_offset, 21, level_block_size, "BYTE", 0, 3)
            data = read_data(f, data, 'ShotgunFlashDur', base_offset, 22, level_block_size, "BYTE", 0, 3)

            # Gravity
            data = read_data(f, data, 'Gravity', base_offset, 23, level_block_size, "BYTE", 0, 5)

            # DFThresh
            data = read_data(f, data, 'DFThresh', base_offset, 24, level_block_size, "FLOAT", 0, 20480)

            # WUVScroll
            data = read_data(f, data, 'WUVScroll', base_offset, 28, level_block_size, "BYTEI", 0, 7)

            # Waterfall Mist Parameters
            data = read_data(f, data, 'MistRGB1', base_offset, 30, level_block_size, "HEX", 0, "#c0c0c0")
            data = read_data(f, data, 'MistRGB2', base_offset, 33, level_block_size, "HEX", 0, "#808080")
            data = read_data(f, data, 'MistSize', base_offset, 36, level_block_size, "BYTE", 0, 12)
            data = read_data(f, data, 'MistDensity', base_offset, 37, level_block_size, "BYTE", 0, 6)
            data = read_data(f, data, 'MistAmount', base_offset, 38, level_block_size, "BYTE", 0, 4)

            # Lights
            data = read_data(f, data, 'PistolFlashArea', base_offset, 39, level_block_size, "BYTE", 0, 10)
            data = read_data(f, data, 'RevolverFlashArea', base_offset, 40, level_block_size, "BYTE", 0, 12)
            data = read_data(f, data, 'ShotgunFlashArea', base_offset, 41, level_block_size, "BYTE", 0, 12)
            data = read_data(f, data, 'FlameEmitterArea', base_offset, 42, level_block_size, "BYTE", 0, 16)
            data = read_data(f, data, 'BlinkingLightRGB', base_offset, 43, level_block_size, "HEX", 0, "#ffc010")
            data = read_data(f, data, 'BlinkingLightArea', base_offset, 46, level_block_size, "BYTE", 0, 16)
            
            # HP, ect.
            data = read_data(f, data, 'HealthAtStartup', base_offset, 47, level_block_size, "WORD", 0, 1000)
            data = read_data(f, data, 'AirAtStartup', base_offset, 49, level_block_size, "WORD", 0, 1800)


            # Weapons
            data = read_data(f, data, 'ShotgunShots', base_offset, 51, level_block_size, "BYTE", 0, 6)
            data = read_data(f, data, 'CrossbowBoltSpeed', base_offset, 52, level_block_size, "WORD", 0, 512)
            data = read_data(f, data, 'CrossbowDmg', base_offset, 54, level_block_size, "WORD", 0, 5)
            data = read_data(f, data, 'ExplosiveDamage', base_offset, 55, level_block_size, "BYTE", 0, 30)
            data = read_data(f, data, 'CrossbowFlags', base_offset, 56, level_block_size, "HEX", 0, "#010203")
            data = read_data(f, data, 'GrenadeFlags', base_offset, 59, level_block_size, "HEX", 0, "#010203")
            data = read_data(f, data, 'GrenadeTimeout', base_offset, 62, level_block_size, "WORD", 0, 120)
            data = read_data(f, data, 'GrenadeWeight', base_offset, 64, level_block_size, "BYTE", 0, 3)
            data = read_data(f, data, 'GrenadeLaunchPower', base_offset, 65, level_block_size, "WORD", 0, 128)
            data = read_data(f, data, 'GrenadeOneTouch', base_offset, 67, level_block_size, "BOOL", 0, False)
            data = read_data(f, data, 'GrenadeRotation', base_offset, 68, level_block_size, "BOOL", 0, True)
            data = read_data(f, data, 'PistolTargDistance', base_offset, 69, level_block_size, "WORD", 0, 8192)
            data = read_data(f, data, 'UziTargDistance', base_offset, 71, level_block_size, "WORD", 0, 8192)
            data = read_data(f, data, 'RevolverTargDistance', base_offset, 73, level_block_size, "WORD", 0, 8192)
            data = read_data(f, data, 'ShotgunTargDistance', base_offset, 75, level_block_size, "WORD", 0, 8192)
            data = read_data(f, data, 'GrenadeTargDistance', base_offset, 77, level_block_size, "WORD", 0, 8192)
            data = read_data(f, data, 'CrossbowTargDistance', base_offset, 79, level_block_size, "WORD", 0, 8192)

            # Traps
            data = read_data(f, data, 'JobySpikesSpeed', base_offset, 81, level_block_size, "BYTE", 0, 3)
            data = read_data(f, data, 'NormalSpikesTimer', base_offset, 82, level_block_size, "WORD", 0, 64)
            data = read_data(f, data, 'NormalSpikesSpeed', base_offset, 84, level_block_size, "WORD", 0, 128)
            data = read_data(f, data, 'DartsInterval', base_offset, 86, level_block_size, "WORD", 0, 24)
            data = read_data(f, data, 'DartsSpeed', base_offset, 88, level_block_size, "WORD", 0, 256)
            data = read_data(f, data, 'DartsRGB', base_offset, 90, level_block_size, "HEX", 0, "#783c14")
            data = read_data(f, data, 'BoulderGravity', base_offset, 93, level_block_size, "BYTE", 0, 6)
            data = read_data(f, data, 'ConductorInterval', base_offset, 94, level_block_size, "BYTE", 0, 63)

            # Weapon Names
            data = read_data(f, data, 'PistolsName', base_offset, 95, level_block_size, "FIXED_STRING", 26, "Pistols")
            data = read_data(f, data, 'UzisName', base_offset, 121, level_block_size, "FIXED_STRING", 26, "Uzis")
            data = read_data(f, data, 'ShotgunName', base_offset, 147, level_block_size, "FIXED_STRING", 26, "Shotgun")
            data = read_data(f, data, 'RevolverName', base_offset, 173, level_block_size, "FIXED_STRING", 26, "Revolver")
            data = read_data(f, data, 'RevolverLaserName', base_offset, 199, level_block_size, "FIXED_STRING", 26, "Revolver + LaserSight")
            data = read_data(f, data, 'CrossbowName', base_offset, 225, level_block_size, "FIXED_STRING", 26, "Crossbow")
            data = read_data(f, data, 'CrossbowLaserName', base_offset, 251, level_block_size, "FIXED_STRING", 26, "Crossbow + LaserSight")
            data = read_data(f, data, 'GrenadeName', base_offset, 277, level_block_size, "FIXED_STRING", 26, "Grenade Gun")

            # Ammo Names
            data = read_data(f, data, 'SGNormAmmoName', base_offset, 303, level_block_size, "FIXED_STRING", 26, "Shotgun Normal Ammo")
            data = read_data(f, data, 'SGWideAmmoName', base_offset, 329, level_block_size, "FIXED_STRING", 26, "Shotgun Wideshot Ammo")
            data = read_data(f, data, 'GrenadeNormAmmoName', base_offset, 355, level_block_size, "FIXED_STRING", 26, "Grenade Gun Normal Ammo")
            data = read_data(f, data, 'GrenadeSuperAmmoName', base_offset, 381, level_block_size, "FIXED_STRING", 26, "Grenade Gun Super Ammo")
            data = read_data(f, data, 'GrenadeFlashAmmoName', base_offset, 407, level_block_size, "FIXED_STRING", 26, "Grenade Gun Flash Ammo")
            data = read_data(f, data, 'XBowNormAmmoName', base_offset, 433, level_block_size, "FIXED_STRING", 26, "Crossbow Normal Ammo")
            data = read_data(f, data, 'XBowPoisonAmmoName', base_offset, 459, level_block_size, "FIXED_STRING", 26, "Crossbow Poison Ammo")
            data = read_data(f, data, 'XBowExplAmmoName', base_offset, 485, level_block_size, "FIXED_STRING", 26, "Crossbow Explosive Ammo")

            data = read_data(f, data, 'RevolverAmmoName', base_offset, 511, level_block_size, "FIXED_STRING", 26, "Revolver Ammo")
            data = read_data(f, data, 'UzisAmmoName', base_offset, 537, level_block_size, "FIXED_STRING", 26, "Uzis Ammo")
            data = read_data(f, data, 'PistolsAmmoName', base_offset, 563, level_block_size, "FIXED_STRING", 26, "Pistols Ammo")

            # Others
            data = read_data(f, data, 'LasersightName', base_offset, 589, level_block_size, "FIXED_STRING", 26, "Laser-Sight")
            data = read_data(f, data, 'LargeMedkitName', base_offset, 615, level_block_size, "FIXED_STRING", 26, "Large Medkit")
            data = read_data(f, data, 'SmallMedkitName', base_offset, 641, level_block_size, "FIXED_STRING", 26, "Small Medkit")
            data = read_data(f, data, 'BinocularsName', base_offset, 667, level_block_size, "FIXED_STRING", 26, "Binoculars")
            data = read_data(f, data, 'FlaresName', base_offset, 693, level_block_size, "FIXED_STRING", 26, "Flares")
            data = read_data(f, data, 'CrowbarName', base_offset, 719, level_block_size, "FIXED_STRING", 26, "Crowbar")

            # Object parameters
            data = read_data(f, data, 'FallingBlockTimeout', base_offset, 745, level_block_size, "WORD", 0, 60)
            data = read_data(f, data, 'FallingBlockTremble', base_offset, 747, level_block_size, "WORD", 0, 1023)
            data = read_data(f, data, 'RaisingBlockHeight', base_offset, 749, level_block_size, "WORD", 0, 1024)
            data = read_data(f, data, 'TwoBlockGoDown', base_offset, 751, level_block_size, "BOOL", 0, False)
            data = read_data(f, data, 'TwoBlockDeprDist', base_offset, 752, level_block_size, "WORD", 0, 128)
            data = read_data(f, data, 'TwoBlockDeprSpeed', base_offset, 754, level_block_size, "BYTE", 0, 4)
            data = read_data(f, data, 'TwoBlockReprSpeed', base_offset, 755, level_block_size, "BYTE", 0, 4)

            # Physics
            data = read_data(f, data, 'SwimSpeed', base_offset, 756, level_block_size, "WORD", 0, 200)

            # Enemy HP
            data = read_data(f, data, 'SkeletonHP', base_offset, 758, level_block_size, "WORD", 0, 15)
            data = read_data(f, data, 'Baddy1HP', base_offset, 760, level_block_size, "WORD", 0, 25)
            data = read_data(f, data, 'Baddy2HP', base_offset, 762, level_block_size, "WORD", 0, 35)
            data = read_data(f, data, 'ScorpionHP', base_offset, 764, level_block_size, "WORD", 0, 80)
            data = read_data(f, data, 'MummyHP', base_offset, 766, level_block_size, "WORD", 0, 15)
            data = read_data(f, data, 'KnightTemplarHP', base_offset, 768, level_block_size, "WORD", 0, 15)
            data = read_data(f, data, 'SphinxHP', base_offset, 770, level_block_size, "WORD", 0, 1000)
            data = read_data(f, data, 'SethHP', base_offset, 772, level_block_size, "WORD", 0, 500)
            data = read_data(f, data, 'HorsemenHP', base_offset, 774, level_block_size, "WORD", 0, 25)
            data = read_data(f, data, 'HammerheadHP', base_offset, 776, level_block_size, "WORD", 0, 45)
            data = read_data(f, data, 'CrocHP', base_offset, 778, level_block_size, "WORD", 0, 36)
            data = read_data(f, data, 'MutantHP', base_offset, 780, level_block_size, "WORD", 0, 15)
            data = read_data(f, data, 'GuideHP', base_offset, 782, level_block_size, "WORD", 0, -16384)
            data = read_data(f, data, 'Demigod1HP', base_offset, 784, level_block_size, "WORD", 0, 200)
            data = read_data(f, data, 'Demigod2HP', base_offset, 786, level_block_size, "WORD", 0, 200)
            data = read_data(f, data, 'Demigod3HP', base_offset, 788, level_block_size, "WORD", 0, 200)
            data = read_data(f, data, 'TroopsHP', base_offset, 790, level_block_size, "WORD", 0, 40)
            data = read_data(f, data, 'SASHP', base_offset, 792, level_block_size, "WORD", 0, 40)
            data = read_data(f, data, 'HarpyHP', base_offset, 794, level_block_size, "WORD", 0, 60)
            data = read_data(f, data, 'WildBoarHP', base_offset, 796, level_block_size, "WORD", 0, 40)
            data = read_data(f, data, 'DogHP', base_offset, 798, level_block_size, "WORD", 0, 16)
            data = read_data(f, data, 'AhmetHP', base_offset, 800, level_block_size, "WORD", 0, 80)
            data = read_data(f, data, 'BaboonHP', base_offset, 802, level_block_size, "WORD", 0, 30)
            data = read_data(f, data, 'BatHP', base_offset, 804, level_block_size, "WORD", 0, 5)
            data = read_data(f, data, 'BigBeetleHP', base_offset, 806, level_block_size, "WORD", 0, 30)
            data = read_data(f, data, 'VonCroyHP', base_offset, 808, level_block_size, "WORD", 0, 15)

            # Enemy Damage
            data = read_data(f, data, 'BaddyUZIDmg', base_offset, 810, level_block_size, "BYTE", 0, 15)
            data = read_data(f, data, 'SASMachinegunDmg', base_offset, 811, level_block_size, "BYTE", 0, 15)
            data = read_data(f, data, 'TurretDmg', base_offset, 812, level_block_size, "BYTE", 0, 5)
            data = read_data(f, data, 'BatDmg', base_offset, 813, level_block_size, "BYTEI", 0, 2)
            data = read_data(f, data, 'CrocUWDmg', base_offset, 814, level_block_size, "BYTEI", 0, 120)
            data = read_data(f, data, 'CrocLandDmg', base_offset, 815, level_block_size, "BYTEI", 0, 120)
            data = read_data(f, data, 'LocustDmg', base_offset, 816, level_block_size, "BYTEI", 0, 3)
            data = read_data(f, data, 'MummyDmg', base_offset, 817, level_block_size, "BYTEI", 0, 100)
            data = read_data(f, data, 'BaddySwordDmg', base_offset, 818, level_block_size, "BYTEI", 0, 120)
            data = read_data(f, data, 'SmallScorpionDmg', base_offset, 819, level_block_size, "BYTEI", 0, 20)
            data = read_data(f, data, 'DogDmg', base_offset, 820, level_block_size, "BYTEI", 0, 10)
            data = read_data(f, data, 'SkeletonAttack1Dmg', base_offset, 821, level_block_size, "BYTEI", 0, 80)
            data = read_data(f, data, 'SkeletonAttack2Dmg', base_offset, 822, level_block_size, "BYTEI", 0, 80)
            data = read_data(f, data, 'WildBoarDmg', base_offset, 823, level_block_size, "BYTEI", 0, 30)
            data = read_data(f, data, 'HarpyDmg', base_offset, 824, level_block_size, "BYTEI", 0, 10)
            data = read_data(f, data, 'ScorpionDmg', base_offset, 825, level_block_size, "BYTEI", 0, 120)
            data = read_data(f, data, 'HammerheadDmg', base_offset, 826, level_block_size, "BYTEI", 0, 120)
            data = read_data(f, data, 'KnightTemplarDmg', base_offset, 827, level_block_size, "BYTEI", 0, 120)
            data = read_data(f, data, 'BigBeetleDmg', base_offset, 828, level_block_size, "BYTEI", 0, 50)
            data = read_data(f, data, 'SphinxDmg', base_offset, 829, level_block_size, "WORDI", 0, 200)
            data = read_data(f, data, 'SethAttack1Dmg', base_offset, 831, level_block_size, "WORDI", 0, 200)
            data = read_data(f, data, 'SethAttack2Dmg', base_offset, 833, level_block_size, "WORDI", 0, 250)

            # Ponytail Mode
            data = read_data(f, data, 'PonytailMode', base_offset, 835, level_block_size, "BYTE", 0, 0)

            # Moterbike Headlight
            data = read_data(f, data, 'MotorbikeHeadlight', base_offset, 836, level_block_size, "BOOL", 0, True)

            # MP Bar Param
            data = read_data(f, data, 'MPBarRGB1', base_offset, 837, level_block_size, "HEX", 0, "#ffaa00") # FFAA00 AAFF
            data = read_data(f, data, 'MPBarRGB2', base_offset, 840, level_block_size, "HEX", 0, "#000000")
            data = read_data(f, data, 'MPBarDecSpeed', base_offset, 843, level_block_size, "BYTE", 0, 30)
            data = read_data(f, data, 'MPBarIncSpeed', base_offset, 844, level_block_size, "BYTE", 0, 15)
            data = read_data(f, data, 'MPBarHPDecSpeed', base_offset, 845, level_block_size, "BYTE", 0, 40)
            data = read_data(f, data, 'AudioPath', base_offset, 847, level_block_size, "FIXED_STRING", 53, "audio\\%s")
            data = read_data(f, data, 'HardClipRange', base_offset, 900, level_block_size, "DWORD", 0, 20480)
            data = read_data(f, data, 'LoadingPath', base_offset, 904, level_block_size, "FIXED_STRING", 40, "screens\loading.bmp")
            data = read_data(f, data, 'OptionsScreen', base_offset, 944, level_block_size, "FIXED_STRING", 40, "screens\options.bmp")
            data = read_data(f, data, 'InventoryScreen', base_offset, 984, level_block_size, "FIXED_STRING", 40, "screens\inventory.bmp")
            data = read_data(f, data, 'LoadSaveScreen', base_offset, 1024, level_block_size, "FIXED_STRING", 40, "screens\loadsave.bmp")

            # Names
            data = read_data(f, data, 'SkeletonName', base_offset, 1064, level_block_size, "FIXED_STRING", 40, "Skeleton")
            data = read_data(f, data, 'GuideName', base_offset, 1104, level_block_size, "FIXED_STRING", 40, "Guide")
            data = read_data(f, data, 'VonCroynName', base_offset, 1144, level_block_size, "FIXED_STRING", 40, "Von Croy")
            data = read_data(f, data, 'Baddy1Name', base_offset, 1184, level_block_size, "FIXED_STRING", 40, "Baddy")
            data = read_data(f, data, 'Baddy2Name', base_offset, 1224, level_block_size, "FIXED_STRING", 40, "Black Baddy")
            data = read_data(f, data, 'SethaName', base_offset, 1264, level_block_size, "FIXED_STRING", 40, "Seth")
            data = read_data(f, data, 'MummyName', base_offset, 1304, level_block_size, "FIXED_STRING", 40, "Mummy")
            data = read_data(f, data, 'SphinxName', base_offset, 1344, level_block_size, "FIXED_STRING", 40, "Sphinx")
            data = read_data(f, data, 'CrocodileName', base_offset, 1384, level_block_size, "FIXED_STRING", 40, "Crocodile")
            data = read_data(f, data, 'HorsemanName', base_offset, 1424, level_block_size, "FIXED_STRING", 40, "Horseman")
            data = read_data(f, data, 'ScorpionName', base_offset, 1464, level_block_size, "FIXED_STRING", 40, "Scorpion")
            data = read_data(f, data, 'JeanYvesName', base_offset, 1504, level_block_size, "FIXED_STRING", 40, "Jean Yves")
            data = read_data(f, data, 'TroopsName', base_offset, 1544, level_block_size, "FIXED_STRING", 40, "Troops")
            data = read_data(f, data, 'KnightTemplarName', base_offset, 1584, level_block_size, "FIXED_STRING", 40, "Knight Templar")
            data = read_data(f, data, 'MutantName', base_offset, 1624, level_block_size, "FIXED_STRING", 40, "Mutant")
            data = read_data(f, data, 'HorseName', base_offset, 1664, level_block_size, "FIXED_STRING", 40, "Horse")
            data = read_data(f, data, 'BaboonNormalName', base_offset, 1704, level_block_size, "FIXED_STRING", 40, "Baboon")
            data = read_data(f, data, 'BaboonInvName', base_offset, 1744, level_block_size, "FIXED_STRING", 40, "Baboon (invisible)")
            data = read_data(f, data, 'BaboonSilentName', base_offset, 1784, level_block_size, "FIXED_STRING", 40, "Baboon (silent)")
            data = read_data(f, data, 'WildBoarName', base_offset, 1824, level_block_size, "FIXED_STRING", 40, "Wild boar")
            data = read_data(f, data, 'HarpyName', base_offset, 1864, level_block_size, "FIXED_STRING", 40, "Harpy")
            data = read_data(f, data, 'Demigod1Name', base_offset, 1904, level_block_size, "FIXED_STRING", 40, "Demigod")
            data = read_data(f, data, 'Demigod2Name', base_offset, 1944, level_block_size, "FIXED_STRING", 40, "Demigod 2")
            data = read_data(f, data, 'Demigod3Name', base_offset, 1984, level_block_size, "FIXED_STRING", 40, "Demigod 3")
            data = read_data(f, data, 'BigBeetleName', base_offset, 2024, level_block_size, "FIXED_STRING", 40, "Beetle")
            data = read_data(f, data, 'BatName', base_offset, 2064, level_block_size, "FIXED_STRING", 40, "Bat")
            data = read_data(f, data, 'DogName', base_offset, 2104, level_block_size, "FIXED_STRING", 40, "Dog")
            data = read_data(f, data, 'HammerheadName', base_offset, 2144, level_block_size, "FIXED_STRING", 40, "Hammer-headed shark")
            data = read_data(f, data, 'SASName', base_offset, 2184, level_block_size, "FIXED_STRING", 40, "Special Air Service soldier")
            data = read_data(f, data, 'AhmetName', base_offset, 2224, level_block_size, "FIXED_STRING", 40, "Ahmet")
            data = read_data(f, data, 'LaraDoubleName', base_offset, 2264, level_block_size, "FIXED_STRING", 40, "Strange statue...")
            data = read_data(f, data, 'SmallScorpionName', base_offset, 2304, level_block_size, "FIXED_STRING", 40, "Small scorpion")
            data = read_data(f, data, 'SentryGunName', base_offset, 2344, level_block_size, "FIXED_STRING", 40, "SAS Sentry Gun")

            # Horizontal Mirrors
            hor_mirror_offset = 2384
            for i in range(1, 20+1):
                data = read_data(f, data, 'HorMirror' + str(i).zfill(2), base_offset, hor_mirror_offset, level_block_size, "BYTE", 0, 255)
                data = read_data(f, data, 'HorMirror' + str(i).zfill(2) + 'Room', base_offset, hor_mirror_offset + 1, level_block_size, "DWORD", 0, 0)
                hor_mirror_offset += 5

            # Vertical Mirrors
            vert_mirror_offset = 2484
            for i in range(1, 50+1):
                data = read_data(f, data, 'VertMirror' + str(i).zfill(2), base_offset, vert_mirror_offset, level_block_size, "BYTE", 0, 255)
                data = read_data(f, data, 'VertMirror' + str(i).zfill(2) + 'Room', base_offset, vert_mirror_offset + 1, level_block_size, "DWORD", 0, 0)
                vert_mirror_offset += 5
                

            level_info = {}

            if patch_data["meta_info"]["esse_scripted_params"] == True:
                environment_info = {}
                
                environment_info["fog_start_range"] = int(data["DF"])
                environment_info["fog_end_range"] = int(data["DFThresh"])
                environment_info["far_view"] = int(data["DD"])

                level_info["environment_info"] = environment_info

            level_array.append(level_info)

    return level_array