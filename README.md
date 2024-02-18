# Tomb4Plus - Feature Extractor
## A tool for generating Tomb4Plus-compatible manifest files

This repository contains a companion tool for the [Tomb4Plus](https://github.com/saracenone/tomb4) engine designed to generate engine-compatible `game_mod_config.json` manifest files.

Since custom levels often use direct engine binary patches, and there are 1000s of TRLE-based custom levels spanning decades, this tool attempts to extract known modifications from commonly-used binary patches and convert them into a format that Tomb4Plus can understand. Patches can then be submitted to [this](https://github.com/saracenone/tomb4_manifest_directory) repository.

### Instructions
* Ensure you have Python 3 installed (https://www.python.org/downloads/)
* If you run on Windows, you can run it with the batch tool `start_windows.bat` or otherwise use the command `python tomb4_feature_extractor.py`.
* You will be prompted to input a path to a custom level. Make sure that it is the full file path and contains a file named `SCRIPT.DAT`. 
* You will then be prompted to enter the name of the .exe file which you execute to run the game. If its called `tomb4.exe` you can simply press enter and skip to the next step.
* If this is your first time attempting to generate a manifest file for this particular custom level, you will be prompted to input the name of the custom level, the author(s) names (preferred convention is using the handle names of all the known authors seperated by commas and in alphabetical order), the release date formatted as dd/mm/yyyy, and the name of the directory where user data like saves and screenshots will be stored (preferred convention is to use the name of the game folder which is usually `authorname-levelname`). Once this step is completed, a file named `metadata.ini` will be saved in the folder and this step will be skipped in the future as long as this file is present. You can also edit this file if you input any previous data incorrectly.
* If FURR scripting data is detected in the binary, you will be given a multiple choice prompt to choose the most appropriate syntax file in order to decompile it. This step is still very much experimental and will likely require trial and error to get the most accurate results. Try re-running the steps with an alternative syntax choice if you get mangled FURR data or submit an issue report with the custom level in question if none of the options works.
* Not every common binary modification is supported, so check back regularly for updates which should hopefully provide increased compatibility with custom patches.

### Contributing
PRs extending the capability of this tool are welcome.