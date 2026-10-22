/*
  Example rules for the Hermit demo. They are synthetic: written for this repository to show how
  Hermit sorts, scores and packages rules. They match harmless planted strings, not real malware
  samples, and are not meant for production scanning.
*/

import "pe"

private rule Example_IsPE {
  condition: uint16(0) == 0x5A4D
}

rule MAL_Example_FakeCheat_SteamStealer : stealer {
  meta:
    description = "Example: info stealer posing as a game cheat, reads Steam login files and Discord tokens"
    author = "mantha-hermit examples"
    date = "2026-10-22"
    score = 85
  strings:
    $steam = "loginusers.vdf" ascii wide
    $ssfn = "\\Steam\\ssfn" ascii wide nocase
    $discord = "\\discord\\Local Storage\\leveldb" ascii wide nocase
  condition:
    Example_IsPE and 2 of them
}

rule MAL_Example_XMRig_Miner_Config {
  meta:
    description = "Example: XMRig miner configuration dropped by a fake crack"
    author = "mantha-hermit examples"
    date = "2026-10-22"
    score = 80
  strings:
    $pool = "stratum+tcp://" ascii
    $donate = "\"donate-level\"" ascii
    $algo = "\"algo\": \"rx/0\"" ascii
  condition:
    $pool and 1 of ($donate, $algo)
}

rule SUSP_Example_Defender_Exclusion {
  meta:
    description = "Example: script adds a Microsoft Defender exclusion before dropping a payload"
    author = "mantha-hermit examples"
    date = "2026-10-22"
    score = 65
  strings:
    $a = "Add-MpPreference" ascii wide nocase
    $b = "-ExclusionPath" ascii wide nocase
  condition:
    all of them
}

rule SUSP_Example_Renamed_SteamAPI_Emulator {
  meta:
    description = "Example: steam_api64.dll that is really a Steam emulator (common in cracked games)"
    author = "mantha-hermit examples"
    date = "2026-10-22"
    score = 60
  strings:
    $emu1 = "SmartSteamEmu" ascii
    $emu2 = "steam_settings" ascii
  condition:
    filename == "steam_api64.dll" and Example_IsPE and any of them
}

rule INFO_Example_Steam_Emulator_Settings {
  meta:
    description = "Example: Steam emulator settings folder referenced by a game file"
    author = "mantha-hermit examples"
    date = "2026-10-22"
    score = 40
  strings:
    $a = "steam_settings" ascii
    $b = "steam_emu.ini" ascii
  condition:
    any of them
}

rule PUA_Example_Game_Trainer {
  meta:
    description = "Example: game trainer / cheat tool (dual-use, potentially unwanted)"
    author = "mantha-hermit examples"
    date = "2026-10-22"
  strings:
    $a = "Trainer Options" ascii wide
    $b = "WriteProcessMemory" ascii
  condition:
    Example_IsPE and all of them
}

rule WEBSHELL_Example_PHP_Eval {
  meta:
    description = "Example: PHP web shell. Not applicable to any Mantha Ray pack, so Hermit leaves it out"
    author = "mantha-hermit examples"
    date = "2026-10-22"
  strings:
    $a = "<?php eval($_POST[" ascii
  condition:
    $a
}
