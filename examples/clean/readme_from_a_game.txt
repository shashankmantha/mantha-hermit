Example "known-clean" file for the demo's clean-set test.

A legitimate game's installer notes. Its anti-cheat setup script runs
  Add-MpPreference -ExclusionPath "C:\Games\Example\AntiCheat"
so SUSP_Example_Defender_Exclusion fires on a clean file, and Hermit demotes that rule to info
instead of letting it raise verdicts on real games. It also mentions the steam_settings folder.
