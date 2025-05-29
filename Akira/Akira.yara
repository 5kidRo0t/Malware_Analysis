import "pe"
rule Akira_malware
{
	meta:
		author="5kidRo0t"
		sha256="3d6c1fdfc04383ddb9a9028fa7181b017978a0d4f910fdfcb3905ed6b4f33418"
		sha512="13c6703aa542c813f2416562fb40f32b712ecae4de988e86ae5ab7758a66b11fa9cd1444bc39771ad5c54c9d7955f1a1fd34fa1bdc0f591e3da9cdd772979ad0"
	strings:
		$s1="0tYH91tT" nocase
		$s2="write_encrypt_info"
		$s3="IsDebuggerPresent"
		$s4="FreeLibrary"
		$s5="RtlPcToFileHeader"
		$s6="encryption"
		$s7="akiral2iz6a7qgd3ayp3l6yub7xx2uep76idk3u2kollpj5z3z636bad" nocase
		$s8="onion"
		$s9="akiralkzxzq2dsrzsrvbr2xgbbu2wgsmxryd4csgfameg52n7efvr2id" nocase
		$s10="5897704147" nocase
		$s11="akira" nocase
		$s12="torproject"
		$hex1={ 61 6B 69 72 61 6C 32 69 7A 36 61 37 71 67 64 33 61 79 70 33 6C 36 79 75 62 37 78 78 32 75 65 70 37 36 69 64 6B 33 75 32 6B 6F 6C 6C 70 6A 35 7A 33 7A 36 33 36 62 61 64 }
		$hex2={ 6F 6E 69 6F 6E }
		$hex3={ 38 39 30 33 2D 56 41 2D 4D 55 4D 47 2D 56 4A 4D 48 }
		$hex4={ 61 6B 69 72 61 }
	condition:
		9 of ($s*) and 2 of ($hex*) and pe.imphash() == "f89d971f855e5743dd4d1e73a5da5699"
}
