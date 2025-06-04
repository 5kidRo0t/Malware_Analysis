import "pe"
rule snake_keylogger_malware
{
	meta:
		author="5kidRo0t"
		sha256="50ec898674f779ff3115b5d856c579eb89aa9702db8355a6a8f34616223a889c"
		sha512="c295f56f7c11c93606b7fbdd5d2b2ff9a15df6d19e6a1634687ffc78f99f84a021173f6a80d93d5e24aa4e6145d029db5996a91597f07daaf1d19ccf895ac5a5"
	strings:
		$s1="KhongXoa" nocase
		$s2="HashPasswordForStoringInConfigFile"
		$s3="ZFpR.exe"
		$s4="ZFpR"
		$s5="ngayvaodang"
		$s6="getAllTrinhDoLiLuanChinhTri" nocase
		$s7="GetAllNguonKinhPhi" nocase
		$s8="ThanhPhanXuatThan" nocase
		$s9="b03f5f7f11d50a3a" nocase
		$s10="b77a5c561934e089"
		$s11="D8A3F621-B4E7-4C95-9F18-A6C2E5D8B473" nocase
		$hex1={ 71 75 61 6E 68 61 6D }
		$hex2={ 6E 67 61 79 74 68 61 6D 67 69 61 63 6D }
		$hex3={ 44 38 41 33 46 36 32 31 2D 42 34 45 37 2D 34 43 39 35 2D 39 46 31 38 2D 41 36 43 32 45 35 44 38 42 34 37 33 }
	condition:
		(4 of ($s*) or any of ($hex*)) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"		
}
