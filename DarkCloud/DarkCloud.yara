import "pe"
rule DarkCloud_Malware
{
	meta:
		author="5kidRo0t"
		sha256="ff14655342e9f2d6c62955f89111bded7e4d1f65237201e502fb9b7fbd75c46b"
		sha512="ef6a51976c716376c345f8a50cbb45969b834b99629809fa4424da8f2ea5d768f9304d529e5a9407180fac9c05aa5ea5d27fc4b2e80c99ce1708de5668941bca"
	strings:
		$s1="groupBox"
		$s2="AutomatedWrapper85"
		$s3="ProfessionalAnalyzer26"
		$s4="numericupdown9"
		$s5="LuongCB"
		$s6="Dwon.exe" nocase
		$s7="12345678-1234-5678-9abc-123456789012"
		$s8="b03f5f7f11d50a3a"
		$hex1={ 44 77 6f 6e }
		$hex2={ 4c 75 6f 6e 67 43 42 }
		$hex3={ 6c 75 6f 6e 67 43 42 }
		$hex4={ 44 77 6f 6e 2e 65 78 65 }
		$hex5={ 6e 61 6d 53 69 6e 68 }
		$hex6={ 4e 61 6d 53 69 6e 68 }
	condition:
		6 of ($s*) and 3 of ($hex*) and
		pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and
		pe.imports("mscoree.dll", "_CorExeMain")
}
