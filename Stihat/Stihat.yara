import "pe"
rule Stihat_malware
{
	meta:
		author="5kidRo0t"
		sha256="e3ab7fad9178ec1e501b33b191d9f9388e354ebc5e4d8e94ba50ea2b17450e19"
		sha512="4c9286a288a4150173c944aec5cde3a548f7c87a68d385c13b888a2f00e4ff872bf60d2755a173e4c6767b0fc0ea7d422e07ba886967ec0f3ba0b4eb323a39fc"
	strings:
		$s1="yxutw"
		$s2="fmbav"
		$s3="VarXor" nocase
		$s4="pmXor" nocase
		$s5="comctl32.dll"
		$s6="vcltest3.dll"
		$s7="Stone,I hate you!"
		$s8="Your disk is removed!"
		$s9="RegCreateKey"
		$s10="CallNextHookEx"
		$s11="kd_02_15b3.dll"
		$hex1={ 53 74 6F 6E 65 2C 49 20 68 61 74 65 20 79 6F 75 21 }
		$hex2={ 59 6F 75 72 20 64 69 73 6B 20 69 73 20 72 65 6D 6F 76 65 64 21 }
		$hex3={ 48 65 6C 70 4D 65 2E 65 78 65 }
		$hex4={ 4C 6F 61 64 42 69 74 6D 61 70 41 }
		$hex5={ 53 65 74 57 69 6E 64 6F 77 73 48 6F 6F 6B }
		$hex6={ 6B 64 5F 30 32 5F 31 35 62 33 2E 64 6C 6C }
	condition:
		(pe.imphash() == "17ed737e8e77e97fd1eb6ad9ba5d3eae") and (9 of ($s*) or 4 of ($hex*))
}
