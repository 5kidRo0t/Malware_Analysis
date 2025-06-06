import "pe"
rule Abantes_malware
{
	meta:
		author="5kidRo0t"
		sha256="dac4b5511343cf863832e38886af8a3e1d55529648314eb02cc21fa3979f6419"
		sha512="3ad23ad35d23acfa9edc187f443f28c4bb11279472632726f450b10cc09a653e10f4832f9cca44d063ad1259de6c7017ca6ca8f64ed07d302c3b2d06628f0ba7"
	strings:
		$s1="b77a5c561934e089"
		$s2="b03f5f7f11d50a3a"
		$s3="IFEODebugger"
		$s4="613d1c05-d148-4b44-b1c3-34254ee5d8a1"
		$s5="6595b64144ccf1df"
		$s6="Payloads" nocase
		$s7="AbantesTrojan" nocase
		$s8="infected" nocase
		$s9="ABANTES" nocase
		$s10="CreateEncryptor" nocase
		$hex1={ 41 62 61 6E 74 65 73 }
		$hex2={ 41 42 41 4E 54 45 53 }
		$hex3={ 45 4E 43 52 59 50 54 45 44 }
		$hex4={ 54 52 4F 4A 41 4E }
		$hex5={ 47 69 74 48 75 62 }
		$hex6={ 41 62 61 6E 74 65 73 54 72 6F 6A 61 6E }
		$hex7={ 36 35 39 35 62 36 34 31 34 63 63 66 31 64 66 }
	condition:
		7 of ($s*) and 4 of ($hex*) and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744"
}
