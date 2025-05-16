import "pe"
rule DragonForce_malware
{
	meta:
		author="5kidRo0t"
		sha256="d06b5a200292fedcfb4d4aecac32387a2e5b5bb09aaab5199c56bab3031257d6"
		sha512="cd9e0773e076ee93a2640de1811f1a840612c13e6ba14b60493e086832e51ee9a060a6298449afd433a881ded761f9f199f589d5b637bc9bce1e0198fc37f5bb"
	strings:
		$s1="Mnbc"
		$s2="0N1i2"
		$s3="RSA"
		$s4="CryptGenRandom"
		$s5="CryptEncrypt"
		$s6="CryptImportKey"
		$s7="CryptAcquireContextA"
		$s8="Mark Adler"
		$hex1={ 57 6F 77 36 34 44 69 73 61 62 6C 65 57 6F 77 36 34 }
		$hex2={ 43 72 65 61 74 65 4D 75 74 65 78 41 }
		$hex3={ 43 72 79 70 74 47 65 6E 52 61 6E 64 6F 6D }
		$hex4={ 43 72 79 70 74 45 6E 63 72 79 70 74 }
		$hex5={ 43 72 79 70 74 49 6D 70 6F 72 74 4B 65 79 }
		$hex6={ 43 72 79 70 74 41 63 71 75 69 72 65 43 6F 6E 74 65 78 74 41 }
		$hex7={ 43 6F 53 65 74 50 72 6F 78 79 42 6C 61 6E 6B 65 74 }
		$hex8={ 52 6D 53 68 75 74 64 6F 77 6E }
		$hex9={ 4D 61 82 6B 20 41 64 6C 65 72 }
	condition:
		6 of ($s*) and 6 of ($hex*) and pe.imphash() == "d428b0554d443c341b28703744573111"	
}
