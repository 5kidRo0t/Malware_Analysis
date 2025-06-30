import "pe"
rule Amadey_Lumma_malware
{
	meta:
		author="5kidRo0t"
		sha256="44f15726d9891de7d857d4261d6b993afde0958aae26385271947e8820c309fe"
		sha512="82c72f074291992258ba435346cd1595784d65821d24cc2a2ac85b87c1bcc6561e1c292c744cad38136597e8ecc5c7f47d468ea9357f52fb4ee1c20f81d27722"
	strings:
		$s1="wpbpuxqb"
		$s2="lmjtwset"
		$s3="taggant"
		$s4="idata"
		$s5="6595b64144ccf1df"
		$hex1={ 69 64 61 74 61 }
		$hex2={ 77 70 62 70 75 78 71 62 }
		$hex3={ 6C 6D 6A 74 77 73 65 74 }
		$hex4={ 74 61 67 67 61 6E 74 }
		$hex5={ 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 }
	condition:
		all of them and pe.imphash() == "2eabe9054cad5152567f0699947a2c5b"
}
