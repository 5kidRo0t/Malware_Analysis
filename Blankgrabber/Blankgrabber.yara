import "pe"
rule Blankgrabber_malware
{
	meta:
		author="5kidRo0t"
		sha256="00fe4d84e3dc59e072575baf1b0b010541d7d472978f40741b4bc33d51ad2dfb"
		sha512="d6ae8b9ae8f3d136f73394a19afa68c0962c984be6e9f4b368c5ab6ed96091cbc5c6563f5b6d154c98219e83e083bb2be6d52a3428e002f559bf182e67e79258"

	strings:
		$s1="OpenProcessToken" nocase
		$s2="281231235959Z0V1"
		$s3="sqlite3.dbapi2"
		$s4_wide="charmap.exe" wide nocase
		$s5="230425231152Z0"
		$s6="python311.dll" nocase
		$hex={ 63 00 68 00 61 00 72 00 6D 00 61 00 70 00 2E 00 65 00 78 00 65 00 }
	
	condition:
		all of them and pe.imphash() == "dcaf48c1f10b0efa0a4472200f3850ed"
}

