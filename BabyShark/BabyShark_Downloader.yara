import "pe"
rule BabyShark_Downloader_Malware
{
	meta:
		author="5kidRo0t"
		sha256="6f76a8e16908ba2d576cf0e8cdb70114dcb70e0f7223be10aab3a728dc65c41c"
		sha512="b2eab3f851b7032c04b8a2874910fb5b10cd52dc92e71143cbf18a691dc7b22f2928a8f69468a27cdd33ae7e171795d722326dbd9c79cbc19af9825a6e18e27f"
	strings:
		$s1="K0I0"
		$s2="egiskorea"
		$s3="231209235959Z0L1" nocase
		$s4="360716235959Z0" nocase
		$s5="ksi/1.hta"
		$s6="mshta.exe"
		$s7="R6019" nocase
		$s8="ppxxxx"
		$hex1={ 52 36 30 30 32 }
		$hex2={ 6D 73 68 74 61 2E 65 78 65 20 68 74 74 70 3A 2F 2F 6B 73 69 2F 31 2E 68 74 61 }
		$hex3={ 6B 73 69 2F 31 2E 68 74 61 }
		$hex4={ 32 33 31 32 30 39 32 33 35 39 35 39 5A 30 4C 31 }
		$hex5={ 65 67 69 73 6B 6F 72 65 61 } 
	condition:
		pe.imphash() == "57b6d88707d9cd1c87169076c24f962e" and 
		6 of ($s*) and 
		all of ($hex*) and
		(pe.imports("KERNEL32.dll", "VirtualAlloc") and pe.imports("KERNEL32.dll", "LoadLibraryA"))
}
