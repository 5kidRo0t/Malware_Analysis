import "pe"
rule Abaddon_malware
{
	meta:
		author="5kidRo0t"
		sha256upx="56b035a26f214444b1ae1024b9cbca782ddd28ad46f2a4bd4f37f89fa538914e"
		sha512upx="63039195eebb88e6cec9db9afe19c4f4b862a3ed35c4022b542495ddf23f08df0fb4f6776bb6ac20656ae1052370ab9dc7bf46cf286774c886b948f8ce63638f"
		sha256="58fd6c577d6818105437146282e46b9a705208d73cd3b974381a36e86ccbe398"
		sha512="9c6dd849ba877c7018678b6ca933dd3b663e6612c5b5b2ede9203f24b4b15b110748ec0891937aab8a51c64f32327815c1082723411cb3c3643b45e324671f82"
	strings:
		$s1="5kidRo0t" nocase
		$s2="Abaddon" nocase
		$s3="runas" nocase
		$hex1={ 35 6B 69 64 52 6F 30 74 }
		$hex2={ 41 62 61 64 64 6F 6E }
		$hex3={ 72 75 6E 61 73 }
		$hex4={ 41 44 56 41 50 49 33 32 2E 64 6C 6C }
	condition:
		2 of ($s*) or
		2 of ($hex*) and pe.imphash() == "f17a72629f2df8616bc88c082cc4d643" or pe.imphash() == "8891a6891805745136afcf42fd89b5e4"
}
