import "pe"
rule ValleyRAT_Malware_packer
{
	meta:
		author="5kidRo0t"
		sha256_packer="7a2a1b89a482a8ee2204a4c4b30e776d5139e14a055ff00a480ed27a965e23b6"
		sha512_packer="add3ac76bd7c1a1e064e79dc923ce3dfb47fa84c3ae703442a44cbca86036704434f3d0f58dbcff47078e706abf6e305702e9dc4cd8c03ce6949034a808059b3"
	strings:
		$s1="VirtualAlloc" nocase
		$s2="d09f2340818511d396f6aaf844c7e325" nocase
		$s3="52F260023059454187AF826A3C07AF2A" nocase
		$s4="6595b64144ccf1df"
		$s5="VirtualAllocEx" nocase
		$s6="4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38" nocase
		$hex1={ 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 }
		$hex2={ 31 30 30 36 30 38 32 33 35 39 35 39 5A 30 }
		$hex3={ 30 37 30 36 31 35 30 30 30 30 30 30 5A }
	condition:
		all of them and pe.imphash() == "9165ea3e914e03bda3346f13edbd6ccd"
}
rule ValleyRAT_Malware
{
	meta:
		sha256="7e6646706dc4384934eff1741778ec06d2c3b155d6591050fc2588fab6edb1f8"
		sha512="64a8c86a30c2d0291ff6dc4d5a81906809436e2844143bd2e1e48882a44518ae1d1940250d1e38162fcc5dfb01a922a2d9ccf564a735624bffb23c9168725750"
	strings:
		$s1="6595b64144ccf1df"
		$s2="8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"
		$s3="VirtualAllocEx"
		$s4="tracerpt"
		$s5="denglupeizhi"
		$s6="tWItHIt9It"
		$hex1={ 36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 }
		$hex2={ 34 38 66 64 35 30 61 31 35 61 39 61 }
	condition:
		all of them and pe.imphash() == "b8bf08fa843a9ec1ce10d80fbf550c26"
}
