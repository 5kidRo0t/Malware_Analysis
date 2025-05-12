import "pe"

rule Trickbot_malware
{
	meta:
		author="5kidRo0t"
		sha256="1a6bef8525a2b7eded1ea8c92e65cea20a08dc2fff175e37886c7f46846bcb68"
		sha512="bbc7e32825b292dcd40d8385dff809df0ddf4d27b23f456b918068fb07d5940d741e7b294fb3350bab80dcf6142107c8a2be46a9ada1b7e45b1fca6051921d70"
	strings:
		$s1="eiV1LuE0R"
		$s2="Kirschner"
		$s3="Jens"
		$s4="NLIROMROKGEA"
	condition:
		pe.imphash() == "297ed3de0a49d4831344ce5a84729097" and 3 of ($s*)
}
