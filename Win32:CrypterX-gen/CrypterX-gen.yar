rule CrypterX_gen_malware
{
	meta:
	        author="5kidRo0t"
		sha256="8e209e4f7f10ca6def27eabf31ecc0dbb809643feaecb8e52c2f194daa0511aa"
		sha512="59a5891ba76ec3107026891508ad73cfa8b1be19ffe07a50f792d2ecda2d74b3b759a72edc2b7c77605653b53207344d830209271ea64e15df1003e21f7c09a0"
	strings:
		$st1="CreateThread"
		$st3="DOGE BIG BALLS RANSOMWARE"
		$st4="RANSOMNOTE"
		$st5="Sandbox detected!"
	condition:
		3 of them
}
