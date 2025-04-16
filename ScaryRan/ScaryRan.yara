rule ScaryRan_malware
{
	meta:
		author="5kidRo0t"
		sha256="c3a005875fd0fd711617b06f95a94c0253360622e1f7c87f9ed1d27c3b242fa2"
		sha512="a739b0e2374d24f12755d464216f672001df901c1ed7fc7bd2d88394d813426d5164360f8715524a5a73817196036eb46c93c4d76ee169828f6ff442f36ae39e"
	strings:
		$s1="6595b64144ccf1df"
		$s2="SHGetKnownFolderPath"
		$s3="Mark Adler"
		$s4="tolower"
		$s5="CreateAcceleratorTableW"
		$s6="XpHoHx"
	condition:
		all of them
}
