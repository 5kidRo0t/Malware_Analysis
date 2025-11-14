import "pe"
rule WinBar_Lumma_Malware
{
	meta:
		author="5kidRo0t"
		sha256="e8267cff9aa55eb925a57a5753f67c9eb9d3ec34e9abbd8ba2a5ac75ddf6ad09"
		sha512="f15ee4a46891ea3cc440bb5cde9c08b6d0792c9c33fd146c6fbd5c02cd2a9d5f9b9acf08d23f4aeeebc55684859ab53e0843be7a6138653b5b4aaa6ccf54050e"
	strings:
		$s1="The WinBar Team" ascii wide
		$s2="www.winbar.nl" ascii wide
		$s3="progapi" ascii wide
		$s4="WinBar" ascii wide
		$s5="Thunder2" ascii wide
		$s6="drZymo" ascii wide
		$s7="johnwoo" ascii wide
		$base64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" ascii
	condition:
		uint16(0) == 0x5A4D and ((5 of ($s*)) and $base64) and (pe.imphash()=="02b04677321d823fbe529a06e47a701e")
}
