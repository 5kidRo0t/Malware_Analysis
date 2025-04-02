rule XClient_malware
{
	meta:
                author="5kidRo0t" 
		sha256="8c51d3e674102aecb72beac0bbb3e337295b1a1e078d4bedd6ff3389623fa318"
		sha512="fa77a2ec6a838a45fe0d53298970304d509d7d98f35ab2ba693ea26d46f6d19fc2b5d628bdd72db67129212bb9b6927ae53b0410a1ea0dac5896e20235e75747"

	strings:
		$XClient="p4CUqgqKExOhLYuePGyCkC9OeniRq9y79vWRaiY2UBOSrcuzTX1e3L6ye67cJjxUKpRtmqm0hmskvg1Dxfyvkt6RpIDNUWu"
		$XClient2="XClient.exe"
		$XClient3="O1erhWNpHLu5HaD7YdCbceMHEHKdFL1VNMq0EXgFEqR119AlPmyEc0GZJWOiB3d1mkuMzwFhueJYD"
		$XClient4="System.Security.Cryptography"
		$XClient5="ZxXe7fEdZ0A1hJmBxbAjqvFODOlPRAQtrmWlKlzdK9on8doMXrnuevAoBCUIOV2Oe76veVCdMupB2vvi3qSzEMoKWDkoTby"
		$XClient6="KN8hOOcuY1vC9qq9qXOdPYyU6tmBCi1HehtlAyLDkE1iQOgUl7YCxUQ2PuAfqLcpTZOK0ovxp47afujLDCBfmZFJHxe2ycw"
	condition:
		3 of them
}
