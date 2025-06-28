import "pe"
rule Cosmu_malware
{
	meta:
		author="5kidRo0t"
		sha256="65ca7ba84aab380f567de480f63624c3443c26b0df33d8b4869132c6640bcec3"
		sha512="3e43d6743c1a59b28a0b574c138f8e5e746249c7d1dfa245ec32389797820c51b57ef9efc2d4509d67036929128f72b1d57ac384e134b646fb26a8a61c2865cf"
	strings:
		$s1="eXPressor"
		$s2="VirtualAlloc"
		$s3="LoadLibraryExA"
		$s4="IJ9DK4M.au3"
		$s5="qVdeulhkzjhdvlvzzdmvfehizjvxzmfyhiVTcrA"
		$s6="WinHttpGetIEProxyConfigForCurrentUser"
		$s7="ConvertStringSecurityDescriptorToSecurityDescriptorW"
		$s8="GetTokenInformation"
		$s9="NdrServerCall2"
		$s10="RPCRT4.dll" nocase
		$hex1={ 65 58 50 72 65 73 73 6F 72 }
		$hex2={ 56 69 72 74 75 61 6C 46 72 65 65 }
		$hex3={ 49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6E 74 }
		$hex4={ 4E 64 72 53 65 72 76 65 72 43 61 6C 6C 32 }
		$hex5={ 52 70 63 53 65 72 76 65 72 55 73 65 50 72 6F 74 73 65 71 45 70 57 }
	condition:
		6 of them and pe.imphash() == "58708828d5c31968bd59859804ecde67"
}
