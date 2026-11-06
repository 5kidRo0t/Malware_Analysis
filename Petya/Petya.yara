import "pe"
rule Petya_malware
{
	meta:
		author="5kidRo0t"
		sha256="26b4699a7b9eeb16e76305d843d4ab05e94d43f3201436927e13b3ebafa90739"
		sha512="69899c47d0b15f92980f79517384e83373242e045ca696c6e8f930ff6454219bf609e0d84c2f91d25dfd5ef3c28c9e099c4a3a918206e957be806a1c2e0d3e99"		
	strings:
		$s1="DeviceIoControl"
		$s2="CreateFileW"
		$s3="WriteFile"
		$s4="FlushFileBuffers"
		$s5="OpenProcess"
		$s6="ReadProcessMemory"
		$s7="CreateProcessW"
		$s8="OpenProcessToken"
		$s9="RegSetValueExW"
		$s10="VirtualProtect"
	condition:
		8 of ($s*) and pe.imphash() == "1a63922d5931d1bb8ca5188313f78eaa"
}
