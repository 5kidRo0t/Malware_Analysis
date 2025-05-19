import "pe"

rule Monoxide_malware
{
	meta:
		author="5kidRo0t"
		sha256="bd764fe2f9734d5ac56933ce68df0a175bfa98dc0266ae3cd3a5c963267ea77e"
		sha512="c6fe33ff3825e9018abea99ea49dc5221f2abd96bd1099def898425b82c05f9b9ca1aacaba0b7ffb7d09a7d097eae9937abdc13bbf3e7643e24e37edc7841c48"
	strings:
		$s1="Monoxide" nocase
		$s2="EnterCriticalSection" nocase
		$s3="DeleteCriticalSection" nocase
		$s4="IsDebuggerPresent" nocase
		$s5="AdjustTokenPrivileges" nocase
		$s6="DeleteDC" nocase
		$s7="MoveWindow" nocase
		$s8="SetWindowsHook" nocase
		$s9="NtShutdownSystem" nocase
		$s10="ldexp" nocase
		$hex1={ 44 65 6C 65 74 65 44 43 }
		$hex2={ 44 65 63 6F 64 65 50 6F 69 6E 74 65 72 }
		$hex3={ 4D 00 41 00 49 00 4E 00 49 00 43 00 4F 00 4E }
		$hex4={ 4D 6F 6E 6F 78 69 64 65 }
		$hex5={ 52 74 6C 53 65 74 50 72 6F 63 65 73 73 49 73 43 72 69 74 69 63 61 6C }
	condition:
		7 of ($s*) and 2 of ($hex*) and pe.imphash() == "9ac10d3eb45e2af35269569591fda84b"
}
