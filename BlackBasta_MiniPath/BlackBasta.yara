import "pe"
rule BlackBasta_Malware
{
	meta:
		author="5kidRo0t"
		sha256="723d1cf3d74fb3ce95a77ed9dff257a78c8af8e67a82963230dd073781074224"
		sha512="af88fd3a0a2728c811be524feee575d8d2d9623b7944021c83173e40dbec6b1fbe7bea64dcdd8f1dbebc7d8df76b40e5c9647e2586316ea46ceb191ebcf14d89"
	strings:
		$s1="uxtheme.dll" nocase
		$s2="minipath"
		$s3="DragAcceptFiles"
		$s4="IsDebuggerPresent"
		$s5="PCDB0"
		$s6="xro0okh"
		$hex1={ 6D 69 6E 69 70 61 74 68 2E 70 64 62 }
		$hex2={ 6D 69 6E 69 70 61 74 68 }
	condition:
		all of them and pe.imphash() == "e7481059b799ac586859298d4788584d" and 
		(pe.imports("KERNEL32.dll", "LoadLibraryExW") and pe.imports("ole32.dll", "CoTaskMemAlloc"))
}
