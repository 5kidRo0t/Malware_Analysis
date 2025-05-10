import "pe"

rule Conti_malware
{
	meta:
		author="5kidRo0t"
		sha256="b800bf6f11170ff68cd552484fa144571069513adad2d75ac7462b126b5f0816"
		sha512="26b8573208b5884c9bfec9fdac3170f0b56a3ce730f92ee5b21aa20aab5eaaca30434cb371127c66b29e740032605afb02f2ea35a1987dba469e232fa924edce"
	strings:
		$s1="3x03p43P83H"
		$s2="tijIh"
		$s3="QQSVj8j@"
		$s4="IsDebuggerPresent"
		$s5="DecodePointer"
		$s6="RSA"
		$s7="0g3I6i6s6w"
		$s8="404P4p4"
		$s9="505P5p5"
		$s10="606L6P6"
	condition:
		pe.imphash() == "5036747c069c42a5e12c38d94db67fad" and
		7 of ($s*)
}
