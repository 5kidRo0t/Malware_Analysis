rule korplug_fragtor_malware
{
	meta:
		author="5kidRo0t"
		sha256="f2b04c3c764c85c0bedb434b55304d26d067662cd47e620e219657a0007c9fe0"
		sha512="199dd1413cf4093de1dba256127463c4aee591d3136394f0cfe7aee85b2bf104a358234bef0f5aca9f97ade8c0f58a26f1148c9f389e0f3f4113edf7a7121b82"
	strings:
		$s1="281022120000Z0r1"
		$s2="Zainuddin Nafarin"
		$s3="InitializeCriticalSectionAndSpinCount"
		$s4="IsDebuggerPresent"
		$s5="SmadHook32c.dll"
		$s6="vector deleting destructor"
		$s7="local vftable"
	condition:
		all of them
}
