rule uniflorous_malware
{
	meta:
		author="5kidRo0t"
		sha256="135ad3fd55dc6e7cc31b1742f095a14a2e56b3abbe0c4bbcde100ccd9f6e6d3d"
		sha512="e3dcd26f3b1ab2fdb36bcd85db79874b1718cd76a9d2727bb26f0b8a6910f6cfa965de3340dfe7bb5e959641b5d866b69bfa662a29236dc1e6fe26a72607cdd1"
	strings:
		$st1="ringen"
		$st2="Asshole@Bocks"
		$st3="Destillatorerne"
		$st4="Bernterode"
		$st5="Untereichsfeld"
		$st6="250930075028Z0"
		$st7="AdjustTokenPrivileges"
		$st8="LookupPrivilegeValueA"
		$st9="OpenProcessToken"
	condition:
		all of them
}
