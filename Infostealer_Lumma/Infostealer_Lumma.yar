rule Infostealer_Lumma_malware
{
	meta:
		author="5kidRo0t"
		sha256="6dfd81633a29a7f973d5bbce4139260e90743237dcd647a4accda65602bd454e"
		sha512="b2da7ee12368951e3849f36841da56a9f5210d5c7fbc7352359299f9e2bebb9981a8e4428f4f277ceff5518b31094c050a63583a1e4b281f2cb6550ea6b6cb71"
	strings:
		$s1="CreateToolhelp32Snapshot"
		$s2="RSA"
		$s3="351125235959Z0B1"
                $s4="370322235959Z0c1"
                $s5="Washington"
                $s6="e2011457-1546-43c5-a5fe-008deee3d3f0"
                $s7="AdjustTokenPrivileges"
                $s8="OpenProcessToken"
	condition:
		5 of them
}
