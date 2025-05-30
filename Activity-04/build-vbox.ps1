#### **For VirtualBox:** (`build-vbox.ps1`)

#Create a script to:

#- Create and register a new VM.
#- Set memory, CPU, and storage parameters.
#- Attach both your Windows ISO and `answer.iso`.
#- Start the VM automatically.

#Example commands to use:

'''```powershell & """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" createvm --name "AutomatedWin10" --register
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" modifyvm "AutomatedWin10" --memory 4096 --cpus 2 --ostype "Windows10_64"
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" createmedium disk --filename "C:\ISO Folder\AutomatedWin10.vdi" --size 40000
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" storagectl "AutomatedWin10" --name "SATA Controller" --add sata --controller IntelAhci
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" storageattach "AutomatedWin10" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "C:\ISO Folder\AutomatedWin10.vdi"
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" storagectl "AutomatedWin10" --name "IDE Controller" --add ide
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISO Folder\answer.iso"
& """C:\Program Files\Oracle\VirtualBox\VBoxManage.exe""" startvm "AutomatedWin10"
'''

'''& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" createvm --name "AutomatedWin10" --register
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" modifyvm "AutomatedWin10" --memory 4096 --cpus 2 --ostype "Windows10_64"
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" createmedium disk --filename "C:\ISO Folder\AutomatedWin10.vdi" --size 40000
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" storagectl "AutomatedWin10" --name "SATA Controller" --add sata --controller IntelAhci
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" storageattach "AutomatedWin10" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "C:\ISO Folder\AutomatedWin10.vdi"
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" storagectl "AutomatedWin10" --name "IDE Controller" --add ide
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISO Folder\answer.iso"
& ""C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"" startvm "AutomatedWin10"
'''

& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name "AutomatedWin10" --register
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "AutomatedWin10" --memory 4096 --cpus 2 --ostype "Windows10_64"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename "C:\ISO Folder\AutomatedWin10.vdi" --size 40000
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl "AutomatedWin10" --name "SATA Controller" --add sata --controller IntelAhci
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "AutomatedWin10" --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium "C:\ISO Folder\AutomatedWin10.vdi"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl "AutomatedWin10" --name "IDE Controller" --add ide
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach "AutomatedWin10" --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium "C:\ISO Folder\answer.iso"
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "AutomatedWin10"
