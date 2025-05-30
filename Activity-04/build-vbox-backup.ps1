# Define paths and VM name
$vmName = "AutomatedWin10"
$vmPath = "C:\Users\User1\VirtualBox VMs\$vmName"
$diskPath = "C:\ISO Folder\AutomatedWin10.vdi"
$isoPath = "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerIsoPath = "C:\ISO Folder\answer.iso"

# Check if the VM already exists
if (Test-Path "$vmPath\$vmName.vbox") {
    Write-Host "VM '$vmName' already exists. Skipping VM creation."
} else {
    # Create the VM if it does not exist
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createvm --name $vmName --register
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm $vmName --memory 4096 --cpus 2 --ostype "Windows10_64"
}

# Check if the disk image already exists
if (Test-Path $diskPath) {
    Write-Host "VDI disk image already exists. Skipping disk creation."
} else {
    # Create the disk if it does not exist
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" createmedium disk --filename $diskPath --size 40000
}

# Check if SATA Controller exists, if not, create it
$sataControllerExists = & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $vmName --details | Select-String -Pattern "SATA Controller"
if ($sataControllerExists) {
    Write-Host "SATA Controller already exists. Skipping SATA controller creation."
} else {
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "SATA Controller" --add sata --controller IntelAhci
}

# Attach the VDI disk to SATA Controller if not already attached
$sataDiskAttached = & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $vmName --details | Select-String -Pattern "C:\ISO Folder\AutomatedWin10.vdi"
if ($sataDiskAttached) {
    Write-Host "VDI disk already attached. Skipping disk attachment."
} else {
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $diskPath
}

# Check if IDE Controller exists, if not, create it
$ideControllerExists = & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $vmName --details | Select-String -Pattern "IDE Controller"
if ($ideControllerExists) {
    Write-Host "IDE Controller already exists. Skipping IDE controller creation."
} else {
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storagectl $vmName --name "IDE Controller" --add ide
}

# Attach ISO and Answer file if not already attached
$isoAttached = & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $vmName --details | Select-String -Pattern $isoPath
if ($isoAttached) {
    Write-Host "ISO already attached. Skipping ISO attachment."
} else {
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium $isoPath
}

$answerIsoAttached = & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo $vmName --details | Select-String -Pattern $answerIsoPath
if ($answerIsoAttached) {
    Write-Host "Answer ISO already attached. Skipping Answer ISO attachment."
} else {
    & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" storageattach $vmName --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium $answerIsoPath
}

# Start the VM
& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm $vmName
