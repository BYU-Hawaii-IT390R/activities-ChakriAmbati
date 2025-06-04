# build-vbox.ps1 – Automate VM creation and Windows installation using VirtualBox

# Paths (update if needed)
$vmName     = "AutomatedWin10"
$vmDisk     = "C:\ISO Folder\AutomatedWin10.vdi"
$windowsISO = "C:\ISO Folder\en-us_windows_10_consumer_editions_version_22h2_x64_dvd_8da72ab3.iso"
$answerISO  = "C:\ISO Folder\answer.iso"
$VBoxManage = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"

# Create the VM
& "$VBoxManage" createvm --name $vmName --register

# Set basic config (memory, CPUs, OS type)
& "$VBoxManage" modifyvm $vmName --memory 4096 --cpus 2 --ostype "Windows10_64"

# Create virtual hard disk
& "$VBoxManage" createmedium disk --filename $vmDisk --size 40000

# Add SATA controller and attach VDI
& "$VBoxManage" storagectl $vmName --name "SATA Controller" --add sata --controller IntelAhci
& "$VBoxManage" storageattach $vmName --storagectl "SATA Controller" --port 0 --device 0 --type hdd --medium $vmDisk

# Add IDE controller and attach ISOs
& "$VBoxManage" storagectl $vmName --name "IDE Controller" --add ide
& "$VBoxManage" storageattach $vmName --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium $windowsISO
& "$VBoxManage" storageattach $vmName --storagectl "IDE Controller" --port 1 --device 0 --type dvddrive --medium $answerISO

# Set networking to NAT
& "$VBoxManage" modifyvm $vmName --nic1 nat

# Start the VM
& "$VBoxManage" startvm $vmName
