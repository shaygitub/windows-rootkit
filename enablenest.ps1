Start-Process powershell -ArgumentList '-noprofile -file enablenest.ps1' -verb RunAs
$NameVm = Read-Host "Enter Virtual Machine Name:"
Set-VMProcessor -VMName NameVm -ExposeVirtualizationExtensions $true