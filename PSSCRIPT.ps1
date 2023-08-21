# Check if the script is already running with administrator privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch the script with administrator privileges
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`"" -Verb RunAs
    Exit
}

# Actual script to load and install driver:
# DO BCDEDIT \DBGSETTINGS CONFIG LIKE SUPPOSED TO
# RUN THE MSI TEST (MIGHT NOT BE NEEDED - TEST!!!)
# LOAD DRIVER USING KDMAPPER/OTHER
#USE DEVCON INSTALL IF NEEDED
# restart if needed
#for now:
#CD TO DRIVER DIRECTORY
#USE DEVCON INSTALL
#RESTART