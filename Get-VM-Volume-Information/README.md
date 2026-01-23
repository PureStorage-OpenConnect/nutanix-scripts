# Collect Nutanix VM vDisk and Map to Pure Storage Volumes and Snapshots

Follow the below step to collect Azure VM data disk information.

1. Configure Prism Credentials - `$prismcred = Get-Credential`
2. Configure Array Credentials - `$arraycred = Get-Credential`
3. Using Powershell, run the following command(s)

4. Execute the script. 

```powershell
./GetVMVol.ps1 -ArrayEndpoint $ArrayEndpoint -PrismEndpoint $PrismEndpoint -ArrayCredential $arraycred -PrismCredential $prismcred
./GetVMVol.ps1 -ArrayEndpoint $ArrayEndpoint1,$ArrayEndpoint2 -PrismEndpoint $PrismEndpoint -ArrayCredential $arraycred -PrismCredential $prismcred

```

`-Cluster <CLUSTERNAME>` (OPTIONAL) - To Show Specific Cluster's Details

`-VM <VMNAME>` (OPTIONAL) - To Show Specific VM's Details

`-showSnapshots $true` (OPTIONAL) - To Show VM's Snapshots

`-showMetadata $true` (OPTIONAL) - Show VM's Metadata Disks

## Examples

### Display All VM's and Disks

![screenshot1](/Get-VM-Volume-Information/screenshot1.png)

### Display Cluster's VM's Disks and Snapshots

![screenshot3](/Get-VM-Volume-Information/screenshot2.png)

### Display VM's Disks and Snapshots

![screenshot2](/Get-VM-Volume-Information/screenshot2.png)
