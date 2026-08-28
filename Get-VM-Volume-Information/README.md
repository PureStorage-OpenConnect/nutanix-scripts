# Collect Nutanix VM vDisk and Map to Everpure Volumes and Snapshots

This script maps Nutanix VMs and their vDisks to the corresponding Everpure volumes by reading volume tags written by the Nutanix integration. It queries both Prism Central and one or more Everpure FlashArrays, then outputs a combined view showing VM name, disk bus type, vDisk ID, Pure volume name, provisioned size, and any additional tags on the volume.

**Version:** 2.1.0 | **Author:** David Stamen @ Everpure | **Last Modified:** January 2026

---

## Prerequisites

- PowerShell 7+
- Network access to Prism Central (port 9440) and Everpure FlashArray(s)
- Nutanix integration configured and writing tags to volumes in the `nutanix-integration.nutanix.com` namespace
- Credentials for both Prism Central and the Everpure FlashArray(s)

---

## Setup

Store your credentials before running the script:

```powershell
$prismcred = Get-Credential   # Prism Central username/password
$arraycred = Get-Credential   # Everpure array username/password
```

---

## Usage

**Single FlashArray:**
```powershell
./GetVMVol.ps1 -ArrayEndpoint $ArrayEndpoint -PrismEndpoint $PrismEndpoint `
               -ArrayCredential $arraycred -PrismCredential $prismcred
```

**Multiple FlashArrays:**
```powershell
./GetVMVol.ps1 -ArrayEndpoint $ArrayEndpoint1,$ArrayEndpoint2 -PrismEndpoint $PrismEndpoint `
               -ArrayCredential $arraycred -PrismCredential $prismcred
```

---

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-ArrayEndpoint` | Yes | One or more Everpure FlashArray FQDNs or IP addresses (comma-separated) |
| `-ArrayCredential` | Yes | Everpure FlashArray credential |
| `-PrismEndpoint` | Yes | Prism Central FQDN or IP address |
| `-PrismCredential` | Yes | Prism Central credential |
| `-Cluster` | No | Filter results to VMs on a specific Nutanix cluster (case-sensitive) |
| `-VM` | No | Filter results to a specific VM (case-sensitive) |
| `-ShowSnapshots` | No | Display volume snapshots for each matched volume |
| `-ShowMetadata` | No | Include metadata volumes (volumes ending in `-md`) in results |
| `-ExportPath` | No | Export results to a CSV file at the specified path |

---

## Output

The script outputs a table with the following columns:

| Column | Description |
|--------|-------------|
| `VM` | VM name (or UUID if name cannot be resolved) |
| `BusType` | Disk bus type (SCSI, SATA, IDE, etc.) |
| `Index` | Disk index on the bus |
| `BackingType` | Disk backing type (e.g., VmDisk, CdRom, UefiDisk) |
| `vDisk` | Nutanix vDisk ID used to provision the volume |
| `PureVolume` | Everpure volume name |
| `DiskSize` | Provisioned size in GB |

Any additional tags on the volume are appended as extra columns.

After all FlashArrays are processed, a summary prints the total volume count, unique VM count, and total provisioned size.

---

## Examples

### Display All VMs and Disks

```powershell
./GetVMVol.ps1 -ArrayEndpoint array.example.com -PrismEndpoint prism.example.com `
               -ArrayCredential $arraycred -PrismCredential $prismcred
```

![screenshot1](/Get-VM-Volume-Information/screenshot1.png)

---

### Display a Cluster's VMs, Disks, and Snapshots

```powershell
./GetVMVol.ps1 -ArrayEndpoint array.example.com -PrismEndpoint prism.example.com `
               -ArrayCredential $arraycred -PrismCredential $prismcred `
               -Cluster "MyCluster" -ShowSnapshots
```

![screenshot2](/Get-VM-Volume-Information/screenshot2.png)

---

### Display a Specific VM's Disks and Snapshots

```powershell
./GetVMVol.ps1 -ArrayEndpoint array.example.com -PrismEndpoint prism.example.com `
               -ArrayCredential $arraycred -PrismCredential $prismcred `
               -VM "MyVM" -ShowSnapshots
```

![screenshot3](/Get-VM-Volume-Information/screenshot3.png)

---

### Export Results to CSV

```powershell
./GetVMVol.ps1 -ArrayEndpoint array.example.com -PrismEndpoint prism.example.com `
               -ArrayCredential $arraycred -PrismCredential $prismcred `
               -ExportPath "C:\results.csv"
```

---

## Troubleshooting

- **No volumes found** — Verify the Nutanix integration is active and volumes are tagged in the `nutanix-integration.nutanix.com` namespace.
- **VM not found** — VM name matching is case-sensitive. Confirm the exact name in Prism.
- **Authentication failure** — The script tries multiple Everpure REST API versions (2.49 down to 1.16) automatically. Confirm credentials and FlashArray reachability.
- **Cluster not found** — Cluster name is case-sensitive. Confirm the exact name in Prism Central.

---

## Disclaimer

The sample script and documentation are provided AS IS and are not supported by the author or the author's employer, unless otherwise agreed in writing. You bear all risk relating to the use or performance of the sample script and documentation.
