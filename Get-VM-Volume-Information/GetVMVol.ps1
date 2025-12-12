<#
    GetVMVol.ps1 -
    Version:        1.0.2
    Author:         David Stamen @ Pure Storage
.SYNOPSIS
    Map the Nutanix VM UUID and vDisks to Pure Storage Volumes
.DESCRIPTION
    This script will review Pure Storage Volume Tags and provide the following:
    - VM Name (or VM UUID if name not found)
    - vDisk ID that was used to provision the volume.
    - Volume Name
    - Provisioned Size
    - Any additional tags found on the volume.
.INPUTS
    - Pure Storage Array FQDN or IP Address.
    - Pure Storage Array Credential (Username and Password).
    - Prism FQDN or IP Address.
    - Prism Credential (Username and Password).
    - (optional) VM Name to filter the results. If not provided, all tagged volumes will be returned.
.OUTPUTS
    Print out the on console the disk mapping results.
.EXAMPLE
    Option 1: Return all Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred
    Option 2: Return specific VM's Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM"
    Option 3: Return specific VM's Volumes and Include Metadata Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM" -ShowMetadata $true
    Option 4: Return specific VM's Volumes and Snapshots
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM" -ShowSnapshots $true
.CHANGELOG
    10/30/25 1.0.0 Initial version
    11/7/25  1.0.1 Added ShowMetadata, ShowSnapshots parameter
    11/13/25 1.0.2 Optimized with batch API calls and in-memory lookups to speed up resolution.
#>
<#
.DISCLAIMER
The sample script and documentation are provided AS IS and are not supported by the author or the author's employer, unless otherwise agreed in writing. You bear all risk relating to the use or performance of the sample script and documentation.
The author and the author's employer disclaim all express or implied warranties (including, without limitation, any warranties of merchantability, title, infringement  or fitness for a particular purpose). In no event shall the author, the author's employer or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever arising out of the use or performance of the sample script and   documentation (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss), even if  such person has been advised of the possibility of such damages.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Enter the Array FQDN/IP Address")]
    [string]
    $ArrayEndpoint,

    [Parameter(Mandatory = $true, HelpMessage = "Enter Array Credential")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    $ArrayCredential,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the Prism FQDN/IP Address")]
    [string]
    $PrismEndpoint,

    [Parameter(Mandatory = $true, HelpMessage = "Enter Prism Credential")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    $PrismCredential,

    [Parameter(Mandatory = $false, HelpMessage = "Enter the VM Name (Optional)")]
    [string]
    $VM,

    [Parameter(Mandatory = $false, HelpMessage = "Show Metadata Volumes (Optional)")]
    [string]
    $ShowMetadata = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Show Snapshots (Optional)")]
    [string]
    $ShowSnapshots = $false
)

# --- Import the Pure Storage PowerShell Module ---
if (-not (Get-Module -Name PureStoragePowerShellSDK2 -ListAvailable)) {
    Write-Error "PureStoragePowerShellSDK2 module is not installed. Please install it from the PowerShell Gallery."
    exit
}

if (-not (Get-Module -Name Nutanix.Cli -ListAvailable)) {
    Write-Error "Nutanix.Cli module is not installed. Please install it from the PowerShell Gallery."
    exit
}

# -- Import the module(s) ---
Import-Module PureStoragePowerShellSDK2 | Out-Null
Import-Module Nutanix.Cli | Out-Null

# --- Attempt to connect to Prism ---
try {
    $Prism = Connect-PrismCentral -Server $PrismEndpoint -Credential $PrismCredential -AcceptInvalidSSLCerts -ForcedConnection
}
catch {
    Write-Error "Failed to connect to Prism at $PrismEndpoint. $_"
    exit
}

# --- Attempt to connect to the array ---
try {
    $array = Connect-Pfa2Array -Credential $ArrayCredential -Endpoint $ArrayEndpoint -IgnoreCertificateError
}
catch {
    Write-Error "Failed to connect to array at $ArrayEndpoint. $_"
    Disconnect-PrismCentral -Servers *
    exit
}

# --- Retrieve tagged volumes and determine VM UUID(s) to process ---
try {
    # Get all Nutanix tags from the array (1 API Call)
    $TaggedVolumes = Get-Pfa2VolumeTag -Namespaces 'nutanix-integration.nutanix.com' -Array $array -ErrorAction Stop

    # --- Filter for owner_id tags only (in-memory) ---
    $OwnerTags = $TaggedVolumes | Where-Object { $_.Key -eq 'owner_id' -and $_.Value }

    $VMLookup = @{}
    $TargetOwnerTags = @()

    if (-not [string]::IsNullOrWhiteSpace($VM)) {
        # --- SCENARIO 1: Specific VM Name provided ---
        $vm1 = Get-VM -Name $VM -ErrorAction SilentlyContinue
        if (-not $vm1) {
            Write-Error "VM with name '$VM' not found in Prism."
            Disconnect-PrismCentral -Servers *
            Disconnect-Pfa2Array -Array $array
            exit
        }
        # Pre-populate the lookup table with our single VM
        $VMLookup[$vm1.UUID] = $vm1.VMName
        # Find only the tags matching this VM's UUID
        $TargetOwnerTags = $OwnerTags | Where-Object { $_.Value -eq $vm1.UUID }
    }
    else {
        # Get all unique UUIDs from the tags
        $VM_UUIDs = $OwnerTags | Select-Object -ExpandProperty Value -Unique

        if (-not $VM_UUIDs -or $VM_UUIDs.Count -eq 0) {
            Write-Error "No VM UUIDs found in tags."
            Disconnect-Pfa2Array -Array $array
            Disconnect-PrismCentral -Servers *
            exit
        }
        $AllPrismVMs = Get-VM

        # Build the hashtable for fast lookups
        foreach ($v in $AllPrismVMs) {
            if (-not [string]::IsNullOrWhiteSpace($v.VMName)) {
                $VMLookup[$v.UUID] = $v.VMName
            }
        }

        # Add fallbacks for any tagged UUIDs not found in Prism
        foreach ($uuid in $VM_UUIDs) {
            if (-not $VMLookup.ContainsKey($uuid)) {
                $VMLookup[$uuid] = $uuid # Use UUID as the name
            }
        }
        # We are processing all tags we found
        $TargetOwnerTags = $OwnerTags
    }

    if (-not $TargetOwnerTags) {
        Write-Host "No volumes found with matching Nutanix tags."
        Disconnect-Pfa2Array -Array $array
        Disconnect-PrismCentral -Servers *
        exit
    }

    # --- Build list of unique volumes to process from our target tags ---
    $UniqueVolumeNames = $TargetOwnerTags |
        Select-Object -ExpandProperty Resource |
        Select-Object -ExpandProperty Name -Unique

    $AllVolumes = Get-PFA2Volume -Array $array -ErrorAction SilentlyContinue

    # Create a hashtable for instant lookups: $VolLookup['vol-name'] -> $volObject
    $VolLookup = $AllVolumes | Group-Object -AsHashtable -Property Name

    $results = foreach ($volName in $UniqueVolumeNames) {

        # --- OPTIMIZATION: Use fast in-memory lookup instead of API call ---
        if (-not $VolLookup.ContainsKey($volName)) {
            Write-Warning "Volume '$volName' found in tags but not on the array. Skipping."
            continue
        }
        # $VolLookup[$volName] returns an array (from Group-Object), so we take the first item [0]
        $vol = $VolLookup[$volName][0]

        # -- Skip metadata volumes unless user requested to show them ---
        # Normalize $ShowMetadata to a boolean (accepts boolean or common string forms)
        $showMeta = $false
        if ($ShowMetadata -is [string]) {
            $showMeta = ($ShowMetadata.Trim().ToLower() -in @('true','1','yes'))
        }
        else {
            try { $showMeta = [bool]$ShowMetadata } catch { $showMeta = $false }
        }

        if (-not $showMeta -and $vol.Name -and $vol.Name.EndsWith('-md')) { continue }

        $podName = if ($null -ne $vol.Pod) { $vol.Pod.name } else { $null }

        # -- OPTIMIZATION 2: Filter existing tag data instead of new API call ---
        $tags = $TaggedVolumes | Where-Object { $_.Resource.Name -eq $volName }

        $props = [ordered]@{
            PureVolume    = $vol.Name
            DiskSize = if ($null -ne $vol.Space.UsedProvisioned) { [math]::Round($vol.Space.UsedProvisioned / 1GB, 2) } else { $null }
        }

        if ($tags) {
            foreach ($t in $tags) {
                # -- Skip volume_name tag as it's redundant ---
                if ($t.Key -eq 'volume_name') { continue }

                # -- Map specific keys to desired property names ---
                switch ($t.Key) {
                    'owner_id'       {
                        # Do NOT add VM_ID to output. Instead, map owner_id to VM using lookup.
                        if ($t.Value) {
                            if ($VMLookup.ContainsKey($t.Value)) {
                                $props['VM'] = $VMLookup[$t.Value]
                            }
                            else {
                                $props['VM'] = $t.Value
                            }
                        }
                        continue
                    }
                    'owner_disk_id'  { $propName = 'vDisk' ; break }
                    default          { $propName = ($t.Key -replace '\s','_') }
                }

                # -- Add tag to properties if mapped to a property name ---
                if ($propName) {
                    $props[$propName] = $t.Value
                }
            }
        }

        [PSCustomObject]$props
    }

    # --- Final Formatting and Output ---
    $results = @($results)

    $tagKeys = $results |
        ForEach-Object { $_.PSObject.Properties.Name } |
        Select-Object -Unique |
        Where-Object { $_ -notin 'PureVolume','DiskSize','volume_name' }

    # Ensure VM appears to the left in the output
    $orderedTagKeys = @()
    if ($tagKeys -contains 'VM') {
        $orderedTagKeys += 'VM'
        $tagKeys = $tagKeys | Where-Object { $_ -ne 'VM' }
    }
    # append remaining tag keys (including VDisk_ID or others)
    $orderedTagKeys += ($tagKeys | Sort-Object)

    $columns = $orderedTagKeys + @('PureVolume','DiskSize')

    # --- Format, Sort and Display the Results ---
    $results | Sort-Object VM, PureVolume | Format-Table -Property $columns -AutoSize

    # Snapshots (run only if requested)
    # Normalize $ShowSnapshots to a boolean
    $showSnaps = $false
    if ($ShowSnapshots -is [string]) {
        $showSnaps = ($ShowSnapshots.Trim().ToLower() -in @('true','1','yes'))
    }
    else {
        try { $showSnaps = [bool]$ShowSnapshots } catch { $showSnaps = $false }
    }

    if ($showSnaps) {
        try {
            # Determine which volumes to get snapshots for
            $vmVolumes = @()
            if (-not [string]::IsNullOrWhiteSpace($VM)) {
                # Specific VM was requested, so only get snaps for that VM's volumes
                $vmVolumes = $results | Where-Object { $_.VM -eq $VM } | Select-Object -ExpandProperty PureVolume -Unique
            } else {
                # All VMs, so get snaps for all volumes found in the results
                $vmVolumes = $results | Select-Object -ExpandProperty PureVolume -Unique
            }

            $AllSnaps = Get-Pfa2VolumeSnapshot -Array $array -ErrorAction SilentlyContinue

            $SnapLookup = @{}
            if ($AllSnaps) {
                # Group snapshots by their source volume name (if it exists)
                $SnapLookup = $AllSnaps | Where-Object { $_.Source.Name } | Group-Object -AsHashtable -Property { $_.Source.Name }
            } else {
                Write-Host "No snapshots found on array."
            }

            foreach ($vol in $vmVolumes) {
                Write-Host ""
                Write-Host ("Snapshots for Volume: {0}" -f $vol) -ForegroundColor Cyan

                $volSnaps = @()

                # 1. Check the primary lookup (fastest, most reliable)
                if ($SnapLookup.ContainsKey($vol)) {
                    $volSnaps += $SnapLookup[$vol]
                }

                # 2. Fallback: name prefix match (for snaps without a source.name)
                $volSnaps += $AllSnaps | Where-Object { $_.Name -like "$vol.*" -and (-not $_.Source.Name) }

                if (-not $volSnaps) {
                    Write-Host "  (no snapshots found)"
                    continue
                }

                $volSnaps | Select-Object -Unique | # Add Unique just in case of overlap
                    Select-Object @{
                            Name  = 'VolumeName';   Expression = { $vol }
                        }, @{
                            Name  = 'SnapshotName'; Expression = { $_.Name }
                        }, @{
                            Name  = 'Created';      Expression = {
                                if ($_.Created)         { $_.Created }
                                elseif ($_.TimeCreated) { $_.TimeCreated }
                                elseif ($_.creation_time){ $_.creation_time }
                                elseif ($_.Time)        { $_.Time }
                                else { $null }
                            }
                        } |
                    Sort-Object Created | # Added sorting for readability
                    Format-Table -AutoSize
            }
        }
        catch {
            Write-Warning "Failed to retrieve snapshots for one or more volumes: $($_.Exception.Message)"
        }
    }
    # --- Disconnect from Array ---
    Disconnect-Pfa2Array -Array $array

    # --- Disconnect from Prism ---
    Disconnect-PrismCentral -Servers *
}
catch {
    Write-Error "An error occurred during data retrieval: $_.Exception.Message"
}