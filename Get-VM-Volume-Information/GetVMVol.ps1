<#
    GetVMVol.ps1 -
    Version:        2.0.0
    Author:         David Stamen @ Pure Storage
.SYNOPSIS
    Map the Nutanix VM UUID and vDisks to Pure Storage Volumes
.DESCRIPTION
    This script will review Pure Storage Volume Tags and provide the following:
    - VM Name (or VM UUID if name not found)
    - Disk Type (Backing, Type and Index)
    - vDisk ID that was used to provision the volume.
    - Volume Name
    - Provisioned Size
    - Any additional tags found on the volume.
.INPUTS
    - Pure Storage Array(s) FQDN or IP Address.
    - Pure Storage Array Credential (Username and Password).
    - Prism Central FQDN or IP Address.
    - Prism CentralCredential (Username and Password).
    - (optional) VM Name to filter the results. If not provided, all tagged volumes will be returned.
    - (optional) Cluster Name to filter the results. If not provided, all tagged volumes will be returned.

.OUTPUTS
    Print out the on console the disk mapping results.
.EXAMPLE
    Return all Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray1,$FQDNorIPofArray2 -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred
    Return specific VM's Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM"
    Return specific Cluster's Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -Cluster "Cluster"
    Return specific VM's Volumes and Include Metadata Volumes
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM" -ShowMetadata $true
    Return specific VM's Volumes and Snapshots
        ./GetVMVol.ps1 -ArrayEndpoint $FQDNorIPofArray -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM" -ShowSnapshots $true
.CHANGELOG
    10/30/25 1.0.0 Initial version
    11/7/25  1.0.1 Added ShowMetadata, ShowSnapshots parameter
    11/13/25 1.0.2 Optimized with batch API calls and in-memory lookups to speed up resolution.
    1/22/26  2.0.0 Use Nutanix API instead of PowerShell. Implemented Additional Volume Information and Multiple Array Support
#>
<#
.DISCLAIMER
The sample script and documentation are provided AS IS and are not supported by the author or the author's employer, unless otherwise agreed in writing. You bear all risk relating to the use or performance of the sample script and documentation.
The author and the author's employer disclaim all express or implied warranties (including, without limitation, any warranties of merchantability, title, infringement  or fitness for a particular purpose). In no event shall the author, the author's employer or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever arising out of the use or performance of the sample script and   documentation (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss), even if  such person has been advised of the possibility of such damages.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, HelpMessage = "Enter one or more Array FQDN/IP Addresses (comma separated)")]
    [string[]]
    $ArrayEndpoint,

    [Parameter(Mandatory = $true, HelpMessage = "Enter Array Credential")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    $ArrayCredential,

    [Parameter(Mandatory = $true, HelpMessage = "Enter the Prism FQDN/IP Address")]
    [string]
    $PrismEndpoint,

    [Parameter(Mandatory = $true, HelpMessage = "Enter Prism Central Credential")]
    [ValidateNotNullOrEmpty()]
    [PSCredential]
    $PrismCredential,

    [Parameter(Mandatory = $false, HelpMessage = "Filter by Nutanix Cluster Name (Optional)")]
    [string]
    $Cluster,

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
function Get-NutanixClusterExtId {
    param (
        [string]$PrismEndpoint,
        [PSCredential]$PrismCredential,
        [string]$Cluster
    )

    $baseUrl = "https://${PrismEndpoint}:9440/api/clustermgmt/v4.2/config/clusters"
    $user = $PrismCredential.UserName
    $pass = $PrismCredential.GetNetworkCredential().Password
    $pair = "${user}:${pass}"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $headers = @{ 'Authorization' = "Basic $base64" }

    $filter = "?`$filter=name eq '$Cluster'&`$limit=1"
    $uri = "${baseUrl}${filter}"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop

        if ($response.data -and $response.data.Count -gt 0) {
            $c = $response.data[0]
            if ($c.extId) { return $c.extId }
            if ($c.ExtId) { return $c.ExtId }
            throw "Cluster found but ExtId property is missing."
        }
        else {
            throw "Cluster '$Cluster' not found."
        }
    }
    catch {
        $errMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errBody = $reader.ReadToEnd()
                Write-Warning "Cluster API Error: $errBody"
            } catch {}
        }
        throw "Failed to retrieve Cluster ID for '$Cluster': $errMessage"
    }
}
function Get-NutanixVMs {
    param (
        [string]$PrismEndpoint,
        [PSCredential]$PrismCredential,
        [string]$FilterVMName,
        [string]$ClusterFilterId
    )

    $baseUrl = "https://${PrismEndpoint}:9440/api/vmm/v4.2/ahv/config/vms"

    $user = $PrismCredential.UserName
    $pass = $PrismCredential.GetNetworkCredential().Password
    $pair = "${user}:${pass}"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)
    $headers = @{ 'Authorization' = "Basic $base64" }

    function Fetch-VMs {
        param ([string]$ODataFilter)
        $collected = @()
        $page = 0
        $limit = 50 
        $totalFetched = 0
        $grandTotal = -1
        $sortParam = "&`$orderby=name" 

        do {
            $uri = "${baseUrl}?`$page=${page}&`$limit=${limit}${ODataFilter}${sortParam}"
            $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop
            $batchCount = 0

            if ($response.data) {
                $batch = @($response.data)
                $batchCount = $batch.Count

                if ($response.metadata -and $response.metadata.totalAvailableResults) {
                    $grandTotal = $response.metadata.totalAvailableResults
                }

                foreach ($vm in $batch) {
                    if (-not [string]::IsNullOrWhiteSpace($ClusterFilterId)) {
                        $vmClusterId = $null
                        if ($vm.cluster.extId) { $vmClusterId = $vm.cluster.extId }
                        elseif ($vm.cluster.ExtId) { $vmClusterId = $vm.cluster.ExtId }
                        elseif ($vm.Cluster.extId) { $vmClusterId = $vm.Cluster.extId }
                        elseif ($vm.Cluster.ExtId) { $vmClusterId = $vm.Cluster.ExtId }
                        elseif ($vm.clusterReference.extId) { $vmClusterId = $vm.clusterReference.extId }
                        elseif ($vm.clusterReference.ExtId) { $vmClusterId = $vm.clusterReference.ExtId }
                        elseif ($vm.ClusterReference.extId) { $vmClusterId = $vm.ClusterReference.extId }
                        elseif ($vm.ClusterReference.ExtId) { $vmClusterId = $vm.ClusterReference.ExtId }

                        if ($vmClusterId -ne $ClusterFilterId) { continue }
                    }
                    $collected += $vm
                }
            }

            $totalFetched += $batchCount

            if ($grandTotal -ge 0 -and $totalFetched -ge $grandTotal) { break }
            if ($batchCount -eq 0) { break }

            $page++
        } while ($true)

        return $collected
    }

    if (-not [string]::IsNullOrWhiteSpace($FilterVMName)) {
        Write-Verbose "Attempting Exact Match for VM '$FilterVMName'..."
        $serverFilter = "&`$filter=name eq '$FilterVMName'"

        try {
            $results = Fetch-VMs -ODataFilter $serverFilter
            if ($results.Count -gt 0) { return $results }
            Write-Verbose "Exact match not found. Switching to Full Scan..."
        }
        catch { Write-Warning "Server filter failed. Retrying with Full Scan." }
    }

    $allVMs = Fetch-VMs -ODataFilter ""

    if (-not [string]::IsNullOrWhiteSpace($FilterVMName)) {
        return $allVMs | Where-Object { $_.name -eq $FilterVMName }
    }

    return $allVMs
}

if (-not (Get-Module -Name PureStoragePowerShellSDK2 -ListAvailable)) {
    Write-Error "PureStoragePowerShellSDK2 module is not installed."
    exit
}

Import-Module PureStoragePowerShellSDK2 | Out-Null

if ([System.Net.ServicePointManager]::ServerCertificateValidationCallback -eq $null) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

if ($ArrayEndpoint.Count -eq 1 -and $ArrayEndpoint[0] -match ',') {
    $ArrayEndpoint = $ArrayEndpoint[0] -split ',' | ForEach-Object { $_.Trim() }
}
$ArrayEndpoint = $ArrayEndpoint | Select-Object -Unique

try {
    $targetClusterId = $null
    if (-not [string]::IsNullOrWhiteSpace($Cluster)) {
        Write-Host "Resolving Cluster ID for '$Cluster'..." -ForegroundColor Cyan
        try {
            $targetClusterId = Get-NutanixClusterExtId -PrismEndpoint $PrismEndpoint -PrismCredential $PrismCredential -Cluster $Cluster
        }
        catch {
            Write-Error $_
            exit
        }
    }

    $VMLookup = @{}
    Write-Host "Retrieving VM information from Nutanix Prism $PrismEndpoint..." -ForegroundColor Cyan

    $prismVMs = Get-NutanixVMs -PrismEndpoint $PrismEndpoint -PrismCredential $PrismCredential -FilterVMName $VM -ClusterFilterId $targetClusterId

    if (-not $prismVMs) {
        if ($VM) { Write-Error "VM '$VM' not found." }
        else { Write-Warning "No VMs returned from Prism (check cluster/permissions)." }
        if ($VM) { exit }
    }

    if ($prismVMs) {
        foreach ($v in $prismVMs) { 
            if ($v.extId) { $VMLookup[$v.extId] = $v }
            if ($v.biosUuid) { $VMLookup[$v.biosUuid] = $v }
            elseif ($v.BiosUuid) { $VMLookup[$v.BiosUuid] = $v }
        }
    }
}
catch {
    Write-Error "Error fetching Nutanix Data: $_"
    exit
}

foreach ($currentArrayEndpoint in $ArrayEndpoint) {
    Write-Host "`n--- Processing Array: $currentArrayEndpoint ---" -ForegroundColor Cyan

    $array = $null
    $results = $null
    $matchFoundOnThisArray = $false

    try {
        $array = Connect-Pfa2Array -Credential $ArrayCredential -Endpoint $currentArrayEndpoint -IgnoreCertificateError -ErrorAction Stop
    }
    catch {
        Write-Warning "FAILED to connect to array [$currentArrayEndpoint]"
        Write-Warning "Reason: $($_.Exception.Message)"
        continue
    }

    try {
        $OwnerTags = @()
        $namespace = 'nutanix-integration.nutanix.com'

        if (-not [string]::IsNullOrWhiteSpace($VM) -and $VMLookup.Count -gt 0) {
            Write-Host "  Performing targeted tag search for VM '$VM'..." -ForegroundColor Green
            foreach ($uuid in $VMLookup.Keys) {
                $filterStr = "key='owner_id' and value='$uuid'"
                $found = Get-Pfa2VolumeTag -Namespaces $namespace -Array $array -Filter $filterStr -ErrorAction SilentlyContinue
                if ($found) { $OwnerTags += $found }
            }
        }
        else {
            $bulkFilter = "key='owner_id'"
            $OwnerTags = Get-Pfa2VolumeTag -Namespaces $namespace -Array $array -Filter $bulkFilter -ErrorAction Stop
        }

        if (-not $OwnerTags) {
            Write-Host "  No matching volumes found on $currentArrayEndpoint."
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($VM)) {
            $foundUUIDs = $VMLookup.Keys
            $OwnerTags = $OwnerTags | Where-Object { $_.Value -in $foundUUIDs }
        }

        elseif (-not [string]::IsNullOrWhiteSpace($Cluster)) {
            $foundUUIDs = $VMLookup.Keys
            $OwnerTags = $OwnerTags | Where-Object { $_.Value -in $foundUUIDs }
        }

        if (-not $OwnerTags) {
            Write-Host "  No matches found on this array (after filtering)."
            continue
        }

        $UniqueVolumeNames = $OwnerTags | Select-Object -ExpandProperty Resource | Select-Object -ExpandProperty Name -Unique

        Write-Host "  Found $($UniqueVolumeNames.Count) volume matches. This may take awhile..." -ForegroundColor Gray

        $FullTagSet = @()

        if ($UniqueVolumeNames.Count -gt 100) {
            $FullTagSet = Get-Pfa2VolumeTag -Namespaces $namespace -Array $array
        }
        else {
            foreach ($vName in $UniqueVolumeNames) {
                $vTags = Get-Pfa2VolumeTag -Namespaces $namespace -Array $array -ResourceNames $vName
                $FullTagSet += $vTags
            }
        }

        $AllVolumes = Get-PFA2Volume -Array $array -ErrorAction SilentlyContinue
        $VolLookup = $AllVolumes | Group-Object -AsHashtable -Property Name

        $results = foreach ($volName in $UniqueVolumeNames) {
            if (-not $VolLookup.ContainsKey($volName)) { continue }
            $vol = $VolLookup[$volName][0]

            $showMeta = $false
            if ($ShowMetadata -is [string]) { $showMeta = ($ShowMetadata.Trim().ToLower() -in @('true','1','yes')) }
            else { try { $showMeta = [bool]$ShowMetadata } catch { $showMeta = $false } }
            if (-not $showMeta -and $vol.Name -and $vol.Name.EndsWith('-md')) { continue }

            $tags = $FullTagSet | Where-Object { $_.Resource.Name -eq $volName }

            $props = [ordered]@{
                Array       = $currentArrayEndpoint
                VM          = "Unknown"
                PureVolume  = $vol.Name
                BusType     = $null
                Index       = $null
                BackingType = $null
                vDisk       = $null
                DiskSize    = if ($null -ne $vol.Space.UsedProvisioned) { [math]::Round($vol.Space.UsedProvisioned / 1GB, 2) } else { $null }
            }

            if ($tags) {
                foreach ($t in $tags) {
                    if ($t.Key -eq 'volume_name') { continue }
                    switch ($t.Key) {
                        'owner_id' {
                            if ($t.Value -and $VMLookup.ContainsKey($t.Value)) {
                                $props['VM'] = $VMLookup[$t.Value].name
                                $vmObj = $VMLookup[$t.Value]
                            } elseif ($t.Value) {
                                $props['VM'] = $t.Value 
                            }
                            continue
                        }
                        'owner_disk_id' { $props['vDisk'] = $t.Value; continue }
                        default { $propName = ($t.Key -replace '\s','_'); if($propName){ $props[$propName] = $t.Value } }
                    }
                }
            }

            if ($vmObj -and $props['vDisk']) {
                $matchFound = $false

                if ($vmObj.Disks) {
                    foreach ($disk in $vmObj.Disks) {
                        if ($disk.extId -eq $props['vDisk']) {
                            $matchFound = $true
                            if ($disk.DiskAddress) {
                                $props['BusType'] = $disk.DiskAddress.busType
                                $props['Index']   = $disk.DiskAddress.index
                            }
                            if ($disk.BackingInfo) {
                                $rawType = $disk.BackingInfo.'$objectType'
                                if ($rawType) { $props['BackingType'] = $rawType -replace '^.*\.config\.', '' }
                            }
                            break
                        }
                    }
                }

                if (-not $matchFound -and $vmObj.CdRoms) {
                    foreach ($cdrom in $vmObj.CdRoms) {
                        if ($cdrom.extId -eq $props['vDisk']) {
                            $matchFound = $true
                            if ($cdrom.DiskAddress) {
                                $props['BusType'] = $cdrom.DiskAddress.busType
                                $props['Index']   = $cdrom.DiskAddress.index
                            }
                            $rawType = $cdrom.'$objectType'
                            if ($rawType) { $props['BackingType'] = $rawType -replace '^.*\.config\.', '' }
                            else { $props['BackingType'] = "CdRom" }
                            break
                        }
                    }
                }

                if (-not $matchFound -and $vmObj.vtpmConfig -and $vmObj.vtpmConfig.vtpmDevice) {
                    $vtpm = $vmObj.vtpmConfig.vtpmDevice
                    if ($vtpm.diskExtId -eq $props['vDisk']) {
                        $matchFound = $true
                        $props['BusType'] = "TPM" 
                        $props['Index']   = ""
                        $rawType = $vtpm.'$objectType'
                        if ($rawType) { $props['BackingType'] = $rawType -replace '^.*\.config\.', '' }
                        else { $props['BackingType'] = "VtpmDevice" }
                    }
                }

                if (-not $matchFound -and $vmObj.bootConfig) {
                    $nvram = $null
                    if ($vmObj.bootConfig.nvramDevice) { $nvram = $vmObj.bootConfig.nvramDevice }
                    elseif ($vmObj.bootConfig.uefiBoot -and $vmObj.bootConfig.uefiBoot.nvramDevice) { $nvram = $vmObj.bootConfig.uefiBoot.nvramDevice }

                    if ($nvram) {
                        $nvramDiskId = $null
                        if ($nvram.backingStorageInfo -and $nvram.backingStorageInfo.diskExtId) {
                            $nvramDiskId = $nvram.backingStorageInfo.diskExtId
                        }
                        if ($nvramDiskId -eq $props['vDisk']) {
                            $matchFound = $true
                            $props['BusType']     = "UEFI"
                            $props['Index']       = ""
                            $props['BackingType'] = "UefiDisk"
                        }
                    }
                }
            }
            $vmObj = $null

            [PSCustomObject]$props
        }

        if ($results) {
            $matchFoundOnThisArray = $true
            $standardCols = @('VM','BusType','Index','BackingType','vDisk','PureVolume','DiskSize')
            $allProps = $results | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique
            $extraTags = $allProps | Where-Object { $_ -notin $standardCols -and $_ -ne 'volume_name' } | Sort-Object
            $columns = $standardCols + $extraTags

            $results | Sort-Object VM, BusType, Index, PureVolume | Format-Table -Property $columns -AutoSize
        }
        else {
            Write-Host "  No results matching criteria on this array."
        }

        $showSnaps = $false
        if ($ShowSnapshots -is [string]) { $showSnaps = ($ShowSnapshots.Trim().ToLower() -in @('true','1','yes')) }
        else { try { $showSnaps = [bool]$ShowSnapshots } catch { $showSnaps = $false } }

        if ($showSnaps -and $results) {
            try {
                $vmVolumes = @()
                if (-not [string]::IsNullOrWhiteSpace($VM)) {
                    $vmVolumes = $results | Where-Object { $_.VM -eq $VM } | Select-Object -ExpandProperty PureVolume -Unique
                } else {
                    $vmVolumes = $results | Select-Object -ExpandProperty PureVolume -Unique
                }

                if ($vmVolumes) {
                    Write-Host "  Retrieving snapshots..." -ForegroundColor Cyan
                    $AllSnaps = Get-Pfa2VolumeSnapshot -Array $array -ErrorAction SilentlyContinue

                    $SnapLookup = @{}
                    if ($AllSnaps) {
                        $SnapLookup = $AllSnaps | Where-Object { $_.Source.Name } | Group-Object -AsHashtable -Property { $_.Source.Name }
                    }

                    foreach ($vol in $vmVolumes) {
                        Write-Host ""
                        Write-Host ("  Snapshots for Volume: {0}" -f $vol) -ForegroundColor Cyan

                        $volSnaps = @()
                        if ($SnapLookup.ContainsKey($vol)) { $volSnaps += $SnapLookup[$vol] }
                        $volSnaps += $AllSnaps | Where-Object { $_.Name -like "$vol.*" -and (-not $_.Source.Name) }

                        if (-not $volSnaps) {
                            Write-Host "    (no snapshots found)"
                            continue
                        }

                        $volSnaps | Select-Object -Unique |
                            Select-Object @{ Name = 'VolumeName'; Expression = { $vol } }, @{ Name = 'SnapshotName'; Expression = { $_.Name } }, @{ Name = 'Created'; Expression = { if ($_.Created) { $_.Created } elseif ($_.TimeCreated) { $_.TimeCreated } elseif ($_.creation_time){ $_.creation_time } elseif ($_.Time) { $_.Time } else { $null } } } |
                            Sort-Object Created | Format-Table -AutoSize
                    }
                }
            }
            catch {
                Write-Warning "Failed to retrieve snapshots: $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-Error "Error processing array $currentArrayEndpoint : $_"
    }
    finally {
        if ($array) {
            Disconnect-Pfa2Array -Array $array -ErrorAction SilentlyContinue 
        }
    }

    if ($matchFoundOnThisArray) {
        if (-not [string]::IsNullOrWhiteSpace($VM)) {
            Write-Host "  Target VM '$VM' found on this array. Stopping search." -ForegroundColor Green
            break
        }
        if (-not [string]::IsNullOrWhiteSpace($Cluster)) {
            break
        }
    }
}