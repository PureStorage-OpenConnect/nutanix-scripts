<#
.SYNOPSIS
    Map Nutanix VM UUIDs and vDisks to Pure Storage Volumes

.DESCRIPTION
    This script reviews Pure Storage Volume Tags and provides comprehensive mapping between
    Nutanix VMs and Pure Storage volumes, including:
    - VM Name (or VM UUID if name not found)
    - Disk Type (Backing, Type and Index)
    - vDisk ID that was used to provision the volume
    - Volume Name and Provisioned Size
    - Any additional tags found on the volume

.PARAMETER ArrayEndpoint
    One or more Pure Storage Array FQDNs or IP Addresses (comma separated)

.PARAMETER ArrayCredential
    Pure Storage Array Credential (Username and Password)

.PARAMETER PrismEndpoint
    Prism Central FQDN or IP Address

.PARAMETER PrismCredential
    Prism Central Credential (Username and Password)

.PARAMETER VM
    (Optional) VM Name to filter results. If not provided, all tagged volumes are returned.

.PARAMETER Cluster
    (Optional) Cluster Name to filter results. If not provided, all tagged volumes are returned.

.PARAMETER ShowMetadata
    (Optional) Include metadata volumes (volumes ending in -md) in results

.PARAMETER ShowSnapshots
    (Optional) Display snapshots for each volume found

.PARAMETER ExportPath
    (Optional) Export results to CSV file at specified path

.EXAMPLE
    Return all Volumes
    ./GetVMVol.ps1 -ArrayEndpoint $ArrayFQDN -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred

.EXAMPLE
    Return specific VM's Volumes
    ./GetVMVol.ps1 -ArrayEndpoint $ArrayFQDN -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -VM "MyVM"

.EXAMPLE
    Return specific Cluster's Volumes with Snapshots
    ./GetVMVol.ps1 -ArrayEndpoint $ArrayFQDN -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -Cluster "Cluster" -ShowSnapshots

.EXAMPLE
    Export results to CSV
    ./GetVMVol.ps1 -ArrayEndpoint $ArrayFQDN -ArrayCredential $cred -PrismEndpoint $PrismFQDN -PrismCredential $prismCred -ExportPath "C:\results.csv"

.NOTES
    Version:        2.1.0
    Author:         David Stamen @ Pure Storage
    Last Modified:  January 2026
    API Version:    Pure Storage REST API 2.49

.CHANGELOG
    10/30/25    1.0.0   Initial version
    11/7/25     1.0.1   Added ShowMetadata, ShowSnapshots parameter
    11/13/25    1.0.2   Optimized with batch API calls and in-memory lookups
    1/22/26     2.0.0   Use Nutanix API instead of PowerShell. Multiple Array Support
    1/23/26     2.1.0   Replaced PureStoragePowershellSDK with direct REST API calls,
                        Improved handling and added progress

.DISCLAIMER
    The sample script and documentation are provided AS IS and are not supported by
    the author or the author's employer, unless otherwise agreed in writing. You bear
    all risk relating to the use or performance of the sample script and documentation.
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
    [switch]$ShowMetadata,

    [Parameter(Mandatory = $false, HelpMessage = "Show Snapshots (Optional)")]
    [switch]$ShowSnapshots,

    [Parameter(Mandatory = $false, HelpMessage = "Export results to CSV file (Optional)")]
    [string]
    $ExportPath
)

function Get-PropertyValue {
    param(
        [Parameter(Mandatory = $true)]
        $Object,
        [Parameter(Mandatory = $true)]
        [string[]]$PropertyPaths
    )

    foreach ($path in $PropertyPaths) {
        $value = $Object
        $parts = $path.Split('.')

        foreach ($part in $parts) {
            if ($null -eq $value) { break }
            if ($value.PSObject.Properties[$part]) {
                $value = $value.$part
            } else {
                $value = $null
                break
            }
        }

        if ($null -ne $value) { return $value }
    }
    return $null
}

function Get-ClusterExtId {
    param($VM)

    $paths = @(
        'cluster.extId', 'cluster.ExtId', 'Cluster.extId', 'Cluster.ExtId',
        'clusterReference.extId', 'clusterReference.ExtId',
        'ClusterReference.extId', 'ClusterReference.ExtId'
    )

    return Get-PropertyValue -Object $VM -PropertyPaths $paths
}

function Get-BiosUuid {
    param($VM)

    return Get-PropertyValue -Object $VM -PropertyPaths @('biosUuid', 'BiosUuid')
}

function New-NutanixAuthHeader {
    param(
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential
    )

    $user = $Credential.UserName
    $pass = $Credential.GetNetworkCredential().Password
    $pair = "${user}:${pass}"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($pair)
    $base64 = [System.Convert]::ToBase64String($bytes)

    return @{ 'Authorization' = "Basic $base64" }
}

function New-PureAuthHeader {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,
        [Parameter(Mandatory = $true)]
        [PSCredential]$Credential
    )

    $apiVersions = @(
        @{ Version = "2.49"; Path = "/api/2.49" },
        @{ Version = "2.39"; Path = "/api/2.39" },
        @{ Version = "2.33"; Path = "/api/2.33" },
        @{ Version = "2.30"; Path = "/api/2.30" },
        @{ Version = "2.28"; Path = "/api/2.28" },
        @{ Version = "2.26"; Path = "/api/2.26" },
        @{ Version = "2.24"; Path = "/api/2.24" },
        @{ Version = "2.20"; Path = "/api/2.20" },
        @{ Version = "2.16"; Path = "/api/2.16" },
        @{ Version = "2.14"; Path = "/api/2.14" },
        @{ Version = "2.10"; Path = "/api/2.10" },
        @{ Version = "2.4"; Path = "/api/2.4" },
        @{ Version = "2.0"; Path = "/api/2.0" },
        @{ Version = "1.19"; Path = "/api/1.19" },
        @{ Version = "1.17"; Path = "/api/1.17" },
        @{ Version = "1.16"; Path = "/api/1.16" }
    )

    $lastError = $null

    foreach ($api in $apiVersions) {
        $loginUrl = "https://${ArrayEndpoint}$($api.Path)/login"
        $body = @{
            username = $Credential.UserName
            password = $Credential.GetNetworkCredential().Password
        } | ConvertTo-Json

        try {
            Write-Verbose "Attempting authentication with API $($api.Version) at $loginUrl..."

            $response = Invoke-WebRequest -Uri $loginUrl -Method Post `
                -Body $body -ContentType "application/json" `
                -SkipCertificateCheck -ErrorAction Stop

            $responseObj = $response.Content | ConvertFrom-Json
            $token = $null

            if ($response.Headers['x-auth-token']) {
                $headerValue = $response.Headers['x-auth-token']

                if ($headerValue -is [array]) {
                    $token = $headerValue[0]
                } else {
                    $token = $headerValue
                }

                $token = $token.ToString()
                Write-Verbose "Successfully authenticated with API $($api.Version) (header-based)"
                Write-Verbose "Token: $token"
            }

            if ($token) {
                return @{
                    'x-auth-token' = $token
                    'Content-Type' = 'application/json'
                    'ApiVersion' = $api.Path
                }
            }
        }
        catch {
            $lastError = $_
            Write-Verbose "API $($api.Version) authentication failed: $($_.Exception.Message)"
            continue
        }
    }

    if ($lastError) {
        $errorMsg = "Failed to authenticate to Pure Storage array ${ArrayEndpoint}"
        if ($lastError.Exception.Response) {
            try {
                $statusCode = $lastError.Exception.Response.StatusCode.value__
                $errorMsg += " (HTTP $statusCode)"

                $reader = New-Object System.IO.StreamReader($lastError.Exception.Response.GetResponseStream())
                $responseBody = $reader.ReadToEnd()
                if ($responseBody) {
                    $errorMsg += ": $responseBody"
                }
            } catch { }
        }
        throw "$errorMsg - Last error: $($lastError.Exception.Message)"
    }

    throw "Failed to authenticate to Pure Storage array ${ArrayEndpoint}: No API token returned from any API version"
}

function Get-NutanixClusterExtId {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrismEndpoint,
        [Parameter(Mandatory = $true)]
        [PSCredential]$PrismCredential,
        [Parameter(Mandatory = $true)]
        [string]$ClusterName
    )

    $baseUrl = "https://${PrismEndpoint}:9440/api/clustermgmt/v4.2/config/clusters"
    $headers = New-NutanixAuthHeader -Credential $PrismCredential
    $filter = "?`$filter=name eq '$ClusterName'&`$limit=1"
    $uri = "${baseUrl}${filter}"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers `
            -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop

        if ($response.data -and $response.data.Count -gt 0) {
            $cluster = $response.data[0]
            $extId = Get-PropertyValue -Object $cluster -PropertyPaths @('extId', 'ExtId')

            if ($extId) { return $extId }
            throw "Cluster found but ExtId property is missing."
        }
        else {
            throw "Cluster '$ClusterName' not found."
        }
    }
    catch {
        $errMessage = $_.Exception.Message
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errBody = $reader.ReadToEnd()
                Write-Warning "Cluster API Error: $errBody"
            } catch { }
        }
        throw "Failed to retrieve Cluster ID for '${ClusterName}': $errMessage"
    }
}

function Get-NutanixVMs {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrismEndpoint,

        [Parameter(Mandatory = $true)]
        [PSCredential]$PrismCredential,

        [string]$FilterVMName,
        [string]$ClusterFilterId
    )

    $baseUrl = "https://${PrismEndpoint}:9440/api/vmm/v4.2/ahv/config/vms"
    $headers = New-NutanixAuthHeader -Credential $PrismCredential

    function Fetch-VMPage {
        param ([string]$ODataFilter)

        $collected = @()
        $page = 0
        $limit = 50
        $totalFetched = 0
        $grandTotal = -1
        $sortParam = "&`$orderby=name"

        do {
            $uri = "${baseUrl}?`$page=${page}&`$limit=${limit}${ODataFilter}${sortParam}"

            try {
                $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers `
                    -ContentType "application/json" -SkipCertificateCheck -ErrorAction Stop

                $batchCount = 0

                if ($response.data) {
                    $batch = @($response.data)
                    $batchCount = $batch.Count

                    if ($response.metadata -and $response.metadata.totalAvailableResults) {
                        $grandTotal = $response.metadata.totalAvailableResults
                    }

                    foreach ($vm in $batch) {
                        if (-not [string]::IsNullOrWhiteSpace($ClusterFilterId)) {
                            $vmClusterId = Get-ClusterExtId -VM $vm
                            if ($vmClusterId -ne $ClusterFilterId) { continue }
                        }
                        $collected += $vm
                    }
                }

                $totalFetched += $batchCount

                if ($grandTotal -ge 0 -and $totalFetched -ge $grandTotal) { break }
                if ($batchCount -eq 0) { break }

                $page++
            }
            catch {
                Write-Warning "Error fetching VM page ${page}: $($_.Exception.Message)"
                break
            }
        } while ($true)

        return $collected
    }

    if (-not [string]::IsNullOrWhiteSpace($FilterVMName)) {
        Write-Verbose "Attempting exact match for VM '$FilterVMName'..."
        $serverFilter = "&`$filter=name eq '$FilterVMName'"

        try {
            $results = Fetch-VMPage -ODataFilter $serverFilter
            if ($results.Count -gt 0) {
                Write-Verbose "Found $($results.Count) VM(s) with exact match"
                return $results
            }
            Write-Verbose "Exact match not found. Switching to full scan..."
        }
        catch {
            Write-Warning "Server filter failed. Retrying with full scan."
        }
    }

    $allVMs = Fetch-VMPage -ODataFilter ""

    if (-not [string]::IsNullOrWhiteSpace($FilterVMName)) {
        $filtered = $allVMs | Where-Object { $_.name -eq $FilterVMName }
        Write-Verbose "Full scan found $($filtered.Count) matching VM(s)"
        return $filtered
    }

    Write-Verbose "Retrieved $($allVMs.Count) total VMs"
    return $allVMs
}

function Get-PureVolumeTags {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,

        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,

        [string]$Namespace,
        [string]$Filter,
        [string[]]$ResourceNames,
        [switch]$ShowProgress
    )

    $apiVersion = if ($Headers.ContainsKey('ApiVersion')) {
        $Headers['ApiVersion']
    } else {
        '/api/2.49'
    }

    $baseUrl = "https://${ArrayEndpoint}${apiVersion}"
    $endpoint = "/volumes/tags"

    $allItems = @()
    $offset = 0
    $limit = 500
    $moreData = $true
    $totalFetched = 0
    $startTime = Get-Date

    $firstCall = $true

    while ($moreData) {
        $uri = "${baseUrl}${endpoint}?limit=${limit}&offset=${offset}"

        if ($Namespace) {
            $uri += "&namespaces=${Namespace}"
        }

        if ($Filter) {
            $encodedFilter = [System.Web.HttpUtility]::UrlEncode($Filter)
            $uri += "&filter=${encodedFilter}"
        }

        if ($ResourceNames -and $ResourceNames.Count -gt 0) {
            $resourceNamesParam = ($ResourceNames | ForEach-Object { [System.Web.HttpUtility]::UrlEncode($_) }) -join ','
            $uri += "&resource_names=${resourceNamesParam}"
        }

        if ($firstCall) {
            $uri += "&total_item_count=true"
            $firstCall = $false
        }

        try {
            $requestHeaders = @{
                'x-auth-token' = $Headers['x-auth-token']
                'Content-Type' = 'application/json'
            }

            Write-Verbose "API Request: GET $uri"

            $response = Invoke-RestMethod -Uri $uri -Method Get `
                -Headers $requestHeaders -SkipCertificateCheck -ErrorAction Stop

            if ($response.items) {
                $allItems += $response.items
                $totalFetched += $response.items.Count

                if ($ShowProgress) {
                    if ($response.total_item_count) {
                        $percentComplete = [Math]::Min(100, [Math]::Round(($totalFetched / $response.total_item_count) * 100))
                        $elapsed = (Get-Date) - $startTime
                        $rate = $totalFetched / $elapsed.TotalSeconds
                        $remaining = $response.total_item_count - $totalFetched
                        $etaSeconds = if ($rate -gt 0) { [Math]::Round($remaining / $rate) } else { 0 }

                        if ($totalFetched % 1000 -eq 0 -or $totalFetched -eq $response.total_item_count) {
                            Write-Host "`r  Progress: $totalFetched / $($response.total_item_count) tags - ETA: $etaSeconds sec" -NoNewline -ForegroundColor Gray
                        }
                    }
                }
            }

            if (-not $ResourceNames) {
                if ($response.continuation_token -or
                    ($response.total_item_count -and ($offset + $limit) -lt $response.total_item_count)) {
                    $offset += $limit
                }
                else {
                    $moreData = $false
                }
            }
            else {
                $moreData = $false
            }
        }
        catch {
            Write-Verbose "API call failed: $($_.Exception.Message)"
            $moreData = $false
        }
    }

    if ($ShowProgress) {
        Write-Host ""
    }

    return $allItems
}

function Disconnect-PureArray {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers
    )

    $apiVersion = if ($Headers.ContainsKey('ApiVersion')) {
        $Headers['ApiVersion']
    } else {
        '/api/2.49'
    }

    $baseUrl = "https://${ArrayEndpoint}${apiVersion}"
    $logoutUrl = "${baseUrl}/logout"

    $requestHeaders = @{
        'x-auth-token' = $Headers['x-auth-token']
        'Content-Type' = 'application/json'
    }

    try {
        Invoke-RestMethod -Uri $logoutUrl -Method Post -Headers $requestHeaders `
            -SkipCertificateCheck -ErrorAction SilentlyContinue | Out-Null
    }
    catch {
        Write-Verbose "Logout failed: $($_.Exception.Message)"
    }
}

function Find-VMDiskInfo {
    param(
        [Parameter(Mandatory = $true)]
        $VMObject,
        [Parameter(Mandatory = $true)]
        [string]$VDiskId
    )

    $result = @{
        BusType     = $null
        Index       = $null
        BackingType = $null
        Found       = $false
    }

    if ($VMObject.Disks) {
        foreach ($disk in $VMObject.Disks) {
            if ($disk.extId -eq $VDiskId) {
                $result.Found = $true

                if ($disk.DiskAddress) {
                    $result.BusType = $disk.DiskAddress.busType
                    $result.Index = $disk.DiskAddress.index
                }

                if ($disk.BackingInfo) {
                    $rawType = $disk.BackingInfo.'$objectType'
                    if ($rawType) {
                        $result.BackingType = $rawType -replace '^.*\.config\.', ''
                    }
                }
                return $result
            }
        }
    }

    if ($VMObject.CdRoms) {
        foreach ($cdrom in $VMObject.CdRoms) {
            if ($cdrom.extId -eq $VDiskId) {
                $result.Found = $true

                if ($cdrom.DiskAddress) {
                    $result.BusType = $cdrom.DiskAddress.busType
                    $result.Index = $cdrom.DiskAddress.index
                }

                $rawType = $cdrom.'$objectType'
                $result.BackingType = if ($rawType) {
                    $rawType -replace '^.*\.config\.', ''
                } else {
                    "CdRom"
                }
                return $result
            }
        }
    }

    if ($VMObject.vtpmConfig -and $VMObject.vtpmConfig.vtpmDevice) {
        $vtpm = $VMObject.vtpmConfig.vtpmDevice
        if ($vtpm.diskExtId -eq $VDiskId) {
            $result.Found = $true
            $result.BusType = "TPM"
            $result.Index = ""
            $rawType = $vtpm.'$objectType'
            $result.BackingType = if ($rawType) {
                $rawType -replace '^.*\.config\.', ''
            } else {
                "VtpmDevice"
            }
            return $result
        }
    }

    if ($VMObject.bootConfig) {
        $nvram = $null
        if ($VMObject.bootConfig.nvramDevice) {
            $nvram = $VMObject.bootConfig.nvramDevice
        }
        elseif ($VMObject.bootConfig.uefiBoot -and $VMObject.bootConfig.uefiBoot.nvramDevice) {
            $nvram = $VMObject.bootConfig.uefiBoot.nvramDevice
        }

        if ($nvram) {
            $nvramDiskId = $null
            if ($nvram.backingStorageInfo -and $nvram.backingStorageInfo.diskExtId) {
                $nvramDiskId = $nvram.backingStorageInfo.diskExtId
            }

            if ($nvramDiskId -eq $VDiskId) {
                $result.Found = $true
                $result.BusType = "UEFI"
                $result.Index = ""
                $result.BackingType = "UefiDisk"
                return $result
            }
        }
    }

    return $result
}

function Get-VolumeSnapshots {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [string[]]$VolumeNames
    )

    if (-not $VolumeNames) { return }

    Write-Host "  Retrieving snapshots..." -ForegroundColor Cyan
    try {
        $AllSnaps = Get-PureVolumeSnapshots -ArrayEndpoint $ArrayEndpoint -Headers $Headers
        if (-not $AllSnaps) {
            Write-Host "    (no snapshots found on array)" -ForegroundColor Gray
            return
        }

        $SnapLookup = @{}
        $AllSnaps | Where-Object { $_.source -and $_.source.name } | ForEach-Object {
            $sourceName = $_.source.name
            if (-not $SnapLookup.ContainsKey($sourceName)) {
                $SnapLookup[$sourceName] = @()
            }
            $SnapLookup[$sourceName] += $_
        }

        foreach ($vol in $VolumeNames) {
            Write-Host ""
            Write-Host ("  Snapshots for Volume: {0}" -f $vol) -ForegroundColor Cyan

            $volSnaps = @()

            if ($SnapLookup.ContainsKey($vol)) {
                $volSnaps += $SnapLookup[$vol]
            }
            $escapedVol = [regex]::Escape($vol)
            $volSnaps += $AllSnaps | Where-Object {
                $_.name -match "^${escapedVol}\." -and (-not ($_.source -and $_.source.name))
            }

            if (-not $volSnaps) {
                Write-Host "    (no snapshots found)" -ForegroundColor Gray
                continue
            }

            $volSnaps | Select-Object -Unique |
                Select-Object @{
                    Name = 'VolumeName'
                    Expression = { $vol }
                },
                @{
                    Name = 'SnapshotName'
                    Expression = { $_.name }
                },
                @{
                    Name = 'Created'
                    Expression = {
                        $_.created ?? $_.time_remaining ?? $_.time
                    }
                },
                @{
                    Name = 'Size (GB)'
                    Expression = {
                        if ($_.space -and $_.space.total_provisioned) {
                            [math]::Round($_.space.total_provisioned / 1GB, 2)
                        } else { $null }
                    }
                } |
                Sort-Object Created |
                Format-Table -AutoSize
        }
    }
    catch {
        Write-Warning "Failed to retrieve snapshots: $($_.Exception.Message)"
    }
}
function Get-PureVolumeSnapshots {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [string]$SourceName
    )

    $endpoint = "/volume-snapshots"
    $filter = if ($SourceName) { "source.name='$SourceName'" } else { "" }

    return Invoke-PureApi -ArrayEndpoint $ArrayEndpoint -Headers $Headers `
        -Endpoint $endpoint -Filter $filter
}
function Invoke-PureApi {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [string]$Filter,
        [string]$Method = 'Get',
        [int]$Limit = 100
    )

    $apiVersion = if ($Headers.ContainsKey('ApiVersion')) {
        $Headers['ApiVersion']
    } else {
        '/api/2.49'
    }

    $baseUrl = "https://${ArrayEndpoint}${apiVersion}"
    $allItems = @()
    $offset = 0
    $moreData = $true

    while ($moreData) {
        $uri = "${baseUrl}${Endpoint}?limit=${Limit}&offset=${offset}"

        if ($Filter) {
            $encodedFilter = [System.Web.HttpUtility]::UrlEncode($Filter)
            $uri += "&filter=${encodedFilter}"
        }

        try {
            $requestHeaders = @{
                'x-auth-token' = $Headers['x-auth-token']
                'Content-Type' = 'application/json'
            }

            Write-Verbose "API Request: $Method $uri"
            Write-Verbose "Token (first 20 chars): $($Headers['x-auth-token'].Substring(0, [Math]::Min(20, $Headers['x-auth-token'].Length)))..."

            $response = Invoke-RestMethod -Uri $uri -Method $Method `
                -Headers $requestHeaders -SkipCertificateCheck -ErrorAction Stop

            if ($response.items) {
                $allItems += $response.items
            }
            elseif ($response) {
                $allItems += $response
                $moreData = $false
                continue
            }

            if ($response.continuation_token -or
                ($response.total_item_count -and ($offset + $Limit) -lt $response.total_item_count)) {
                $offset += $Limit
            }
            else {
                $moreData = $false
            }
        }
        catch {
            Write-Warning "API call failed for ${Endpoint}: $($_.Exception.Message)"
            if ($_.Exception.Response) {
                try {
                    $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                    $responseBody = $reader.ReadToEnd()
                    Write-Verbose "Error response body: $responseBody"
                } catch { }
            }
            $moreData = $false
        }
    }

    return $allItems
}

function Get-VolumeResults {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ArrayEndpoint,
        [Parameter(Mandatory = $true)]
        [hashtable]$Headers,
        [Parameter(Mandatory = $true)]
        [hashtable]$VMLookup,
        [Parameter(Mandatory = $true)]
        [string]$Namespace,
        [Parameter(Mandatory = $true)]
        [array]$VolumeNames,
        [Parameter(Mandatory = $true)]
        [array]$FullTagSet,
        [switch]$ShowProgress
    )

    Write-Verbose "Fetching volume details for $($VolumeNames.Count) volumes..."

    $apiVersion = if ($Headers.ContainsKey('ApiVersion')) {
        $Headers['ApiVersion']
    } else {
        '/api/2.49'
    }

    $baseUrl = "https://${ArrayEndpoint}${apiVersion}"
    $requestHeaders = @{
        'x-auth-token' = $Headers['x-auth-token']
        'Content-Type' = 'application/json'
    }

    $VolLookup = @{}
    $batchSize = 50
    $totalBatches = [Math]::Ceiling($VolumeNames.Count / $batchSize)
    $currentBatch = 0
    $startTime = Get-Date

    for ($i = 0; $i -lt $VolumeNames.Count; $i += $batchSize) {
        $currentBatch++
        $endIndex = [Math]::Min($i + $batchSize, $VolumeNames.Count)
        $batch = $VolumeNames[$i..($endIndex - 1)]

        if ($currentBatch -gt 1 -and $ShowProgress) {
            $elapsed = (Get-Date) - $startTime
            $rate = ($currentBatch - 1) / $elapsed.TotalSeconds
            $remainingBatches = $totalBatches - $currentBatch + 1
            $etaSeconds = if ($rate -gt 0) { [Math]::Round($remainingBatches / $rate) } else { 0 }
            Write-Host "`r  Processing: $($i+1) / $($VolumeNames.Count) volumes - ETA: $etaSeconds sec" -NoNewline -ForegroundColor Gray
        }

        $nameFilters = $batch | ForEach-Object { "name='$_'" }
        $filter = $nameFilters -join ' or '
        $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filter)

        $volumesUrl = "${baseUrl}/volumes?filter=${encodedFilter}&limit=${batchSize}"

        try {
            $volumesResponse = Invoke-RestMethod -Uri $volumesUrl -Method Get `
                -Headers $requestHeaders -SkipCertificateCheck -ErrorAction Stop

            if ($volumesResponse.items) {
                foreach ($vol in $volumesResponse.items) {
                    $VolLookup[$vol.name] = $vol
                }
            }
        }
        catch {
            Write-Warning "Failed to fetch volume batch ${currentBatch}: $($_.Exception.Message)"
        }
    }

    if ($ShowProgress) {
        Write-Host ""
    }
    Write-Verbose "Retrieved details for $($VolLookup.Count) volumes"

    $results = foreach ($volName in $VolumeNames) {
        if (-not $VolLookup.ContainsKey($volName)) {
            Write-Verbose "Volume $volName not found in array"
            continue
        }

        $vol = $VolLookup[$volName]

        if (-not $ShowMetadata -and $vol.name -and $vol.name.EndsWith('-md')) {
            continue
        }

        $tags = $FullTagSet | Where-Object { $_.resource -and $_.resource.name -eq $volName }

        $props = [ordered]@{
            Array       = $ArrayEndpoint
            VM          = "Unknown"
            PureVolume  = $vol.name
            BusType     = $null
            Index       = $null
            BackingType = $null
            vDisk       = $null
            DiskSize    = if ($vol.space -and $null -ne $vol.space.total_provisioned) {
                [math]::Round($vol.space.total_provisioned / 1GB, 2)
            } else { $null }
        }

        $vmObj = $null

        if ($tags) {
            foreach ($t in $tags) {
                if ($t.key -eq 'volume_name') { continue }
                switch ($t.key) {
                    'owner_id' {
                        if ($t.value -and $VMLookup.ContainsKey($t.value)) {
                            $props['VM'] = $VMLookup[$t.value].name
                            $vmObj = $VMLookup[$t.value]
                        } elseif ($t.value) {
                            $props['VM'] = $t.value
                        }
                        continue
                    }
                    'owner_disk_id' {
                        $props['vDisk'] = $t.value
                        continue
                    }
                    default {
                        $propName = ($t.key -replace '\s', '_')
                        if ($propName) {
                            $props[$propName] = $t.value
                        }
                    }
                }
            }
        }

        if ($vmObj -and $props['vDisk']) {
            try {
                $diskInfo = Find-VMDiskInfo -VMObject $vmObj -VDiskId $props['vDisk']
                if ($diskInfo.Found) {
                    $props['BusType'] = $diskInfo.BusType
                    $props['Index'] = $diskInfo.Index
                    $props['BackingType'] = $diskInfo.BackingType
                }
            }
            catch {
                Write-Warning "Error finding disk info for volume ${volName}: $($_.Exception.Message)"
            }
        }

        [PSCustomObject]$props
    }
    return $results
}

if ([System.Net.ServicePointManager]::ServerCertificateValidationCallback -eq $null) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
}

if ($ArrayEndpoint.Count -eq 1 -and $ArrayEndpoint[0] -match ',') {
    $ArrayEndpoint = $ArrayEndpoint[0] -split ',' | ForEach-Object { $_.Trim() }
}
$ArrayEndpoint = $ArrayEndpoint | Select-Object -Unique

Write-Host "Starting Pure Storage Volume Mapping..." -ForegroundColor Green
Write-Host "Arrays to scan: $($ArrayEndpoint -join ', ')" -ForegroundColor Cyan

try {
    $targetClusterId = $null
    if (-not [string]::IsNullOrWhiteSpace($Cluster)) {
        Write-Host "`nResolving Cluster ID for '$Cluster'..." -ForegroundColor Cyan
        try {
            $targetClusterId = Get-NutanixClusterExtId -PrismEndpoint $PrismEndpoint `
                -PrismCredential $PrismCredential -ClusterName $Cluster
            Write-Host "  Cluster ID: $targetClusterId" -ForegroundColor Gray
        }
        catch {
            Write-Error "Failed to resolve cluster: $_"
            exit 1
        }
    }

    Write-Host "`nRetrieving VM information from Nutanix Prism $PrismEndpoint..." -ForegroundColor Cyan

    $prismVMs = Get-NutanixVMs -PrismEndpoint $PrismEndpoint `
        -PrismCredential $PrismCredential `
        -FilterVMName $VM `
        -ClusterFilterId $targetClusterId

    if (-not $prismVMs) {
        if ($VM) {
            Write-Error "VM '$VM' not found."
            exit 1
        }
        else {
            Write-Warning "No VMs returned from Prism (check cluster/permissions)."
        }
    }

    $VMLookup = @{}
    if ($prismVMs) {
        foreach ($v in $prismVMs) {
            $extId = Get-PropertyValue -Object $v -PropertyPaths @('extId')
            $biosUuid = Get-BiosUuid -VM $v

            if ($extId) { $VMLookup[$extId] = $v }
            if ($biosUuid) { $VMLookup[$biosUuid] = $v }
        }
        Write-Host "  Found $($prismVMs.Count) VM(s)..." -ForegroundColor Gray
    }
}
catch {
    Write-Error "Error fetching Nutanix data: $_"
    exit 1
}

$allResults = @()
$namespace = 'nutanix-integration.nutanix.com'

foreach ($currentArrayEndpoint in $ArrayEndpoint) {
    Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
    Write-Host "Processing Array: $currentArrayEndpoint" -ForegroundColor Cyan
    Write-Host "$('=' * 80)" -ForegroundColor Cyan

    $authHeaders = $null
    $matchFoundOnThisArray = $false

    try {
        Write-Host "  Authenticating to array..." -ForegroundColor Gray
        $authHeaders = New-PureAuthHeader -ArrayEndpoint $currentArrayEndpoint `
            -Credential $ArrayCredential
        Write-Host "  Connected successfully" -ForegroundColor Green

        $OwnerTags = @()

        if (-not [string]::IsNullOrWhiteSpace($VM) -and $VMLookup.Count -gt 0) {
            Write-Host "  Performing targeted tag search for VM '$VM'..." -ForegroundColor Gray

            foreach ($uuid in $VMLookup.Keys) {
                $filter = "key='owner_id' and value='$uuid'"
                $found = Get-PureVolumeTags -ArrayEndpoint $currentArrayEndpoint `
                    -Headers $authHeaders `
                    -Namespace $namespace `
                    -Filter $filter

                if ($found) { $OwnerTags += $found }
            }
        }
        else {
            Write-Host "  Retrieving information from array..." -ForegroundColor Gray
            $filter = "key='owner_id'"
            $OwnerTags = Get-PureVolumeTags -ArrayEndpoint $currentArrayEndpoint `
                -Headers $authHeaders `
                -Namespace $namespace `
                -Filter $filter
        }

        if (-not $OwnerTags) {
            Write-Host "  No matching volumes found on this array." -ForegroundColor Yellow
            continue
        }

        if (-not [string]::IsNullOrWhiteSpace($VM) -or -not [string]::IsNullOrWhiteSpace($Cluster)) {
            $foundUUIDs = $VMLookup.Keys
            $OwnerTags = $OwnerTags | Where-Object { $_.value -in $foundUUIDs }
        }

        if (-not $OwnerTags) {
            Write-Host "  No matching volumes found on this array." -ForegroundColor Yellow
            continue
        }

        $UniqueVolumeNames = $OwnerTags |
            Where-Object { $_.resource -and $_.resource.name } |
            Select-Object -ExpandProperty resource |
            Select-Object -ExpandProperty name -Unique

        if (-not $UniqueVolumeNames -or $UniqueVolumeNames.Count -eq 0) {
            Write-Host "  No matching volumes found on this array." -ForegroundColor Yellow
            continue
        }

        Write-Host "  Found $($UniqueVolumeNames.Count) volume(s)..." -ForegroundColor Gray
        Write-Verbose "Fetching tags for matched volumes..."

        $FullTagSet = @()

        if ($UniqueVolumeNames.Count -le 50) {
            Write-Host "  Retrieving tag details..." -ForegroundColor Cyan

            $FullTagSet = Get-PureVolumeTags -ArrayEndpoint $currentArrayEndpoint `
                -Headers $authHeaders `
                -Namespace $namespace `
                -ResourceNames $UniqueVolumeNames `
                -ShowProgress
            Write-Host "  ✓ Retrieved tags for $($UniqueVolumeNames.Count) volumes" -ForegroundColor Green
        }
        else {
            Write-Host "  Retrieving tag details..." -ForegroundColor Cyan

            $FullTagSet = Get-PureVolumeTags -ArrayEndpoint $currentArrayEndpoint `
                -Headers $authHeaders `
                -Namespace $namespace `
                -ShowProgress

            $volumeNameLookup = @{}
            foreach ($vName in $UniqueVolumeNames) {
                $volumeNameLookup[$vName] = $true
            }

            $FullTagSet = $FullTagSet | Where-Object {
                $_.resource -and $_.resource.name -and $volumeNameLookup.ContainsKey($_.resource.name)
            }
            Write-Host "  ✓ Retrieved tags for $($UniqueVolumeNames.Count) volumes" -ForegroundColor Green
        }

        Write-Host "  Processing volume information..." -ForegroundColor Cyan

        $results = Get-VolumeResults -ArrayEndpoint $currentArrayEndpoint `
            -Headers $authHeaders `
            -VMLookup $VMLookup `
            -Namespace $namespace `
            -VolumeNames $UniqueVolumeNames `
            -FullTagSet $FullTagSet `
            -ShowProgress

        if ($results) {
            $matchFoundOnThisArray = $true

            Write-Host "  ✓ Processed $($results.Count) volumes" -ForegroundColor Green

            $standardCols = @('VM', 'BusType', 'Index', 'BackingType', 'vDisk', 'PureVolume', 'DiskSize')
            $allProps = $results | ForEach-Object { $_.PSObject.Properties.Name } | Select-Object -Unique
            $extraTags = $allProps | Where-Object {
                $_ -notin $standardCols -and $_ -ne 'volume_name' -and $_ -ne 'Array'
            } | Sort-Object
            $columns = $standardCols + $extraTags

            Write-Host ""
            $results | Sort-Object VM, BusType, Index, PureVolume |
                Format-Table -Property $columns -AutoSize

            $allResults += $results

            if ($ShowSnapshots) {
                $vmVolumes = @()
                if (-not [string]::IsNullOrWhiteSpace($VM)) {
                    $vmVolumes = $results | Where-Object { $_.VM -eq $VM } |
                        Select-Object -ExpandProperty PureVolume -Unique
                } else {
                    $vmVolumes = $results | Select-Object -ExpandProperty PureVolume -Unique
                }

                if ($vmVolumes) {
                    Get-VolumeSnapshots -ArrayEndpoint $currentArrayEndpoint `
                        -Headers $authHeaders -VolumeNames $vmVolumes
                }
            }
        }
        else {
            Write-Host "  No results matching criteria on this array." -ForegroundColor Yellow
        }

        if ($matchFoundOnThisArray) {
            if (-not [string]::IsNullOrWhiteSpace($VM)) {
                Write-Host "`n  VM '$VM' found on this array. Stopping search." -ForegroundColor Green
                break
            }
            if (-not [string]::IsNullOrWhiteSpace($Cluster)) {
                Write-Host "`n  Cluster '$Cluster' found on this array. Stopping search." -ForegroundColor Green
                break
            }
        }
    }
    catch {
        Write-Error "Error processing array ${currentArrayEndpoint}: $_"
        Write-Error $_.ScriptStackTrace
    }
    finally {
        if ($authHeaders) {
            try {
                Disconnect-PureArray -ArrayEndpoint $currentArrayEndpoint -Headers $authHeaders
                Write-Verbose "Disconnected from array $currentArrayEndpoint"
            }
            catch {
                Write-Warning "Failed to disconnect from array: $($_.Exception.Message)"
            }
        }
    }
}

Write-Host "`n$('=' * 80)" -ForegroundColor Cyan
Write-Host "Summary" -ForegroundColor Cyan
Write-Host "$('=' * 80)" -ForegroundColor Cyan

if ($allResults) {
    $totalVolumes = $allResults.Count
    $uniqueVMs = ($allResults | Select-Object -ExpandProperty VM -Unique).Count
    $totalSize = ($allResults | Measure-Object -Property DiskSize -Sum).Sum

    Write-Host "  Total Volumes Found: $totalVolumes" -ForegroundColor Green
    Write-Host "  Unique VMs: $uniqueVMs" -ForegroundColor Green
    Write-Host "  Total Provisioned Size: $([math]::Round($totalSize, 2)) GB" -ForegroundColor Green

    if (-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        try {
            $allResults | Export-Csv -Path $ExportPath -NoTypeInformation -ErrorAction Stop
            Write-Host "`n  Results exported to: $ExportPath" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to export results: $_"
        }
    }
}
else {
    Write-Host "  No volumes found matching criteria." -ForegroundColor Yellow

    if ($VM) {
        Write-Host "`n  Troubleshooting tips for VM '$VM':" -ForegroundColor Cyan
        Write-Host "    - Verify the VM name is correct (case-sensitive)" -ForegroundColor Gray
        Write-Host "    - Check that the VM has Pure Storage volumes attached" -ForegroundColor Gray
        Write-Host "    - Ensure volumes are properly tagged in the nutanix-integration namespace" -ForegroundColor Gray
        Write-Host "    - Verify array credentials and connectivity" -ForegroundColor Gray
    }

    if ($Cluster) {
        Write-Host "`n  Troubleshooting tips for Cluster '$Cluster':" -ForegroundColor Cyan
        Write-Host "    - Verify the Cluster name is correct (case-sensitive)" -ForegroundColor Gray
        Write-Host "    - Check Prism Central connectivity and permissions" -ForegroundColor Gray
        Write-Host "    - Ensure VMs in cluster have Pure Storage volumes" -ForegroundColor Gray
    }

    if (-not $VM -and -not $Cluster) {
        Write-Host "`n  Troubleshooting tips:" -ForegroundColor Cyan
        Write-Host "    - Verify Pure Storage arrays are accessible" -ForegroundColor Gray
        Write-Host "    - Check that volumes have nutanix-integration tags" -ForegroundColor Gray
        Write-Host "    - Ensure Prism Central is returning VM data" -ForegroundColor Gray
        Write-Host "    - Verify credentials for both systems" -ForegroundColor Gray
    }
}
