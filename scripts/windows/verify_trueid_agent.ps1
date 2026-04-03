param(
    [string]$ServiceName = "TrueIDAgent",
    [int[]]$RemotePorts = @(5615, 5617),
    [switch]$RestartService,
    [int]$WaitSeconds = 15
)

$ErrorActionPreference = "Stop"

function Wait-ServiceState {
    param(
        [string]$Name,
        [string]$DesiredState,
        [int]$TimeoutSeconds = 15
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
        if ($null -ne $service -and $service.State -eq $DesiredState) {
            return $service
        }
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $deadline)

    throw "Service '$Name' did not reach state '$DesiredState' within ${TimeoutSeconds}s."
}

if ($RestartService) {
    Restart-Service -Name $ServiceName -Force
    Wait-ServiceState -Name $ServiceName -DesiredState "Running" -TimeoutSeconds $WaitSeconds | Out-Null
}

$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($null -eq $service) {
    throw "Service '$ServiceName' not found."
}

$processes = Get-CimInstance Win32_Process -Filter "Name='net-identity-agent.exe'" |
    Select-Object ProcessId, ParentProcessId, CommandLine

$wrapper = $processes | Where-Object { $_.CommandLine -match '\sservice(\s|$)' } | Select-Object -First 1
$child = $null
if ($null -ne $wrapper) {
    $child = $processes | Where-Object { $_.ParentProcessId -eq $wrapper.ProcessId } | Select-Object -First 1
}

$connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue |
    Where-Object { $RemotePorts -contains $_.RemotePort } |
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

$report = [ordered]@{
    timestamp = (Get-Date).ToString("o")
    computer_name = $env:COMPUTERNAME
    service = [ordered]@{
        name = $service.Name
        display_name = $service.DisplayName
        state = $service.State
        start_mode = $service.StartMode
        path_name = $service.PathName
    }
    wrapper_process = $wrapper
    child_process = $child
    tls_connections = @($connections)
}

$report | ConvertTo-Json -Depth 6
