function Get-EventsDetails($events_list){
    $detailsEventsList = New-Object System.Collections.Generic.List[PSObject]
    
    foreach($events in $events_list){ 
        $eventDetails = New-Object PSObject

        $eventDetails | Add-Member -MemberType NoteProperty -Name 'TimeCreated' -Value $events.TimeCreated
        $eventDetails | Add-Member -MemberType NoteProperty -Name 'ProviderName' -Value $events.ProviderName
        $eventDetails | Add-Member -MemberType NoteProperty -Name 'Id' -Value $events.Id

        $events.Message -split [Environment]::NewLine | ForEach-Object {
            #if ($_ -match '^\s*(\w+)\s*:\s*(.+)') {
            if ($_ -match '(^[\s\w]+):(.*)[^\n]$') {
                $propertyName = $Matches[1].Trim()
                $propertyValue = $Matches[2].Trim()
                $eventDetails | Add-Member -MemberType NoteProperty -Name $propertyName -Value $propertyValue
            }
        }

        $detailsEventsList.Add($eventDetails) 
    }
    
    return $detailsEventsList
}

function Get-SysmonEvent{
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-Sysmon/Operational"}
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    $events_list = Get-WinEvent -FilterHashtable $filters -ErrorAction SilentlyContinue
    
    Get-EventsDetails($events_list)

}

function Get-SecurityEvent {
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Security"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }
    $events_list = Get-WinEvent -FilterHashtable $filters -ErrorAction SilentlyContinue
    $events_list
    #Get-EventsDetails($events_list)
}

function Get-PSLogEvent {
    param (
        $eventid,
        $start,
        $end
    )
    $filters = @{LogName = "Microsoft-Windows-PowerShell/Operational"}
    
    if ($eventid -ne $null) {
        $filters.ID = $eventid
    }
    if ($start -ne $null) {
        $filters.StartTime = $start
    }

    if ($end -ne $null) {
        $filters.EndTime = $end
    }

    $events_list = Get-WinEvent -FilterHashtable $filters -ErrorAction SilentlyContinue
    $events_list 
    #Get-EventsDetails($events_list)
}