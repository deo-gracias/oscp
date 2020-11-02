 $groups = ([System.Security.Principal.WindowsIdentity]::GetCurrent().Groups).Value | foreach-Object{$objSID = New-Object System.Security.Principal.SecurityIdentifier ($_); Write-Output ($objSID.Translate( [System.Security.Principal.NTAccount])).Value }  

function Get-MyServices(){
 $serv = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\* | Where-Object {$_.ObjectName -match "LocalSystem"} | Select PSChildName; 
return $serv;
}

function Get-SDDL-Group($current_group){
$groups_array = @();
  if ( ($current_group | Out-String ) -match "System" ) { $groups_array += 'SY' }
  if ( ($current_group | Out-String ) -match "Administrators" ) { $groups_array += 'BA' }
  if ( ($current_group | Out-String ) -match "Domain administrators" ) { $groups_array += 'DA' }
  if ( ($current_group | Out-String ) -match "Domain Users" ) { $groups_array += 'DU' }
  if ( ($current_group | Out-String ) -match "Authenticated Users" ) { $groups_array += 'AU' }
  if ( ($current_group | Out-String ) -match "Everyone" ) { $groups_array += 'WD' }
 
 return $groups_array; 
}

function Get-CanStartServices(){
 $services = Get-MyServices ;
 $groups_array = Get-SDDL-Group($groups);

 foreach ($s in $services){
  $sddl = cmd /c sc sdshow $s.PSChildName
 
  foreach ($g in $groups_array){
  if($sddl -match "RP[A-Z]*?;;;$g"){
  Write-Output ($s.PSChildName)
  }
  }
 }
}

function Get-CanStopServices(){
$services = Get-MyServices ;
 $groups_array = Get-SDDL-Group($groups);

 foreach ($s in $services){
  $sddl = cmd /c sc sdshow $s.PSChildName
 
  foreach ($g in $groups_array){
  if($sddl -match "WP[A-Z]*?;;;$g"){
  Write-Output ($s.PSChildName)
  }
  }
 }
}


function Get-CanStartAndStopServices(){
$services = Get-MyServices ;
 $groups_array = Get-SDDL-Group($groups);

 foreach ($s in $services){
  $sddl = cmd /c sc sdshow $s.PSChildName
 
  foreach ($g in $groups_array){
  if( ($sddl -match "RP[A-Z]*?;;;$g") -and ($sddl -match "WP[A-Z]*?;;;$g") ){
  Write-Output ($s.PSChildName)
  }
  }
 }
}

Write-Output ("#############")
Write-Output ("Can Start")
Write-Output ("#############")
   
Get-CanStartServices

Write-Output ("#############")
Write-Output ("Can Stop")
Write-Output ("#############")
   

Get-CanStopServices

Write-Output ("#############")
Write-Output ("Can Start and Stop")
Write-Output ("#############")
   
Get-CanStartAndStopServices

 
