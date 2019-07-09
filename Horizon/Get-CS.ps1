$hvServer = Connect-HVServer -Server hzn-79-cs1-cdh.betavmweuc.com -User chalstead -Password Sp**dR@cer19 -Domain betavmweuc.com
$Global:hvServices = $hvServer.ExtensionData
$csService = New-Object VMware.Hv.ConnectionServerService
$csList = $csService.ConnectionServer_List($hvServices)
foreach ($info in $csList) {
   Write-Host $info.general.name 
}