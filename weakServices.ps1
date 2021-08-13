function servicePathEsc{
	$services=Get-WmiObject win32_service | select Name,PathName
	$currentUser=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name


	#$paths=New-Object System.Collections.ArrayList
	$paths=$null
	$paths=@{} 
	$userArray=New-Object System.Collections.ArrayList
	$userArray.Add("Everyone") | Out-Null
	$userArray.Add("BUILTIN\Users") | Out-Null
	$userArray.add($currentUser) | Out-Null
	$userArray.Add("NT AUTHORITY\Authenticated Users") | Out-Null
	#$userArray.Add("BUILTIN\Administrators") | Out-Null
	#$userArray.Add("NT AUTHORITY\SYSTEM") | Out-Null

		

	for($c=0;$c -lt $services.count;$c++)
	{
		
		
		if($services[$c] -ne " ")
		{

			$services[$c].PathName
		  
			if($services[$c].PathName -match "([a-zA-Z0-9.\\:\\-]*.(\W))") #([a-zA-Z0-9.\\:\\-]*) [-|/]
			{
				if($services[$c].PathName -match "([a-zA-Z0-9.\\:\\-]*) -")
				{
					$serviceBinpath=($services[$c].PathName -split " -.")[0] -replace '"'
					$serviceName=$services[$c].Name

					if(!$paths.ContainsKey($serviceName))
					{
						$paths.Add($serviceName,$serviceBinpath) | Out-Null
					}
				}
				elseif($services[$c].PathName -match "([a-zA-Z0-9.\\:\\-]*) /.")
				{
			
					$serviceBinpath=($services[$c].PathName -split " /.")[0] -replace '"'
					$serviceName=$services[$c].Name

					if(!$paths.ContainsKey($serviceName))
					{
						$paths.Add($serviceName,$serviceBinpath) | Out-Null
					}
				}
				elseif($services[$c].PathName -match "([a-zA-Z0-9.\\:\\-]*.[exe|dll|msi|inf|js])")
				{
			
					$serviceBinpath=$services[$c].PathName -replace '"'
					$serviceName=$services[$c].Name
					if(!$paths.ContainsKey($serviceName))
					{
						$paths.Add($serviceName,$serviceBinpath) | Out-Null
					}
				}
			}
		}
		
		
	}


	foreach($service in $paths.GetEnumerator())
	{           
				$serviceName=$service.Key
				$serviceBinPath=$service.Value

			   
			   
				$exeFile=$serviceBinPath.Substring($serviceBinPath.LastIndexOf("\")+1)
				$stripExe=$exeFile -replace '.exe',''
				
				   
						
				foreach($user in $userArray) #Check Users' permissions
				{
										 
						   
				#Check for writable permission in the path
				  
					$writePerm=Get-Acl $serviceBinPath.Substring(0,$serviceBinPath.LastIndexOf("\")) | %{$_.Access} | where-object {$_.FileSystemRights -like "*Modify*"} | where-Object {$_.IdentityReference -eq $user}
					$writePerms=($writePerm.IdentityReference).Value
				   
					#$execPerm=Get-Acl $serviceBinPath | %{$_.Access} | where-object {$_.FileSystemRights -like "*Modify*"} | where-Object {$_.IdentityReference -eq $user}
					#$execPerms=($execPerm.IdentityReference).Value
				   
					#Check if I have writable permissions to the directory that service executable exists
					if($writePerms -eq $user)
					{
						   
							Write-Host "Vulnerable Path: "$serviceBinPath.Substring(0,$serviceBinPath.LastIndexOf("\"))
							Write-Host "Write permissions to path for : "$writePerms
							Write-Host "BinPath: "$serviceBinPath
							Write-Host "Service Name:"$serviceName
							#Write-Host "Executable can be abused by: "$execPerms
							Write-Output "`n"
					}
	 
				 }  

			   
	}<#End For#>
}	