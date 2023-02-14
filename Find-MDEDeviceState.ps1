function Find-MDEDeviceState {
	<#
	.SYNOPSIS
		Find MDE device state

	.DESCRIPTION
		Find the MDE onboarding state of a device

	.PARAMETER ComputerName
		Name of computer or computers you want to search

	.PARAMETER DisableProgressBar
		Disables the progress bar

	.PARAMETER LoggingPath
		Log file path

	.PARAMETER FailureLoggingPath
		Failure log path

	.PARAMETER SaveResults
		Save results to file

	.PARAMETER ShowResults
		Display results to the console

	.EXAMPLE
		Find-MDEDeviceState -DisableProgressBar

		This will disable the progress bar in the UI

	.EXAMPLE
		Find-MDEDeviceState -ComputerName MachineOne, MachineTwo

		This will query for both MachineOne and MachineTwo

	.EXAMPLE
		Find-MDEDeviceState -Verbose

		This will run the script in verbose mode

	.EXAMPLE
		Find-MDEDeviceState -ShowResults

		Display search results to the console

	.EXAMPLE
		Find-MDEDeviceState -SaveResults

		Query for MDE information and save results to disk

	.NOTES
		Data is saved to the $env:Temp location of the user that executed the script
	#>


	[CmdletBinding()]
	[OutputType('System.String')]
	[OutputType('System.IO.File')]
	param(
		[object[]]
		$ComputerName,

		[switch]
		$DisableProgressBar,

		[string]
		$LoggingPath = "$env:Temp\MDEOnboardingState.csv",

		[string]
		$FailureLoggingPath = "$env:Temp\FailedConnections.csv",

		[switch]
		$SaveResults,

		[switch]
		$ShowResults
	)

	begin {
		Write-Output "Starting MDE discovery process"
		$parameters = $PSBoundParameters
		$successfulConnectionsFound = 0
		$failedConnectionsFound = 0
		[System.Collections.ArrayList]$computerObjects = @()
		[System.Collections.ArrayList]$failedConnections = @()
	}

	process {
		try {
			if (-NOT ($ComputerName)) {
				Write-Verbose "No computer name passed in. Retrieving full domain computer list"
				$computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name -ErrorAction Stop
			}
			else {
				$computers = $ComputerName
			}

			foreach ($computer in $computers) {
				if (-NOT ($parameters.ContainsKey('DisableProgressBar'))) {
					$policyCounter ++
					Write-Progress -Activity "Querying: $computer. Total computers found: $($computers.Count)" -Status "Querying computer list #: $progressCounter" -PercentComplete ($progressCounter / $computers.count * 100)
					$progressCounter ++
				}
				else {
					Write-Verbose "Progress bar has been disabled"
				}

				if (-NOT ($connection = Invoke-Command -ComputerName $computer -ScriptBlock { Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Advanced Threat Protection" } -ErrorAction SilentlyContinue -ErrorVariable FailedConnection)) {
					$failure = [PSCustomObject]@{
						MachineName = $computer
						ErrorId     = $FailedConnection.FullyQualifiedErrorId
						Exception   = $FailedConnection.Exception.Message
					}
					$failedConnectionsFound ++
					$null = $failedConnections.Add($failure)
				}
				else {
					$data = $connection.OnboardedInfo -split ','
					if (($data[0] -split '\"')[5] -ne ':[]') { $previousOrgID = ($data[0] -split '\"')[5] } else { $previousOrgID = "No previous orgId".ToString() }
					if (($data[1] -split '\"')[3] -match '(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})') { $orgId = $matches[0] } else { $orgId = "No orgId".ToString() }
					if (($data[2] -split '\"')[3] -match '((http[s]?)(:\/\/)([^\s,]+))') { $geoLocationUrl = $matches[0] } else { $geoLocationUrl = "No geoLocationUrl" }
					if (($data[3] -split '\"')[3] -match '([a-zA-Z0-9]+)') { $dataCenter = $matches[0] } else { $dataCenter = "No dataCenter location" }
					if (($data[4] -split '\"')[3] -match '([a-zA-Z0-9]+)') { $geoLocation = $matches[0] } else { $geoLocation = "No geoLocation" }

					$machineInfo = [PSCustomObject]@{
						MachineName      = $computer
						SenseGuid        = $connection.senseGuid
						SenseId          = $connection.senseId
						DataCenter       = $dataCenter
						PreviousOrgID    = $previousOrgID
						OrgId            = $orgId
						GeoLocation      = $geoLocation
						GeoLocationUrl   = $geoLocationUrl.TrimEnd('/\')
						DiagtrackService = 'N/A'
						SenseService     = 'N/A'
					}

					try {
						# Service checks
						$services = @('diagtrack', 'sense')
						foreach ($service in $services) {
							Write-Verbose "Checking state of $($service) service"
							Start-Process -FilePath "C:\Windows\System32\sc.exe" -ArgumentList "qc $($service)" -NoNewWindow -RedirectStandardOutput "$env:Temp\$($service).txt" -Wait -ErrorAction SilentlyContinue
							$scStatus = Get-Content "$env:Temp\$($service).txt"
							if ((($scStatus -replace '\s+')[4] -split '([0-9]{1})')[2] -eq 'AUTO_START') {
								Write-Verbose "$($service) Service check: GOOD"
								if ($services -eq 'diagtrack') { $machineInfo.DiagtrackService = "Service check: GOOD".ToString() }
								if ($services -eq 'sense') { $machineInfo.SenseService = "Service check: GOOD".ToString() }
							}
							else {
								Write-Verbose "ERROR: $($service) service check: failed! Service is not set to AUTO_START. Please run: sc config $($service) start=auto"
								if ($services -eq 'diagtrack') { $machineInfo.DiagtrackService = "Service check: Failed!".ToString() }
								if ($services -eq 'sense') { $machineInfo.SenseService = "Service check: Failed!".ToString() }
							}
						}
					}
					catch {
						Write-Output "Error: $_"
					}

					$successfulConnectionsFound ++
					$null = $computerObjects.Add($machineInfo)
				}
			}

			if ($parameters.ContainsKey('ShowResults')) {
				$computerObjects | Select-Object MachineName, SenseGuid, SenseId, DataCenter, PreviousOrgID, OrgId, GeoLocation, GeoLocationUrl, DiagtrackService, SenseService | Sort-Object -Property MachineName
			}
		}
		catch {
			Write-Output "Error: $_"
		}

		try {
			if ($parameters.ContainsKey('SaveResults')) {
				[PSCustomObject]$computerObjects | Export-Csv -Path $LoggingPath -ErrorAction Stop -Encoding UTF8 -NoTypeInformation -Append
				[PSCustomObject]$failedConnections | Export-Csv -Path $FailureLoggingPath -ErrorAction Stop -Encoding UTF8 -NoTypeInformation -Append
			}
		}
		catch {
			Write-Output "Error: $_"
		}
	}

	end {
		Write-Output "There were $($successfulConnectionsFound) successful connections"
		Write-Output "There were $($failedConnectionsFound) failed connections"
		if ($parameters.ContainsKey('SaveResults')) {
			Write-Output "Saving data to $($LoggingPath)"
			Write-Output "Saving failed connection data to $($FailureLoggingPath)"
		}
		Write-Output "MDE discovery process completed!`r`nFor more information on troubleshooting MDE onboarding issues please see: https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/troubleshoot-onboarding?view=o365-worldwide"
	}
}
