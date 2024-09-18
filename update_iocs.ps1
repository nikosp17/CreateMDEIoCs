# M365 custom indicator guidlines
# IndicatorType,IndicatorValue,ExpirationTime,Action,Severity,Title,Description,RecommendedActions,RbacGroups,Category,MitreTechniques,GenerateAlert

#-------------------------------------------------------EXAMPLES-------------------------------------------------------------------------------------
# FileSha1,deadbeafb263b10b284405889fb25dcc3bf1aebb,2018-09-16T12:11:06.2446367Z,BlockAndRemediate,Informational,"File SHA1 custom TI example","malware downloader","Recommended actions should be here","GroupName1,GroupName2,GroupName3","SuspiciousActivity","T0000,T0001,T0002",true
# FileSha256,deadbeafd034a66599407e2fa2ccaf15d11f1079fc0d012bb7b2b8ce66673689,,Audit,Low,File SHA256 custom TI example,"Red Team Activity","Recommended actions should be here","GroupName1","Discovery","T1046",true
# IpAddress,10.10.10.10,2018-09-16T12:11:06.2446367Z,Allowed,Informational,"Ip Address custom TI example","malware downloader","Recommended actions should be here","","","",false
# Url,http://www.facebook.com,2018-09-16T12:11:06.2446367Z,Block,Informational,"Url custom TI example","malware downloader","Recommended actions should be here","","","",true
# DomainName,www.facebook.com,,Audit,Low,Domain custom TI example,"Red Team Activity","Recommended actions should be here","","None","",true

function identifyIndicator([string]$indicator) {
    $sha1HashPattern = '^[0-9a-fA-F]{40}$'
    $sha256HashPattern = '^[0-9a-fA-F]{64}$'
    $ipAddressPattern = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    $urlPattern = '^(https?|ftp):\/\/[^\s/$.?#].[^\s]*$'
    $domainPattern = '^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$'

    if ($indicator -match $sha1HashPattern) {
            return 'FileSha1,' + $indicator + ',"",BlockAndRemediate,High,"Malicious file(s) - Custom Detection","This file has been identified to exhibit malicious behavior.","Investigate the malicious file within the context of the environment where it was detected, considering the user, workstation, and any impacted resources.","","Execution","",true'
    }
    elseif ($indicator -match $sha256HashPattern) {
        return 'FileSha256,' + $indicator + ',"",BlockAndRemediate,High,"Malicious file(s) - Custom Detection","This file has been identified to exhibit malicious behavior.","Investigate the malicious file within the context of the environment where it was detected, considering the user, workstation, and any impacted resources.","","Execution","",true'
    }
    elseif ($indicator -match $ipAddressPattern) {
        return 'IpAddress,' + $indicator + ',"",Block,High,"Malicious IP - Custom Detection","This IP has been associated with malicious activity.","Investigate the malicious IP address within the context of the environment where it was detected, taking into account the user, workstation, and any affected resources.","","SuspiciousActivity","",true'
    }
    elseif ($indicator -match $urlPattern) {
        return 'Url,' + $indicator + ',"",Block,High,"Malicious URL - Custom Detection","This URL has been associated with malicious activity.","Investigate the malicious Domain within the context of the environment where it was detected, taking into account the user, workstation, and any affected resources.","","SuspiciousActivity","",true'
    }
    elseif ($indicator -match $domainPattern) {
        return 'DomainName,' + $indicator + ',"",Block,High,"Malicious Domain - Custom Detection","This Domain has been associated with malicious activity.","Inspect the malicious domain in the context of the environment in which it has appeared (user, workstation)","","SuspiciousActivity","",true'
    }
    else {
        Write-Output $indicator
        return "Unknown indicator type"
    }   
}

$importFilePath = Read-Host -Prompt "Enter the import file path"
$exportFilePath = Read-Host -Prompt "Enter the export file path"

$content = Get-Content $importFilePath

# Create an empty array to store the modified lines
$modifiedLines = @()

# Iterate through each line of the file
foreach ($line in $content) {
    # Join the remaining elements of the array back into a string with a tab delimiter
    $newLine = identifyIndicator($line)
    if ($newLine -eq "Unknown indicator type"){
        continue
    }else{
        $modifiedLines += $newLine
    }
}
# Save the modified lines to a new file
$modifiedLines | Out-File $exportFilePath




