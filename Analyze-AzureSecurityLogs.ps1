# Load mock Azure / Entra sign-in logs.
# In a production implementation, this data could be retrieved through Microsoft Graph or Azure Monitor / Log Analytics.

$Logs = Get-Content ".\MockData\signInLogs.json" | ConvertFrom-Json

$Results = @()

# First Check: Multiple Failed Sign-Ins
# --------------------------------------------------

$FailedLogins = $Logs | Where-Object {
    $_.Status -eq "Failed"
}

$FailedUsers = $FailedLogins |
    Group-Object User |
    Where-Object {
        $_.Count -ge 2
    }

foreach ($User in $FailedUsers) {

    $Results += [PSCustomObject]@{
        User       = $User.Name
        Detection  = "Multiple Failed Sign-Ins"
        Severity   = "High"
        Count      = $User.Count
        Description = "$($User.Count) failed sign-ins detected"
    }
}

# Second Check: Successful Login After Failed Attempts
# --------------------------------------------------

foreach ($Log in $Logs | Where-Object { $_.Status -eq "Success" }) {

    $PreviousFailures = $Logs | Where-Object {
        $_.User -eq $Log.User -and
        $_.Status -eq "Failed"
    }

    if ($PreviousFailures.Count -ge 2) {

        $Results += [PSCustomObject]@{
            User        = $Log.User
            Detection   = "Successful Login After Multiple Failures"
            Severity    = "Critical"
            Count       = $PreviousFailures.Count
            Description = "Successful authentication occurred after multiple failed attempts"
        }
    }
}

# Third Check: Unusual Geographic Location
# --------------------------------------------------

$KnownCountries = @(
    "United States",
    "Canada"
)

$UnusualLocations = $Logs | Where-Object {
    $_.Status -eq "Success" -and
    $_.Country -notin $KnownCountries
}

foreach ($Log in $UnusualLocations) {

    $Results += [PSCustomObject]@{
        User        = $Log.User
        Detection   = "Unusual Geographic Location"
        Severity    = "High"
        Count       = 1
        Description = "Successful login detected from $($Log.Country)"
    }
}

# SECURITY SUMMARY
# --------------------------------------------------

$Critical = ($Results | Where-Object {
    $_.Severity -eq "Critical"
}).Count

$High = ($Results | Where-Object {
    $_.Severity -eq "High"
}).Count

$Medium = ($Results | Where-Object {
    $_.Severity -eq "Medium"
}).Count

# RESULTS
# --------------------------------------------------

Write-Host ""
Write-Host "============================================="
Write-Host "       AZURE SECURITY LOG ANALYZER"
Write-Host "============================================="
Write-Host ""

if ($Results.Count -eq 0) {

    Write-Host "No suspicious activity detected."

}
else {

    $Results | Format-Table `
        User,
        Detection,
        Severity,
        Count,
        Description `
        -AutoSize
}

Write-Host ""
Write-Host "Security Events Detected: $($Results.Count)"
Write-Host "Critical: $Critical"
Write-Host "High:     $High"
Write-Host "Medium:   $Medium"
