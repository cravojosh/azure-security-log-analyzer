# Azure Security Log Analyzer

This project is intentionally designed as a simplified proof of concept and demonstrates a basic security monitoring workflow using PowerShell

This security monitoring tool is designed to analyze Azure/Entra ID sign-in activity and identify potentially suspicious authentication behavior.

The project currently uses simulated/mock sign-in log data to demonstrate the detection logic without requiring access to a live Azure or Entra ID environment however with some additional configuration could be expanded into a more robust tool used in a production environment.

## Overview

The analyzer processes sign-in events and applies basic detection rules to identify suspicious authentication activity.

`
Mock Azure / Entra Sign-In Logs
              ->
     PowerShell Log Analyzer
              ->
       Detection Rules
             ->
      Security Findings
             ->
     Severity Classification
             ->
        Security Summary
`


## Detection Rules

The current implementation checks for:

| Detection | Description | Severity |
|---|---|---|
| Multiple Failed Sign-Ins | Detects users with multiple failed authentication attempts | High |
| Successful Login After Multiple Failures | Detects successful authentication following multiple failed attempts | Critical |
| Unusual Geographic Location | Detects successful authentication from countries outside the defined trusted locations | High |

## Example Output

```text
=============================================
       AZURE SECURITY LOG ANALYZER
=============================================

User                 Detection
----                 ---------
admin@contoso.com    Multiple Failed Sign-Ins
admin@contoso.com    Successful Login After Multiple Failures
admin@contoso.com    Unusual Geographic Location

Security Events Detected: 3
Critical: 1
High:     2
Medium:   0
```

## Production Implementation

In a production implementation, the data collection layer could be replaced with Microsoft Graph or Azure Monitor / Log Analytics to retrieve actual authentication activity.
For Microsoft Graph, the primary permission required for the current sign-in log functionality would be:

`AuditLog.Read.All`

Additional permissions such as `User.Read.All` may be required if the analyzer is expanded to correlate sign-in activity with Entra ID user and directory attributes.
