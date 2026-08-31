Option Explicit

If WScript.Arguments.Count <> 1 Then
    WScript.Quit 87
End If

Dim shell, powershell, scriptPath, command, exitCode
Set shell = CreateObject("WScript.Shell")
powershell = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
scriptPath = WScript.Arguments.Item(0)
command = Chr(34) & powershell & Chr(34) & _
    " -NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File " & _
    Chr(34) & Replace(scriptPath, Chr(34), Chr(34) & Chr(34)) & Chr(34)

' Window style 0 prevents a console window even for an interactive task.
exitCode = shell.Run(command, 0, True)
WScript.Quit exitCode
