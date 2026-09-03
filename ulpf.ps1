param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ScriptArgs
)

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonExe = Join-Path $ScriptDir ".venv\Scripts\python.exe"
$MainPy = Join-Path $ScriptDir "backend\app\main.py"

if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

$env:PYTHONPATH = Join-Path $ScriptDir "backend"
& $PythonExe $MainPy @ScriptArgs
