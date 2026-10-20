$ErrorActionPreference = "Stop"

function Read-SecretValue {
    param([string]$Prompt)

    $secureValue = Read-Host -Prompt $Prompt -AsSecureString
    if ($secureValue.Length -eq 0) {
        return ""
    }

    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer)
    }
}

function Read-RequiredValue {
    param([string]$Prompt)

    do {
        $value = (Read-Host -Prompt $Prompt).Trim()
        if (-not $value) {
            Write-Host "This value is required."
        }
    } while (-not $value)
    return $value
}

$envPath = Join-Path $PSScriptRoot ".env"
if (Test-Path -LiteralPath $envPath) {
    $replace = Read-Host "A .env file already exists. Replace it? (y/N)"
    if ($replace -notin @("y", "Y", "yes", "YES")) {
        Write-Host "Setup cancelled; the existing .env file was not changed."
        exit 0
    }
}

Write-Host "Enter at least one AI provider key. Input is hidden."
$googleKey = Read-SecretValue "Google AI Studio API key (press Enter to skip)"
$groqKey = Read-SecretValue "Groq API key (press Enter to skip)"
if (-not $googleKey -and -not $groqKey) {
    throw "At least one AI provider API key is required."
}

$spreadsheetId = Read-RequiredValue "Google Sheets spreadsheet ID"
$credentialPath = Read-RequiredValue "Path to the Google service-account JSON key"
$credentialPath = (Resolve-Path -LiteralPath $credentialPath).Path
$serviceAccount = Get-Content -LiteralPath $credentialPath -Raw | ConvertFrom-Json
if ($serviceAccount.type -ne "service_account" -or -not $serviceAccount.client_email) {
    throw "The selected JSON file is not a valid Google service-account key."
}

Write-Host "Share the target spreadsheet with this service-account email as Editor:"
Write-Host $serviceAccount.client_email
$articlesTab = Read-Host "Newsletter results tab name [Articles]"
if (-not $articlesTab.Trim()) {
    $articlesTab = "Articles"
}
$vulnerabilitiesTab = Read-Host "CVE results tab name [Vulnerabilities]"
if (-not $vulnerabilitiesTab.Trim()) {
    $vulnerabilitiesTab = "Vulnerabilities"
}
$geminiModel = Read-Host "Gemini model [gemini-2.5-flash]"
if (-not $geminiModel.Trim()) {
    $geminiModel = "gemini-2.5-flash"
}
$groqModel = Read-Host "Groq model [llama-3.3-70b-versatile]"
if (-not $groqModel.Trim()) {
    $groqModel = "llama-3.3-70b-versatile"
}

$settings = [ordered]@{
    GOOGLE_AI_STUDIO_API_KEY          = $googleKey
    GROQ_API_KEY                      = $groqKey
    CYBERINTEL_SPREADSHEET_ID         = $spreadsheetId
    GOOGLE_APPLICATION_CREDENTIALS    = $credentialPath
    CYBERINTEL_ARTICLES_TAB           = $articlesTab.Trim()
    CYBERINTEL_VULNERABILITIES_TAB    = $vulnerabilitiesTab.Trim()
    GEMINI_MODEL                      = $geminiModel.Trim()
    GROQ_MODEL                        = $groqModel.Trim()
}
$lines = foreach ($name in $settings.Keys) {
    $encodedValue = ConvertTo-Json -InputObject ([string]$settings[$name]) -Compress
    "$name=$encodedValue"
}
[IO.File]::WriteAllLines($envPath, [string[]]$lines, [Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "Configuration saved to $envPath"
Write-Host "The .env file contains API keys in plain text. It is Git-ignored; keep it private."
Write-Host "Run: python cyberintel.py --scan-newsletters --write-sheet"
