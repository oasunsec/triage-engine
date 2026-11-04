[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CollectionDirectory,
    [Parameter(Mandatory = $true)]
    [string]$ServerUrl,
    [Parameter(Mandatory = $true)]
    [string]$IngestToken,
    [string]$CaseName
)

# Send a finished collect-windows-evidence.ps1 folder to a triage server. Use it
# directly to resend a collection when the server was unreachable at collection time.
# The folder is zipped beside itself (not inside) and streamed; the server re-checks
# every hash in collection_manifest.json before it opens the case.

$ErrorActionPreference = 'Stop'
if ($ServerUrl -notmatch '^https?://') { throw 'ServerUrl must start with http:// or https://' }
$source = [IO.Path]::GetFullPath($CollectionDirectory).TrimEnd('\')
if (-not (Test-Path -LiteralPath (Join-Path $source 'collection_manifest.json'))) {
    throw "Not a collection folder (collection_manifest.json missing): $source"
}
$archive = "$source.zip"
if (Test-Path -LiteralPath $archive) { throw "Archive already exists; remove it or keep it as the earlier copy: $archive" }

Add-Type -AssemblyName System.IO.Compression.FileSystem, System.Net.Http
[IO.Compression.ZipFile]::CreateFromDirectory($source, $archive, [IO.Compression.CompressionLevel]::Optimal, $false)
$client = New-Object System.Net.Http.HttpClient
$client.Timeout = [TimeSpan]::FromHours(4)
$client.DefaultRequestHeaders.Authorization = New-Object System.Net.Http.Headers.AuthenticationHeaderValue('Bearer', $IngestToken)
$target = $ServerUrl.TrimEnd('/') + '/api/ingest/collection'
if ($CaseName) { $target += '?case_name=' + [Uri]::EscapeDataString($CaseName) }
$stream = [IO.File]::OpenRead($archive)
try {
    $content = New-Object System.Net.Http.StreamContent($stream)
    $content.Headers.ContentType = New-Object System.Net.Http.Headers.MediaTypeHeaderValue('application/zip')
    $response = $client.PostAsync($target, $content).GetAwaiter().GetResult()
    $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
} finally { $stream.Dispose(); $client.Dispose() }
if (-not $response.IsSuccessStatusCode) { throw "Upload refused ($([int]$response.StatusCode)): $body" }
$queued = $body | ConvertFrom-Json
Write-Output "Uploaded $archive; server verified $($queued.files_verified) files and queued case '$($queued.case_name)' (job $($queued.job_id))."
