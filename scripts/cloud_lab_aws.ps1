# AWS SOAR — lab deploy / test / shutdown (PowerShell)
# Chạy 1 phát (dry-run + remediation thật trên EC2 lab):
#   .\scripts\cloud_lab_aws.ps1 -Phase all -AlertEmail "you@email.com"
# Chỉ dry-run: .\scripts\cloud_lab_aws.ps1 -Phase all -AlertEmail "..." -SkipRealRemediation
# Dọn tiền:     .\scripts\cloud_lab_aws.ps1 -Phase shutdown -AlertEmail "you@email.com"

param(
    [ValidateSet("preflight", "bootstrap", "deploy", "verify", "dryrun", "real", "benchmark", "logs", "all", "shutdown")]
    [string]$Phase = "all",
    [Parameter(Mandatory = $false)]
    [string]$AlertEmail = "",
    [string]$Region = "us-east-1",
    [int]$Runs = 5,
    [switch]$SkipRealRemediation
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$TfDir = Join-Path $Root "terraform"
$Fn = "soar-incident-responder"
$LogGroup = "/aws/lambda/$Fn"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[FAIL] $msg" -ForegroundColor Red; throw $msg }

# AWS CLI on PowerShell writes stderr on 404 → must not use $ErrorActionPreference Stop
function Invoke-AwsCli {
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]]$AwsArgs
    )
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $output = & aws @AwsArgs 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $_.ToString() } else { $_ }
    }
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prevEap
    return [pscustomobject]@{
        ExitCode = $code
        Output   = ($output | Out-String).Trim()
    }
}

function Test-AwsCliSuccess {
    param($Result, [string]$Step)
    if ($Result.ExitCode -ne 0) {
        Write-Fail "$Step failed (exit $($Result.ExitCode)): $($Result.Output)"
    }
}

function Test-S3BucketExists {
    param([string]$BucketName)
    $r = Invoke-AwsCli s3api head-bucket --bucket $BucketName --region $Region
    return ($r.ExitCode -eq 0)
}

function Test-DynamoTableExists {
    param([string]$TableName)
    $r = Invoke-AwsCli dynamodb describe-table --table-name $TableName --region $Region
    return ($r.ExitCode -eq 0)
}

function Get-LabContext {
    $env:AWS_DEFAULT_REGION = $Region
    $identity = aws sts get-caller-identity | ConvertFrom-Json
    $accountId = $identity.Account
    @{
        Region     = $Region
        AccountId  = $accountId
        Bucket     = "soar-tf-state-prod-$accountId"
        LockTable  = "terraform-lock-prod-$accountId"
        BackendHcl = Join-Path $TfDir "backend.generated.hcl"
    }
}

function Test-Preflight {
    param([string]$Email)
    Write-Step "Preflight checks"
    if (-not (Get-Command aws -ErrorAction SilentlyContinue)) { Write-Fail "Thieu AWS CLI" }
    if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) { Write-Fail "Thieu Terraform" }
    $ctx = Get-LabContext
    aws sts get-caller-identity | Out-Null
    Write-Ok "AWS auth OK — account $($ctx.AccountId)"
    if ($Phase -in @("deploy", "all", "shutdown") -and -not $Email) {
        Write-Fail "Can -AlertEmail (SNS subscription). Vi du: -AlertEmail tht.csec2005@gmail.com"
    }
    if ($Email -and $Email -notmatch "^[^@]+@[^@]+\.[^@]+$") {
        Write-Fail "AlertEmail khong hop le: $Email"
    }
    if (-not (Test-Path $TfDir)) { Write-Fail "Khong tim thay $TfDir" }
    Write-Ok "Region lab: $Region (Console phai chon N. Virginia neu us-east-1)"
    Write-Ok "Preflight passed"
    return $ctx
}

function Initialize-Backend {
    param($Ctx)
    Write-Step "Bootstrap Terraform backend (S3 + DynamoDB)"
    $bucket = $Ctx.Bucket
    $table = $Ctx.LockTable

    if (Test-S3BucketExists -BucketName $bucket) {
        Write-Ok "S3 bucket da ton tai: $bucket"
    }
    else {
        Write-Host "Tao S3 bucket: $bucket"
        if ($Region -eq "us-east-1") {
            Test-AwsCliSuccess (Invoke-AwsCli s3api create-bucket --bucket $bucket --region $Region) "create-bucket"
        }
        else {
            Test-AwsCliSuccess (Invoke-AwsCli s3api create-bucket --bucket $bucket --region $Region `
                --create-bucket-configuration LocationConstraint=$Region) "create-bucket"
        }
        Test-AwsCliSuccess (Invoke-AwsCli s3api put-bucket-versioning --bucket $bucket `
            --versioning-configuration Status=Enabled) "bucket-versioning"
        $encFile = Join-Path $env:TEMP "soar-s3-enc-$bucket.json"
        @'
{
  "Rules": [{
    "ApplyServerSideEncryptionByDefault": {
      "SSEAlgorithm": "AES256"
    }
  }]
}
'@ | Set-Content -Path $encFile -Encoding utf8NoBOM
        $encUri = "file://" + ($encFile -replace '\\', '/')
        Test-AwsCliSuccess (Invoke-AwsCli s3api put-bucket-encryption --bucket $bucket `
            --server-side-encryption-configuration $encUri) "bucket-encryption"
        Write-Ok "S3 bucket created"
    }

    if (Test-DynamoTableExists -TableName $table) {
        Write-Ok "DynamoDB lock table da ton tai: $table"
    }
    else {
        Write-Host "Tao DynamoDB table: $table"
        Test-AwsCliSuccess (Invoke-AwsCli dynamodb create-table `
            --table-name $table `
            --attribute-definitions "AttributeName=LockID,AttributeType=S" `
            --key-schema "AttributeName=LockID,KeyType=HASH" `
            --billing-mode PAY_PER_REQUEST `
            --region $Region) "create-table"
        Write-Host "Doi table ACTIVE..."
        Test-AwsCliSuccess (Invoke-AwsCli dynamodb wait table-exists --table-name $table --region $Region) "wait table"
        Write-Ok "DynamoDB table created"
    }
    @"
bucket         = "$bucket"
key            = "aws-soar/terraform.tfstate"
region         = "$Region"
encrypt        = true
dynamodb_table = "$table"
"@ | Set-Content -Path $Ctx.BackendHcl -Encoding utf8
    Write-Ok "Backend config: $($Ctx.BackendHcl)"
}

function Initialize-Terraform {
    param($Ctx)
    Write-Step "terraform init (backend account-scoped)"
    Push-Location $TfDir
    try {
        terraform init -input=false -reconfigure -backend-config="backend.generated.hcl"
        if ($LASTEXITCODE -ne 0) { Write-Fail "terraform init failed" }
        Write-Ok "terraform init OK"
    }
    finally {
        Pop-Location
    }
}

function Invoke-Deploy {
    param([string]$Email, $Ctx)
    Write-Step "Build Lambda package (src/ + deps)"
    & (Join-Path $Root "scripts\build_lambda_package.ps1")
    if ($LASTEXITCODE -ne 0) { Write-Fail "build_lambda_package.ps1 failed" }
    Write-Step "terraform apply"
    Push-Location $TfDir
    try {
        terraform apply -auto-approve -var="alert_email=$Email"
        if ($LASTEXITCODE -ne 0) { Write-Fail "terraform apply failed" }
        Write-Ok "Apply complete"
        terraform output
        Write-Warn "Kiem tra email SNS (Confirm subscription) neu chua bam link"
    }
    finally {
        Pop-Location
    }
}

function Invoke-Verify {
    Write-Step "Verify Lambda + EC2 lab"
    aws lambda get-function --function-name $Fn --region $Region `
        --query "Configuration.{Name:FunctionName,Runtime:Runtime,Handler:Handler,State:State}" --output table
    Push-Location $TfDir
    try {
        $ec2 = terraform output -raw target_ec2_id
        aws ec2 describe-instances --instance-ids $ec2 --region $Region `
            --query "Reservations[0].Instances[0].{Id:InstanceId,State:State.Name,Name:Tags[?Key=='Name']|[0].Value}" --output table
    }
    finally { Pop-Location }
}

function Get-LivePayloadPath {
    Push-Location $TfDir
    try {
        $ec2 = terraform output -raw target_ec2_id
        $payload = Get-Content (Join-Path $TfDir "test-event.json") -Raw | ConvertFrom-Json
        $payload.detail.resources[0].instanceDetails.instanceId = $ec2
        $tmp = Join-Path $TfDir "test-event-live.json"
        $payload | ConvertTo-Json -Depth 20 | Set-Content $tmp -Encoding utf8
        return $tmp
    }
    finally { Pop-Location }
}

function Get-LambdaResponseBody {
    param([string]$JsonPath)
    $raw = Get-Content $JsonPath -Raw | ConvertFrom-Json
    $payload = $raw
    if ($null -ne $raw.statusCode) {
        $payload = $raw.body
        if ($payload -is [string]) {
            $payload = $payload | ConvertFrom-Json
        }
    }
    return $payload
}

function Invoke-DryRun {
    Write-Step "Invoke dry-run (planned_actions, EC2 khong doi)"
    $null = Get-LivePayloadPath
    Push-Location $TfDir
    try {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        Test-AwsCliSuccess (Invoke-AwsCli lambda invoke --function-name $Fn --region $Region `
            --payload "file://test-event-live.json" `
            --cli-binary-format raw-in-base64-out out-dryrun.json) "lambda invoke dry-run"
        $sw.Stop()
        Write-Ok "Invoke wall: $([math]::Round($sw.Elapsed.TotalMilliseconds, 2)) ms"
        $raw = Get-Content (Join-Path $TfDir "out-dryrun.json") -Raw | ConvertFrom-Json
        if ($raw.errorMessage) { Write-Fail "Lambda loi: $($raw.errorMessage)" }
        $body = Get-LambdaResponseBody (Join-Path $TfDir "out-dryrun.json")
        if ($body.mode -ne "dry_run") {
            if ($body.status -eq "ignored") {
                Write-Fail "Pipeline IGNORE (risk=$($body.risk_score)) — can LAB_MOCK_INTEL tren Lambda"
            }
            Write-Warn "Khong thay mode=dry_run — xem out-dryrun.json"
        }
        else {
            $count = @($body.planned_actions).Count
            Write-Ok "mode=dry_run, playbook=$($body.playbook), actions=$count"
        }
        Get-Content out-dryrun.json
    }
    finally { Pop-Location }
}

function Invoke-Benchmark {
    Write-Step "Benchmark dry-run x$Runs"
    $null = Get-LivePayloadPath
    Push-Location $TfDir
    try {
        $rows = @()
        for ($i = 1; $i -le $Runs; $i++) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            Test-AwsCliSuccess (Invoke-AwsCli lambda invoke --function-name $Fn --region $Region `
                --payload "file://test-event-live.json" `
                --cli-binary-format raw-in-base64-out "out-bench-$i.json") "lambda invoke bench $i"
            $sw.Stop()
            $ms = [math]::Round($sw.ElapsedMilliseconds, 2)
            $rows += [pscustomobject]@{ Run = $i; InvokeMs = $ms }
            Write-Host "  Run $i : $ms ms"
        }
        $avg = [math]::Round(($rows.InvokeMs | Measure-Object -Average).Average, 2)
        Write-Ok "Average invoke: $avg ms — ghi vao Bang 4.2"
        $rows | Format-Table -AutoSize
    }
    finally { Pop-Location }
}

function Invoke-Real {
    Write-Step "REAL remediation tren EC2 lab (stop + isolate)"
    Push-Location $TfDir
    try {
        $ec2 = terraform output -raw target_ec2_id
        $payload = Get-Content (Join-Path $TfDir "test-event-real.json") -Raw
        $payload = $payload -replace "REPLACE_WITH_TERRAFORM_OUTPUT_target_ec2_id", $ec2
        Set-Content (Join-Path $TfDir "test-event-real-live.json") $payload -Encoding utf8
        Test-AwsCliSuccess (Invoke-AwsCli lambda invoke --function-name $Fn --region $Region `
            --payload "file://test-event-real-live.json" `
            --cli-binary-format raw-in-base64-out out-real.json) "lambda invoke real"
        Get-Content out-real.json
        $body = Get-LambdaResponseBody (Join-Path $TfDir "out-real.json")
        if ($body.mode -eq "dry_run") {
            Write-Warn "Van o che do dry_run — kiem tra payload test-event-real.json"
        }
        elseif ($body.status -eq "ignored") {
            Write-Fail "Remediation khong chay — decision IGNORE, risk=$($body.risk_score)"
        }
        elseif ($body.status -eq "executed" -or $body.status -eq "completed") {
            Write-Ok "Remediation thuc thi: status=$($body.status), incident=$($body.incident_id)"
        }
        elseif ($body.playbook) {
            Write-Ok "Remediation: playbook=$($body.playbook), mode=$($body.mode)"
        }
        else {
            Write-Fail "Khong thay ket qua remediation — xem out-real.json"
        }
        $ec2State = Invoke-AwsCli ec2 describe-instances --instance-ids $ec2 --region $Region `
            --query "Reservations[0].Instances[0].{State:State.Name,SG:SecurityGroups[*].GroupId}" --output table
        Write-Host $ec2State.Output
    }
    finally { Pop-Location }
}

function Show-Logs {
    Write-Step "CloudWatch Logs"
    aws logs tail $LogGroup --region $Region --since 30m --format short
    Write-Step "Lambda REPORT (duration)"
    aws logs filter-log-events --log-group-name $LogGroup --region $Region `
        --filter-pattern "REPORT" --limit 5 --query "events[*].message" --output text
}

function Invoke-Shutdown {
    param([string]$Email, $Ctx)
    Write-Step "terraform destroy (ngung tinh tien EC2/Lambda/VPC...)"
    Push-Location $TfDir
    try {
        if (-not (Test-Path ".terraform")) {
            Initialize-Terraform $Ctx
        }
        terraform destroy -auto-approve -var="alert_email=$Email"
        if ($LASTEXITCODE -ne 0) { Write-Fail "terraform destroy failed" }
        Write-Ok "Destroy complete — chi con S3 state bucket + DynamoDB lock (phi ~$0)"
        Write-Host "State bucket: $($Ctx.Bucket) (co the xoa tay neu muon)"
    }
    finally { Pop-Location }
}

# --- Main ---
$ctx = $null
switch ($Phase) {
    "preflight" { $null = Test-Preflight -Email $AlertEmail }
    "bootstrap" {
        $ctx = Test-Preflight -Email $AlertEmail
        Initialize-Backend $ctx
        Initialize-Terraform $ctx
    }
    "deploy" {
        $ctx = Test-Preflight -Email $AlertEmail
        Initialize-Backend $ctx
        Initialize-Terraform $ctx
        Invoke-Deploy -Email $AlertEmail -Ctx $ctx
    }
    "verify" { Invoke-Verify }
    "dryrun" { Invoke-DryRun }
    "real" { Invoke-Real }
    "benchmark" { Invoke-Benchmark }
    "logs" { Show-Logs }
    "shutdown" {
        $ctx = Test-Preflight -Email $AlertEmail
        Invoke-Shutdown -Email $AlertEmail -Ctx $ctx
    }
    "all" {
        $ctx = Test-Preflight -Email $AlertEmail
        Initialize-Backend $ctx
        Initialize-Terraform $ctx
        Invoke-Deploy -Email $AlertEmail -Ctx $ctx
        Invoke-Verify
        Invoke-DryRun
        Invoke-Benchmark
        if (-not $SkipRealRemediation) {
            Invoke-Real
        }
        else {
            Write-Warn "Bo qua remediation that (-SkipRealRemediation)"
        }
        Show-Logs
        Write-Step "XONG — len AWS Console chup anh (xem HUONG_DAN_CHEN_WORD_VA_CLOUD_CLI.md)"
        Write-Host @"

Console (region $Region):
  1. Lambda > soar-incident-responder > Configuration (Handler handlers.lambda_handler)
  2. Lambda > Monitor > Invocations
  3. Lambda > View CloudWatch logs (AUDIT, SCORING_DECISION)
  4. EC2 > SOAR-Target-Instance (running → stopped sau remediation that)

Remediation that da chay tren EC2 lab (stop + isolate SG).
Khi xong do an:
  .\scripts\cloud_lab_aws.ps1 -Phase shutdown -AlertEmail "$AlertEmail"
"@ -ForegroundColor Yellow
    }
}
