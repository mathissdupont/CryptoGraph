#!/usr/bin/env pwsh
<#
CryptoGraph Test Runner - Fraunhofer Backend
=============================================

Scans samples/ directory with Fraunhofer CPG backend and generates:
- Normalized graph (JSON, DOT, HTML)
- CBOM findings (JSON)
- HTML report with findings

This script uses Docker Compose to ensure all dependencies are available.
#>

param(
    [string]$Backend = "fraunhofer",
    [string]$Mode = "scan",  # scan, graph, or both
    [switch]$Strict
)

$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputDir = Join-Path $ProjectRoot "output"
$SamplesDir = Join-Path $ProjectRoot "samples"

Write-Host "CryptoGraph Test Suite" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan
Write-Host ""

# Ensure output directory exists
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir | Out-Null
}

# Build backend flag
$BackendFlag = $Backend
if ($Strict) {
    $BackendFlag = "fraunhofer-strict"
}

Write-Host "Configuration:" -ForegroundColor Green
Write-Host "  Backend: $BackendFlag"
Write-Host "  Samples: $SamplesDir"
Write-Host "  Output: $OutputDir"
Write-Host ""

# Test 1: Scan samples and generate CBOM
if ($Mode -eq "scan" -or $Mode -eq "both") {
    Write-Host "[1/3] Scanning samples with cryptographic analysis..." -ForegroundColor Yellow
    
    $Cmd = @(
        "docker", "compose", "run", "--rm", "cryptograph",
        "scan",
        "--input", "/app/samples",
        "--output", "/app/output/result.json",
        "--backend", $BackendFlag
    )
    
    Write-Host "Running: $($Cmd -join ' ')" -ForegroundColor Gray
    & $Cmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ CBOM generation successful" -ForegroundColor Green
        
        $ResultPath = Join-Path $OutputDir "result.json"
        if (Test-Path $ResultPath) {
            $ResultFile = Get-Item $ResultPath
            $FileSizeKB = [Math]::Round($ResultFile.Length / 1KB, 2)
            Write-Host "  Result file: $($ResultFile.FullName) ($FileSizeKB KB)" -ForegroundColor Gray
            
            # Count findings
            $ResultJson = Get-Content $ResultFile.FullName -Raw | ConvertFrom-Json
            $FindingCount = $ResultJson.cryptographic_assets.Count
            Write-Host "  Total findings: $FindingCount" -ForegroundColor Cyan
        }
    } else {
        Write-Host "✗ CBOM generation failed" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
}

# Test 2: Generate CPG visualization
if ($Mode -eq "graph" -or $Mode -eq "both") {
    Write-Host "[2/3] Generating CPG graph visualization..." -ForegroundColor Yellow
    
    $Cmd = @(
        "docker", "compose", "run", "--rm", "cryptograph",
        "graph",
        "--input", "/app/samples",
        "--output", "/app/output/cpg.json",
        "--dot", "/app/output/cpg.dot",
        "--html", "/app/output/cpg.html",
        "--backend", $BackendFlag
    )
    
    Write-Host "Running: $($Cmd -join ' ')" -ForegroundColor Gray
    & $Cmd
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ CPG visualization successful" -ForegroundColor Green
        
        $CpgPath = Join-Path $OutputDir "cpg.html"
        if (Test-Path $CpgPath) {
            Write-Host "  HTML viewer: $CpgPath" -ForegroundColor Gray
        }
    } else {
        Write-Host "✗ CPG visualization failed" -ForegroundColor Red
        exit 1
    }
    
    Write-Host ""
}

# Test 3: Generate HTML report
if ($Mode -eq "scan" -or $Mode -eq "both") {
    Write-Host "[3/3] Generating HTML report..." -ForegroundColor Yellow
    
    $ResultPath = Join-Path $OutputDir "result.json"
    if (Test-Path $ResultPath) {
        $Cmd = @(
            "docker", "compose", "run", "--rm", "cryptograph",
            "report",
            "--input", "/app/output/result.json",
            "--output", "/app/output/report.html"
        )
        
        Write-Host "Running: $($Cmd -join ' ')" -ForegroundColor Gray
        & $Cmd
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ Report generation successful" -ForegroundColor Green
            
            $ReportPath = Join-Path $OutputDir "report.html"
            if (Test-Path $ReportPath) {
                Write-Host "  Report file: $ReportPath" -ForegroundColor Gray
            }
        } else {
            Write-Host "✗ Report generation failed" -ForegroundColor Red
        }
    }
    
    Write-Host ""
}

# Summary
Write-Host "Test Summary:" -ForegroundColor Green
Write-Host "=============" -ForegroundColor Green
Write-Host ""
Write-Host "Output artifacts:" -ForegroundColor Cyan
Get-ChildItem -Path $OutputDir -File |
    Sort-Object -Property LastWriteTime -Descending |
    Select-Object -First 20 |
    ForEach-Object { Write-Host "  $($_.FullName -replace [regex]::Escape($ProjectRoot), '.')" -ForegroundColor Gray }

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Yellow
Write-Host "  1. Open HTML report: start $(Join-Path $OutputDir 'report.html')"
Write-Host "  2. View CPG graph: start $(Join-Path $OutputDir 'cpg.html')"

Write-Host ""
Write-Host "Test completed successfully!" -ForegroundColor Green
