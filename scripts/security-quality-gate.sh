#!/bin/bash

# =============================================================================
# Security Quality Gate Script
# Analiza todos los reportes JSON de herramientas SAST y bloquea el pipeline
# si se superan los umbrales de vulnerabilidades críticas/altas
# =============================================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuración de umbrales (modificar según necesidades)
MAX_CRITICAL=0
MAX_HIGH=2
MAX_MEDIUM=10
BLOCK_ON_SECRETS=true
BLOCK_ON_CRITICAL_DEPS=true

# Contadores globales
TOTAL_CRITICAL=0
TOTAL_HIGH=0
TOTAL_MEDIUM=0
TOTAL_LOW=0
TOTAL_SECRETS=0
GATE_FAILED=false

echo -e "${BLUE}🔒 Security Quality Gate Analysis${NC}"
echo "=================================================="

# Función para logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Función para analizar Bandit
analyze_bandit() {
    local file="bandit-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing Bandit results..."
        
        local high=$(jq -r '.results[] | select(.issue_severity == "HIGH") | .issue_severity' "$file" 2>/dev/null | wc -l || echo 0)
        local medium=$(jq -r '.results[] | select(.issue_severity == "MEDIUM") | .issue_severity' "$file" 2>/dev/null | wc -l || echo 0)
        local low=$(jq -r '.results[] | select(.issue_severity == "LOW") | .issue_severity' "$file" 2>/dev/null | wc -l || echo 0)
        
        TOTAL_HIGH=$((TOTAL_HIGH + high))
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + medium))
        TOTAL_LOW=$((TOTAL_LOW + low))
        
        echo "  - High: $high, Medium: $medium, Low: $low"
    else
        log_warning "Bandit report not found: $file"
    fi
}

# Función para analizar Semgrep
analyze_semgrep() {
    local file="semgrep-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing Semgrep results..."
        
        local error=$(jq -r '.results[] | select(.extra.severity == "ERROR") | .extra.severity' "$file" 2>/dev/null | wc -l || echo 0)
        local warning=$(jq -r '.results[] | select(.extra.severity == "WARNING") | .extra.severity' "$file" 2>/dev/null | wc -l || echo 0)
        local info=$(jq -r '.results[] | select(.extra.severity == "INFO") | .extra.severity' "$file" 2>/dev/null | wc -l || echo 0)
        
        TOTAL_HIGH=$((TOTAL_HIGH + error))
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + warning))
        TOTAL_LOW=$((TOTAL_LOW + info))
        
        echo "  - Error: $error, Warning: $warning, Info: $info"
    else
        log_warning "Semgrep report not found: $file"
    fi
}

# Función para analizar Safety
analyze_safety() {
    local file="safety-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing Safety results..."
        
        local critical=$(jq -r '.vulnerabilities[]? | select(.severity == "CRITICAL") | .severity' "$file" 2>/dev/null | wc -l || echo 0)
        local high=$(jq -r '.vulnerabilities[]? | select(.severity == "HIGH") | .severity' "$file" 2>/dev/null | wc -l || echo 0)
        local medium=$(jq -r '.vulnerabilities[]? | select(.severity == "MEDIUM") | .severity' "$file" 2>/dev/null | wc -l || echo 0)
        local low=$(jq -r '.vulnerabilities[]? | select(.severity == "LOW") | .severity' "$file" 2>/dev/null | wc -l || echo 0)
        
        TOTAL_CRITICAL=$((TOTAL_CRITICAL + critical))
        TOTAL_HIGH=$((TOTAL_HIGH + high))
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + medium))
        TOTAL_LOW=$((TOTAL_LOW + low))
        
        echo "  - Critical: $critical, High: $high, Medium: $medium, Low: $low"
        
        # Bloquear si hay dependencias críticas
        if [[ $BLOCK_ON_CRITICAL_DEPS == true && $critical -gt 0 ]]; then
            log_error "Critical dependency vulnerabilities found!"
            GATE_FAILED=true
        fi
    else
        log_warning "Safety report not found: $file"
    fi
}

# Función para analizar pip-audit
analyze_pip_audit() {
    local file="pip-audit-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing pip-audit results..."
        
        # pip-audit no tiene severity estándar, contamos vulnerabilidades totales
        local total_vulns=$(jq -r '.dependencies[]?.vulns[]? | .id' "$file" 2>/dev/null | wc -l || echo 0)
        
        # Asumimos que son de severidad media por defecto
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + total_vulns))
        
        echo "  - Total vulnerabilities: $total_vulns"
    else
        log_warning "pip-audit report not found: $file"
    fi
}

# Función para analizar GitLeaks
analyze_gitleaks() {
    local file="gitleaks-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing GitLeaks results..."
        
        local secrets=$(jq -r '.[]? | .RuleID' "$file" 2>/dev/null | wc -l || echo 0)
        TOTAL_SECRETS=$((TOTAL_SECRETS + secrets))
        
        echo "  - Secrets found: $secrets"
        
        # Bloquear si hay secretos y está habilitado
        if [[ $BLOCK_ON_SECRETS == true && $secrets -gt 0 ]]; then
            log_error "Secrets detected in code!"
            GATE_FAILED=true
        fi
    else
        log_warning "GitLeaks report not found: $file"
    fi
}

# Función para analizar Trivy FS
analyze_trivy_fs() {
    local file="trivy-fs-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing Trivy FS results..."
        
        local critical=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        local high=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        local medium=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        local low=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        
        TOTAL_CRITICAL=$((TOTAL_CRITICAL + critical))
        TOTAL_HIGH=$((TOTAL_HIGH + high))
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + medium))
        TOTAL_LOW=$((TOTAL_LOW + low))
        
        echo "  - Critical: $critical, High: $high, Medium: $medium, Low: $low"
    else
        log_warning "Trivy FS report not found: $file"
    fi
}

# Función para analizar Trivy Image
analyze_trivy_image() {
    local file="trivy-image-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing Trivy Image results..."
        
        local critical=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        local high=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        local medium=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "MEDIUM") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        local low=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "LOW") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
        
        TOTAL_CRITICAL=$((TOTAL_CRITICAL + critical))
        TOTAL_HIGH=$((TOTAL_HIGH + high))
        TOTAL_MEDIUM=$((TOTAL_MEDIUM + medium))
        TOTAL_LOW=$((TOTAL_LOW + low))
        
        echo "  - Critical: $critical, High: $high, Medium: $medium, Low: $low"
    else
        log_warning "Trivy Image report not found: $file"
    fi
}

# Función para mostrar resumen
show_summary() {
    echo ""
    echo "=================================================="
    echo -e "${BLUE}📊 SECURITY ANALYSIS SUMMARY${NC}"
    echo "=================================================="
    echo -e "Critical vulnerabilities: ${RED}$TOTAL_CRITICAL${NC}"
    echo -e "High vulnerabilities:     ${RED}$TOTAL_HIGH${NC}"
    echo -e "Medium vulnerabilities:   ${YELLOW}$TOTAL_MEDIUM${NC}"
    echo -e "Low vulnerabilities:      ${GREEN}$TOTAL_LOW${NC}"
    echo -e "Secrets found:            ${RED}$TOTAL_SECRETS${NC}"
    echo ""
    echo "Quality Gate Thresholds:"
    echo "- Max Critical: $MAX_CRITICAL"
    echo "- Max High: $MAX_HIGH"
    echo "- Max Medium: $MAX_MEDIUM"
    echo "- Block on Secrets: $BLOCK_ON_SECRETS"
    echo "- Block on Critical Dependencies: $BLOCK_ON_CRITICAL_DEPS"
}

# Función para evaluar quality gate
evaluate_quality_gate() {
    echo ""
    echo "=================================================="
    echo -e "${BLUE}🚦 QUALITY GATE EVALUATION${NC}"
    echo "=================================================="
    
    # Verificar umbrales
    if [[ $TOTAL_CRITICAL -gt $MAX_CRITICAL ]]; then
        log_error "Critical vulnerabilities exceed threshold: $TOTAL_CRITICAL > $MAX_CRITICAL"
        GATE_FAILED=true
    fi
    
    if [[ $TOTAL_HIGH -gt $MAX_HIGH ]]; then
        log_error "High vulnerabilities exceed threshold: $TOTAL_HIGH > $MAX_HIGH"
        GATE_FAILED=true
    fi
    
    if [[ $TOTAL_MEDIUM -gt $MAX_MEDIUM ]]; then
        log_error "Medium vulnerabilities exceed threshold: $TOTAL_MEDIUM > $MAX_MEDIUM"
        GATE_FAILED=true
    fi
    
    # Resultado final
    if [[ $GATE_FAILED == true ]]; then
        echo ""
        log_error "❌ QUALITY GATE FAILED"
        echo -e "${RED}Pipeline blocked due to security policy violations${NC}"
        echo ""
        echo "Actions required:"
        echo "1. Review and fix critical/high severity vulnerabilities"
        echo "2. Remove any hardcoded secrets from code"
        echo "3. Update vulnerable dependencies"
        echo "4. Re-run the pipeline after fixes"
        echo ""
        exit 1
    else
        echo ""
        log_success "✅ QUALITY GATE PASSED"
        echo -e "${GREEN}All security checks passed. Pipeline can continue.${NC}"
        echo ""
    fi
}

# Función principal
main() {
    # Verificar que jq está instalado
    if ! command -v jq &> /dev/null; then
        log_error "jq is required but not installed. Please install jq."
        exit 1
    fi
    
    # Analizar todos los reportes
    analyze_bandit
    analyze_semgrep
    analyze_safety
    analyze_pip_audit
    analyze_gitleaks
    analyze_trivy_fs
    analyze_trivy_image
    
    # Mostrar resumen y evaluar
    show_summary
    evaluate_quality_gate
}

# Permitir configuración via variables de entorno
MAX_CRITICAL=${MAX_CRITICAL:-0}
MAX_HIGH=${MAX_HIGH:-2}
MAX_MEDIUM=${MAX_MEDIUM:-10}
BLOCK_ON_SECRETS=${BLOCK_ON_SECRETS:-true}
BLOCK_ON_CRITICAL_DEPS=${BLOCK_ON_CRITICAL_DEPS:-true}

# Ejecutar script principal
main "$@"