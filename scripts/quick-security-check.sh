#!/bin/bash

# =============================================================================
# Quick Security Check Script
# Script simple para verificar vulnerabilidades críticas/altas localmente
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Configuración por defecto (puede ser sobrescrita)
MAX_CRITICAL=${MAX_CRITICAL:-0}
MAX_HIGH=${MAX_HIGH:-3}
FAIL_ON_CRITICAL=${FAIL_ON_CRITICAL:-true}
FAIL_ON_HIGH=${FAIL_ON_HIGH:-false}

echo -e "${YELLOW}🔍 Quick Security Check${NC}"
echo "=========================="

# Contadores
total_critical=0
total_high=0
should_fail=false

# Función para contar vulnerabilidades en un archivo JSON
count_vulnerabilities() {
    local file=$1
    local tool=$2
    
    if [[ ! -f "$file" ]]; then
        echo "⚠️  $tool report not found: $file"
        return
    fi
    
    echo "📋 Analyzing $tool..."
    
    case $tool in
        "Bandit")
            local high=$(jq -r '.results[] | select(.issue_severity == "HIGH") | .issue_severity' "$file" 2>/dev/null | wc -l || echo 0)
            local medium=$(jq -r '.results[] | select(.issue_severity == "MEDIUM") | .issue_severity' "$file" 2>/dev/null | wc -l || echo 0)
            echo "   High: $high, Medium: $medium"
            total_high=$((total_high + high))
            ;;
            
        "Safety")
            local critical=$(jq -r '.vulnerabilities[]? | select(.severity == "CRITICAL") | .severity' "$file" 2>/dev/null | wc -l || echo 0)
            local high=$(jq -r '.vulnerabilities[]? | select(.severity == "HIGH") | .severity' "$file" 2>/dev/null | wc -l || echo 0)
            echo "   Critical: $critical, High: $high"
            total_critical=$((total_critical + critical))
            total_high=$((total_high + high))
            ;;
            
        "Trivy")
            local critical=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "CRITICAL") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
            local high=$(jq -r '.Results[]?.Vulnerabilities[]? | select(.Severity == "HIGH") | .Severity' "$file" 2>/dev/null | wc -l || echo 0)
            echo "   Critical: $critical, High: $high"
            total_critical=$((total_critical + critical))
            total_high=$((total_high + high))
            ;;
            
        "GitLeaks")
            local secrets=$(jq -r '.[]? | .RuleID' "$file" 2>/dev/null | wc -l || echo 0)
            echo "   Secrets: $secrets"
            if [[ $secrets -gt 0 ]]; then
                echo "   ⚠️  Secrets detected!"
            fi
            ;;
    esac
}

# Analizar archivos disponibles
count_vulnerabilities "bandit-report.json" "Bandit"
count_vulnerabilities "safety-report.json" "Safety"
count_vulnerabilities "trivy-fs-report.json" "Trivy FS"
count_vulnerabilities "trivy-image-report.json" "Trivy Image"
count_vulnerabilities "gitleaks-report.json" "GitLeaks"

echo ""
echo "=========================="
echo -e "${YELLOW}📊 SUMMARY${NC}"
echo "=========================="
echo -e "Critical: ${RED}$total_critical${NC}"
echo -e "High:     ${RED}$total_high${NC}"
echo ""

# Evaluar umbrales
if [[ $total_critical -gt $MAX_CRITICAL ]]; then
    echo -e "${RED}❌ Critical vulnerabilities exceed threshold: $total_critical > $MAX_CRITICAL${NC}"
    if [[ $FAIL_ON_CRITICAL == true ]]; then
        should_fail=true
    fi
fi

if [[ $total_high -gt $MAX_HIGH ]]; then
    echo -e "${RED}❌ High vulnerabilities exceed threshold: $total_high > $MAX_HIGH${NC}"
    if [[ $FAIL_ON_HIGH == true ]]; then
        should_fail=true
    fi
fi

# Resultado final
echo ""
if [[ $should_fail == true ]]; then
    echo -e "${RED}🚫 SECURITY CHECK FAILED${NC}"
    echo "Fix critical/high vulnerabilities before proceeding"
    exit 1
else
    echo -e "${GREEN}✅ SECURITY CHECK PASSED${NC}"
    echo "Security thresholds met"
    exit 0
fi