# Security Quality Gate Scripts

## 📋 Descripción

Scripts para implementar Quality Gates de seguridad que analizan los resultados de todas las herramientas SAST y bloquean el pipeline si se superan los umbrales configurados.

## 🛠️ Scripts Disponibles

### 1. `security-quality-gate.sh` - Quality Gate Completo
Script principal que analiza todos los reportes JSON y evalúa umbrales de seguridad.

**Características:**
- ✅ Analiza 7 herramientas SAST
- ✅ Umbrales configurables por severidad
- ✅ Bloqueo automático del pipeline
- ✅ Reportes detallados con colores
- ✅ Configuración via variables de entorno

### 2. `quick-security-check.sh` - Verificación Rápida
Script simplificado para verificaciones locales rápidas.

**Características:**
- ✅ Análisis rápido de vulnerabilidades críticas/altas
- ✅ Ideal para desarrollo local
- ✅ Configuración simple
- ✅ Output minimalista

### 3. `security-config.env` - Configuración
Archivo de configuración con umbrales personalizables por ambiente.

## 🚀 Uso

### En GitHub Actions (Automático)

El workflow ya incluye el Quality Gate automáticamente:

```yaml
- name: Run Security Quality Gate
  env:
    MAX_CRITICAL: 0
    MAX_HIGH: 5
    MAX_MEDIUM: 15
    BLOCK_ON_SECRETS: false
    BLOCK_ON_CRITICAL_DEPS: true
  run: ./scripts/security-quality-gate.sh
```

### Uso Local

#### Verificación Rápida:
```bash
# Ejecutar verificación básica
./scripts/quick-security-check.sh

# Con configuración personalizada
MAX_CRITICAL=0 MAX_HIGH=2 ./scripts/quick-security-check.sh
```

#### Quality Gate Completo:
```bash
# Cargar configuración y ejecutar
source scripts/security-config.env
./scripts/security-quality-gate.sh

# O con variables específicas
MAX_CRITICAL=0 MAX_HIGH=3 ./scripts/security-quality-gate.sh
```

### Pre-commit Hook

Agregar verificación automática antes de commits:

```bash
# .git/hooks/pre-commit
#!/bin/bash
echo "🔒 Running security check..."

# Ejecutar herramientas básicas
bandit -r . -f json -o bandit-report.json -ll -i || true
safety scan -r requirements.txt --output json > safety-report.json || true

# Verificar umbrales
./scripts/quick-security-check.sh

if [ $? -ne 0 ]; then
    echo "❌ Security check failed. Fix vulnerabilities before committing."
    exit 1
fi

echo "✅ Security check passed"
```

## ⚙️ Configuración

### Variables de Entorno

| Variable | Descripción | Valor por Defecto |
|----------|-------------|-------------------|
| `MAX_CRITICAL` | Máximo vulnerabilidades críticas | `0` |
| `MAX_HIGH` | Máximo vulnerabilidades altas | `5` |
| `MAX_MEDIUM` | Máximo vulnerabilidades medias | `15` |
| `BLOCK_ON_SECRETS` | Bloquear si hay secretos | `false` |
| `BLOCK_ON_CRITICAL_DEPS` | Bloquear deps críticas | `true` |
| `FAIL_ON_CRITICAL` | Fallar en críticas | `true` |
| `FAIL_ON_HIGH` | Fallar en altas | `false` |

### Configuración por Ambiente

```bash
# Desarrollo (permisivo)
export ENVIRONMENT=development
export MAX_CRITICAL=1
export MAX_HIGH=10

# Producción (estricto)  
export ENVIRONMENT=production
export MAX_CRITICAL=0
export MAX_HIGH=2
```

## 📊 Interpretación de Resultados

### Ejemplo de Output Exitoso:
```
🔒 Security Quality Gate Analysis
==================================================
[INFO] Analyzing Bandit results...
  - High: 2, Medium: 5, Low: 8
[INFO] Analyzing Safety results...
  - Critical: 0, High: 1, Medium: 2, Low: 0
[INFO] Analyzing Trivy FS results...
  - Critical: 0, High: 1, Medium: 3, Low: 5

📊 SECURITY ANALYSIS SUMMARY
==================================================
Critical vulnerabilities: 0
High vulnerabilities:     4
Medium vulnerabilities:   10
Low vulnerabilities:      13
Secrets found:            0

🚦 QUALITY GATE EVALUATION
==================================================
✅ QUALITY GATE PASSED
All security checks passed. Pipeline can continue.
```

### Ejemplo de Output Fallido:
```
🚦 QUALITY GATE EVALUATION
==================================================
[ERROR] High vulnerabilities exceed threshold: 8 > 5
[ERROR] Secrets detected in code!

❌ QUALITY GATE FAILED
Pipeline blocked due to security policy violations

Actions required:
1. Review and fix critical/high severity vulnerabilities
2. Remove any hardcoded secrets from code
3. Update vulnerable dependencies
4. Re-run the pipeline after fixes
```

## 🎯 Casos de Uso

### 1. Desarrollo Local
```bash
# Verificación rápida antes de commit
./scripts/quick-security-check.sh
```

### 2. CI/CD Pipeline
```yaml
# En GitHub Actions
- name: Security Quality Gate
  run: ./scripts/security-quality-gate.sh
```

### 3. Release Gates
```bash
# Configuración estricta para releases
export MAX_CRITICAL=0
export MAX_HIGH=0
export BLOCK_ON_SECRETS=true
./scripts/security-quality-gate.sh
```

### 4. Monitoreo Continuo
```bash
# Cron job para análisis nocturno
0 2 * * * cd /path/to/project && ./scripts/security-quality-gate.sh
```

## 🔧 Personalización

### Agregar Nueva Herramienta

Para agregar una nueva herramienta SAST:

1. Crear función de análisis:
```bash
analyze_new_tool() {
    local file="new-tool-report.json"
    if [[ -f "$file" ]]; then
        log_info "Analyzing New Tool results..."
        
        local high=$(jq -r '.results[] | select(.severity == "HIGH") | .severity' "$file" | wc -l)
        TOTAL_HIGH=$((TOTAL_HIGH + high))
        
        echo "  - High: $high"
    fi
}
```

2. Llamar función en main:
```bash
main() {
    # ... otras herramientas
    analyze_new_tool
    # ...
}
```

### Personalizar Umbrales por Herramienta

```bash
# En security-quality-gate.sh
analyze_bandit() {
    # ... análisis normal
    
    # Umbrales específicos para Bandit
    local bandit_max_high=${BANDIT_MAX_HIGH:-3}
    if [[ $high -gt $bandit_max_high ]]; then
        log_error "Bandit high issues exceed threshold: $high > $bandit_max_high"
        GATE_FAILED=true
    fi
}
```

## 📚 Referencias

- [OWASP DevSecOps Guideline](https://owasp.org/www-project-devsecops-guideline/)
- [NIST Secure Software Development Framework](https://csrc.nist.gov/Projects/ssdf)
- [GitHub Security Best Practices](https://docs.github.com/en/code-security)

## 🤝 Contribución

Para mejorar estos scripts:

1. Fork del repositorio
2. Crear branch para tu feature
3. Agregar tests si es necesario
4. Crear Pull Request

## 📄 Licencia

Estos scripts están bajo la misma licencia que VAmPI.