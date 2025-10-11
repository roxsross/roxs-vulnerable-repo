# Ejemplos Prácticos de Herramientas SAST

## 🛠️ Guía de Uso y Ejemplos Prácticos

Esta guía muestra cómo usar cada herramienta SAST de forma individual y cómo interpretar sus resultados.

---

## 1. 🐍 **Bandit - Ejemplos de Uso**

### Instalación y Uso Básico:
```bash
# Instalación
pip install bandit

# Análisis básico
bandit -r . -f json -o bandit-report.json

# Análisis con configuración específica
bandit -r . -ll -i -f json -o bandit-report.json
```

### Ejemplo de Salida JSON:
```json
{
  "results": [
    {
      "code": "app.run(host='0.0.0.0', port=5000, debug=True)",
      "filename": "./app.py",
      "issue_confidence": "MEDIUM",
      "issue_severity": "MEDIUM",
      "issue_text": "Possible binding to all interfaces.",
      "line_number": 17,
      "test_id": "B104",
      "test_name": "hardcoded_bind_all_interfaces"
    }
  ],
  "metrics": {
    "loc": 515,
    "nosec": 0
  }
}
```

### Interpretación:
- **test_id**: Código de la regla (B104, B105, etc.)
- **issue_severity**: HIGH, MEDIUM, LOW
- **issue_confidence**: HIGH, MEDIUM, LOW
- **line_number**: Línea exacta del problema

---

## 2. 🔎 **Semgrep - Ejemplos de Uso**

### Instalación y Uso:
```bash
# Instalación
pip install semgrep

# Análisis con rulesets específicos
semgrep --config=p/python --config=p/flask --json --output=semgrep-report.json .

# Análisis con regla personalizada
semgrep --config=custom-rules.yml --json .
```

### Ejemplo de Regla Personalizada:
```yaml
rules:
  - id: flask-debug-enabled
    patterns:
      - pattern: app.run(..., debug=True, ...)
    message: Flask debug mode enabled
    languages: [python]
    severity: ERROR
```

### Ejemplo de Salida JSON:
```json
{
  "results": [
    {
      "check_id": "python.flask.security.xss.audit.direct-use-of-jinja2",
      "path": "api_views/users.py",
      "start": {"line": 45, "col": 12},
      "end": {"line": 45, "col": 28},
      "message": "Detected direct use of jinja2",
      "severity": "WARNING",
      "extra": {
        "metadata": {
          "cwe": "CWE-79: Improper Neutralization of Input"
        }
      }
    }
  ]
}
```

---

## 3. 🔬 **CodeQL - Ejemplos de Uso**

### Instalación y Uso:
```bash
# Descargar CodeQL CLI
wget https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.tar.gz
tar -xzf codeql-linux64.tar.gz

# Crear base de datos
./codeql/codeql database create codeql-db --language=python

# Ejecutar análisis
./codeql/codeql database analyze codeql-db --format=json --output=codeql-report.json
```

### Consulta Personalizada:
```ql
import python

from Call call, Name func
where call.getFunc() = func and
      func.getId() = "eval"
select call, "Dangerous use of eval() function"
```

### Ejemplo de Salida JSON:
```json
{
  "runs": [
    {
      "results": [
        {
          "ruleId": "py/sql-injection",
          "message": {
            "text": "This SQL query is constructed from user input"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "models/user_model.py"
                },
                "region": {
                  "startLine": 72
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

---

## 4. 🛡️ **Safety - Ejemplos de Uso**

### Instalación y Uso:
```bash
# Instalación
pip install safety

# Análisis de requirements.txt
safety scan -r requirements.txt --output json > safety-report.json

# Análisis del entorno actual
safety scan --output json > safety-report.json
```

### Ejemplo de Salida JSON:
```json
{
  "report_meta": {
    "scan_target": "requirements.txt",
    "timestamp": "2025-01-10T10:30:00Z"
  },
  "vulnerabilities": [
    {
      "package_name": "flask",
      "package_version": "2.2.2",
      "vulnerability_id": "55261",
      "cve": "CVE-2023-30861",
      "severity": "HIGH",
      "advisory": "Flask 2.2.5 and 2.3.2 include a fix for CVE-2023-30861",
      "fixed_versions": ["2.2.5", "2.3.2"]
    }
  ]
}
```

---

## 5. 🔍 **pip-audit - Ejemplos de Uso**

### Instalación y Uso:
```bash
# Instalación
pip install pip-audit

# Análisis de requirements.txt
pip-audit -r requirements.txt --format=json --output=pip-audit-report.json

# Análisis del entorno actual
pip-audit --format=json --output=pip-audit-report.json
```

### Ejemplo de Salida JSON:
```json
{
  "dependencies": [
    {
      "name": "flask",
      "version": "2.2.2",
      "vulns": [
        {
          "id": "PYSEC-2023-62",
          "fix_versions": ["2.2.5", "2.3.2"],
          "description": "Flask applications using session cookies...",
          "aliases": ["CVE-2023-30861"]
        }
      ]
    }
  ]
}
```

---

## 6. 🔐 **GitLeaks - Ejemplos de Uso**

### Instalación y Uso:
```bash
# Descargar GitLeaks
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz
tar -xzf gitleaks_8.18.4_linux_x64.tar.gz

# Análisis del repositorio
./gitleaks detect --source . --report-format json --report-path gitleaks-report.json

# Análisis con configuración personalizada
./gitleaks detect --config .gitleaks.toml --report-format json --report-path gitleaks-report.json
```

### Configuración Personalizada (.gitleaks.toml):
```toml
[[rules]]
id = "flask-secret-key"
description = "Flask Secret Key"
regex = '''(?i)(secret_key|SECRET_KEY)\s*=\s*['""][^'""]{8,}['""]'''
tags = ["flask", "secret"]

[allowlist]
description = "Allowlist for test files"
files = ['''test.*\.py$''']
```

### Ejemplo de Salida JSON:
```json
[
  {
    "Description": "Flask Secret Key",
    "StartLine": 13,
    "EndLine": 13,
    "StartColumn": 1,
    "EndColumn": 40,
    "Match": "SECRET_KEY = 'hardcoded-secret'",
    "Secret": "hardcoded-secret",
    "File": "config.py",
    "RuleID": "flask-secret-key",
    "Tags": ["flask", "secret"]
  }
]
```

---

## 7. 🛡️ **Trivy - Ejemplos de Uso**

### Instalación y Uso:
```bash
# Instalación (usando Docker)
docker run --rm -v $(pwd):/workspace aquasec/trivy fs /workspace --format json --output trivy-report.json

# Análisis de dependencias
trivy fs . --format json --output trivy-report.json

# Análisis de configuraciones
trivy config . --format json --output trivy-config-report.json
```

### Ejemplo de Salida JSON:
```json
{
  "SchemaVersion": 2,
  "ArtifactName": ".",
  "ArtifactType": "filesystem",
  "Results": [
    {
      "Target": "requirements.txt",
      "Class": "lang-pkgs",
      "Type": "pip",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-30861",
          "PkgName": "flask",
          "InstalledVersion": "2.2.2",
          "FixedVersion": "2.2.5, 2.3.2",
          "Severity": "HIGH",
          "Description": "Flask applications using session cookies..."
        }
      ]
    }
  ]
}
```

---

## 📊 **Procesamiento de Resultados JSON**

### Usando jq para análisis:
```bash
# Contar vulnerabilidades por severidad en Bandit
jq '.results | group_by(.issue_severity) | map({severity: .[0].issue_severity, count: length})' bandit-report.json

# Extraer solo vulnerabilidades HIGH de Safety
jq '.vulnerabilities[] | select(.severity == "HIGH")' safety-report.json

# Listar archivos con problemas en Semgrep
jq '.results[].path' semgrep-report.json | sort | uniq
```

### Script Python para análisis:
```python
import json

def analyze_bandit_results(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    
    severity_count = {}
    for result in data['results']:
        severity = result['issue_severity']
        severity_count[severity] = severity_count.get(severity, 0) + 1
    
    return severity_count

# Uso
results = analyze_bandit_results('bandit-report.json')
print(f"Vulnerabilidades encontradas: {results}")
```

---

## 🎯 **Integración en CI/CD**

### Ejemplo de script de análisis:
```bash
#!/bin/bash
# analyze_security.sh

echo "🔒 Iniciando análisis de seguridad..."

# Ejecutar todas las herramientas
bandit -r . -f json -o bandit-report.json -ll -i || true
semgrep --config=p/python --json --output=semgrep-report.json . || true
safety scan -r requirements.txt --output json > safety-report.json || true

# Procesar resultados
echo "📊 Resumen de vulnerabilidades:"
echo "Bandit: $(jq '.results | length' bandit-report.json) issues"
echo "Semgrep: $(jq '.results | length' semgrep-report.json) issues"
echo "Safety: $(jq '.vulnerabilities | length' safety-report.json) vulnerabilities"
```

---

## 🔧 **Configuración Avanzada**

### Archivo de configuración unificado (sast-config.yml):
```yaml
tools:
  bandit:
    severity: low
    confidence: low
    exclude_dirs: [".git", "__pycache__", "venv"]
  
  semgrep:
    rulesets:
      - "p/security-audit"
      - "p/python"
      - "p/flask"
    
  safety:
    ignore_vulnerabilities: []
    
  gitleaks:
    allowlist_files: ["test_*.py"]
```

Esta documentación proporciona ejemplos prácticos para usar cada herramienta SAST de forma efectiva en el análisis de seguridad de VAmPI.