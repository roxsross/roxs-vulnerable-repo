# Documentación de Herramientas SAST - VAmPI

## 🔍 Herramientas de Análisis de Seguridad Implementadas

Este repositorio utiliza 7 herramientas SAST (Static Application Security Testing) que analizan el código de forma automática para detectar vulnerabilidades de seguridad.

---

## 1. 🐍 **Bandit** - Análisis de Seguridad Python

### ¿Qué hace?
Bandit es una herramienta especializada en encontrar problemas de seguridad comunes en código Python.

### Vulnerabilidades que detecta:
- **B104**: Binding a todas las interfaces (`0.0.0.0`)
- **B105**: Contraseñas hardcodeadas en strings
- **B201**: Flask ejecutándose en modo debug
- **B301**: Uso inseguro de pickle
- **B324**: Algoritmos de hash débiles (MD5, SHA1)
- **B602**: Subprocess con shell=True
- **B605**: Uso de os.system()
- **B608**: Posible inyección SQL

### Ejemplo de detección:
```python
# B105: Hardcoded password
SECRET_KEY = "admin123"

# B602: Shell injection
subprocess.call(user_input, shell=True)
```

### Configuración:
- **Severidad**: Low, Medium, High
- **Confianza**: Low, Medium, High
- **Formato**: JSON para análisis automatizado

---

## 2. 🔎 **Semgrep** - Análisis de Patrones de Código

### ¿Qué hace?
Semgrep utiliza reglas basadas en patrones para encontrar bugs, vulnerabilidades y anti-patrones en el código.

### Rulesets utilizados:
- **p/security-audit**: Reglas generales de seguridad
- **p/secrets**: Detección de secretos y credenciales
- **p/python**: Reglas específicas de Python
- **p/flask**: Reglas específicas de Flask
- **p/owasp-top-ten**: OWASP Top 10 vulnerabilidades

### Vulnerabilidades que detecta:
- Inyección SQL
- Cross-Site Scripting (XSS)
- Deserialización insegura
- Configuraciones inseguras
- Secretos hardcodeados
- Uso de funciones peligrosas

### Ejemplo de detección:
```python
# SQL Injection
query = f"SELECT * FROM users WHERE id = {user_id}"

# Hardcoded JWT secret
jwt.encode(payload, key="hardcoded-secret")
```

---

## 3. 🔬 **CodeQL** - Análisis Semántico Profundo

### ¿Qué hace?
CodeQL convierte el código en una base de datos consultable y ejecuta consultas complejas para encontrar vulnerabilidades.

### Características:
- **Análisis semántico**: Entiende el flujo de datos
- **Consultas avanzadas**: security-extended, security-and-quality
- **Detección de patrones complejos**: Vulnerabilidades multi-paso

### Vulnerabilidades que detecta:
- Inyección de comandos
- Path traversal
- Inyección SQL compleja
- Vulnerabilidades de deserialización
- Flujos de datos inseguros
- Race conditions

### Ventajas:
- Análisis profundo del flujo de datos
- Baja tasa de falsos positivos
- Detección de vulnerabilidades complejas

---

## 4. 🛡️ **Safety** - Análisis de Dependencias Vulnerables

### ¿Qué hace?
Safety verifica las dependencias de Python contra una base de datos de vulnerabilidades conocidas (CVEs).

### Funcionalidad:
- Escanea `requirements.txt`
- Consulta base de datos de PyUp.io
- Identifica paquetes con vulnerabilidades conocidas
- Proporciona información de CVEs

### Ejemplo de detección:
```
-> Vulnerability found in flask version 2.2.2
Vulnerability ID: 55261
CVE-2023-30861
Affected spec: <2.2.5
```

### Información proporcionada:
- **CVE ID**: Identificador de vulnerabilidad
- **Severidad**: Crítica, Alta, Media, Baja
- **Versiones afectadas**: Rango de versiones vulnerables
- **Versión de corrección**: Versión segura recomendada

---

## 5. 🔍 **pip-audit** - Auditoría de Paquetes Python

### ¿Qué hace?
pip-audit es una herramienta de auditoría que verifica paquetes Python instalados contra vulnerabilidades conocidas.

### Características:
- Análisis de dependencias directas e indirectas
- Múltiples fuentes de vulnerabilidades
- Verificación cruzada con Safety
- Detección de paquetes maliciosos

### Vulnerabilidades detectadas en VAmPI:
```
Name     Version ID                  Fix Versions
flask    2.2.2   PYSEC-2023-62       2.2.5,2.3.2
werkzeug 2.2.3   PYSEC-2023-221      2.3.8,3.0.1
werkzeug 2.2.3   GHSA-2g68-c3qc-8985 3.0.3
```

### Ventajas:
- Verificación independiente de Safety
- Análisis de dependencias transitivas
- Múltiples bases de datos de vulnerabilidades

---

## 6. 🔐 **GitLeaks** - Detección de Secretos

### ¿Qué hace?
GitLeaks escanea el repositorio Git (incluyendo historial) para encontrar secretos, claves API, contraseñas y credenciales.

### Tipos de secretos que detecta:
- **Claves API**: AWS, Google, GitHub, etc.
- **Tokens de acceso**: JWT, OAuth, etc.
- **Contraseñas**: Hardcodeadas en código
- **Certificados**: Claves privadas, certificados
- **Strings de conexión**: Bases de datos, servicios

### Configuración personalizada:
```toml
[[rules]]
id = "flask-secret-key"
description = "Flask Secret Key"
regex = '''(?i)(secret_key|SECRET_KEY)\s*=\s*['""][^'""]{8,}['""]'''
```

### Características:
- Escaneo de historial completo de Git
- Reglas personalizables
- Allowlist para falsos positivos
- Múltiples formatos de salida

---

## 7. 🛡️ **Trivy** - Scanner de Vulnerabilidades Multiplataforma

### ¿Qué hace?
Trivy es un scanner de vulnerabilidades que analiza dependencias, configuraciones y otros componentes del sistema.

### Dos tipos de análisis implementados:

#### **7a. Trivy Filesystem Scan (`fs`)**
- **Target**: Código fuente y archivos del repositorio
- **Analiza**: requirements.txt, configuraciones, secretos en código
- **Velocidad**: Rápido
- **Uso**: Desarrollo, análisis de código fuente

#### **7b. Trivy Container Image Scan (`image`)**
- **Target**: Imagen Docker construida de VAmPI
- **Analiza**: Paquetes del SO, dependencias instaladas, configuración del contenedor
- **Velocidad**: Más lento (requiere build)
- **Uso**: Análisis de runtime, seguridad de contenedores

### Vulnerabilidades que detecta:
- **FS Scan**: CVEs en requirements.txt, misconfigurations, secretos
- **Image Scan**: CVEs en paquetes del SO (Alpine Linux), vulnerabilidades de runtime
- **Ambos**: Problemas de licencias, configuraciones inseguras

### Dockerfile de VAmPI:
```dockerfile
FROM python:3.11-alpine as builder
RUN apk --update add bash nano g++
COPY ./requirements.txt /vampi/requirements.txt
WORKDIR /vampi
RUN pip install -r requirements.txt

FROM python:3.11-alpine
COPY . /vampi
WORKDIR /vampi
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/bin /usr/local/bin
ENV vulnerable=1
ENV tokentimetolive=60
```

### Ventajas del análisis dual:
- **Cobertura completa**: Desarrollo + Runtime
- **Detección temprana**: FS scan en desarrollo
- **Seguridad de contenedores**: Image scan para producción
- **Análisis de SO**: Vulnerabilidades en Alpine Linux

---

## 📊 **Comparación de Herramientas**

| Herramienta | Tipo de Análisis | Especialización | Formato Salida |
|-------------|------------------|-----------------|----------------|
| Bandit | Código Python | Vulnerabilidades Python | JSON |
| Semgrep | Patrones de código | Reglas personalizables | JSON |
| CodeQL | Análisis semántico | Flujo de datos complejo | JSON |
| Safety | Dependencias | CVEs conocidos | JSON |
| pip-audit | Dependencias | Verificación cruzada | JSON |
| GitLeaks | Secretos | Historial Git | JSON |
| Trivy FS | Filesystem | Código fuente y configs | JSON |
| Trivy Image | Container | SO y runtime | JSON |

---

## 🚀 **Ejecución y Resultados**

### Automatización:
- **Triggers**: Push, PR, schedule semanal
- **Paralelización**: Todos los jobs ejecutan en paralelo
- **Tolerancia a fallos**: `continue-on-error: true`

### Artifacts JSON:
Cada herramienta genera un artifact JSON descargable:
- `bandit-results-json`
- `semgrep-results-json`
- `codeql-results-json`
- `safety-results-json`
- `pip-audit-results-json`
- `gitleaks-results-json`
- `trivy-fs-results-json` (Filesystem scan)
- `trivy-image-results-json` (Container scan)

### Procesamiento de Resultados:
Los archivos JSON pueden ser procesados con herramientas como:
- `jq` para consultas
- Scripts Python para análisis
- Herramientas de visualización
- Sistemas de gestión de vulnerabilidades

---

## 🎯 **Casos de Uso por Herramienta**

### Para Desarrolladores:
- **Bandit**: Revisar código Python antes de commit
- **Semgrep**: Validar patrones de seguridad
- **CodeQL**: Análisis profundo de vulnerabilidades

### Para DevSecOps:
- **Safety/pip-audit**: Gestión de dependencias vulnerables
- **GitLeaks**: Prevención de filtración de secretos
- **Trivy**: Scanner integral en CI/CD

### Para Auditores de Seguridad:
- **Todos los JSON**: Análisis forense de vulnerabilidades
- **Correlación**: Comparar resultados entre herramientas
- **Reporting**: Generar reportes ejecutivos

---

## 📚 **Referencias y Documentación**

- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Semgrep Rules](https://semgrep.dev/explore)
- [CodeQL Documentation](https://codeql.github.com/docs/)
- [Safety Database](https://pyup.io/safety/)
- [pip-audit GitHub](https://github.com/pypa/pip-audit)
- [GitLeaks GitHub](https://github.com/gitleaks/gitleaks)
- [Trivy Documentation](https://aquasecurity.github.io/trivy/)

---

## ⚠️ **Nota Importante**

VAmPI es **intencionalmente vulnerable** para propósitos educativos. Las vulnerabilidades detectadas por estas herramientas son esperadas y forman parte del diseño del laboratorio de seguridad.

**No usar este código en producción sin remediar las vulnerabilidades identificadas.**