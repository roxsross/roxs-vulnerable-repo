# Política de Seguridad - VAmPI

## Herramientas SAST Implementadas

Este repositorio incluye múltiples herramientas de análisis estático de seguridad (SAST) que se ejecutan automáticamente:

### 🔍 Herramientas de Análisis

1. **Bandit** - Análisis de seguridad específico para Python
   - Detecta vulnerabilidades comunes en código Python
   - Configuración personalizada en `.bandit`
   - Reportes en formato JSON y texto

2. **Semgrep** - Análisis de patrones de seguridad
   - Reglas específicas para Flask y Python
   - Configuración personalizada en `.semgrep.yml`
   - Integración con GitHub Security tab

3. **CodeQL** - Análisis semántico de código
   - Consultas de seguridad extendidas
   - Detección de vulnerabilidades complejas
   - Integración nativa con GitHub

4. **Safety** - Verificación de dependencias vulnerables
   - Análisis de `requirements.txt`
   - Base de datos actualizada de vulnerabilidades
   - Reportes detallados de CVEs

5. **pip-audit** - Auditoría adicional de dependencias
   - Verificación cruzada con Safety
   - Análisis de vulnerabilidades en paquetes Python
   - Reportes en formato JSON

6. **GitLeaks** - Detección de secretos
   - Escaneo de historial de Git
   - Configuración personalizada en `.gitleaks.toml`
   - Detección de claves API, passwords, etc.

7. **Trivy** - Scanner de vulnerabilidades multiplataforma
   - Análisis de dependencias y vulnerabilidades conocidas
   - Escaneo de configuraciones (IaC)
   - Detección de CVEs en paquetes Python
   - Configuración personalizada en `.trivyignore`

### 🚀 Ejecución Automática

Los análisis se ejecutan automáticamente en:
- ✅ Push a las ramas `vampi`, `main`, `master`
- ✅ Pull Requests
- ✅ Semanalmente (lunes a las 2 AM UTC)

### 📊 Visualización de Resultados

Los resultados están disponibles en:
- **Security tab** del repositorio (CodeQL, Semgrep)
- **Actions tab** para logs detallados
- **Artifacts** descargables con reportes JSON

### ⚙️ Configuración Personalizada

Cada herramienta tiene su configuración específica:
- `.bandit` - Configuración de Bandit
- `.semgrep.yml` - Reglas personalizadas de Semgrep
- `.gitleaks.toml` - Configuración de GitLeaks
- `.trivyignore` - Configuración de Trivy
- `.github/dependabot.yml` - Actualizaciones automáticas

### 🔧 Ejecutar Localmente

Para ejecutar las herramientas localmente:

```bash
# Instalar herramientas
pip install bandit safety pip-audit semgrep

# Ejecutar análisis
bandit -r . -f json -o bandit-report.json
safety check -r requirements.txt
pip-audit -r requirements.txt
semgrep --config=.semgrep.yml .

# Trivy (requiere instalación separada)
# Instalar desde: https://aquasecurity.github.io/trivy/
trivy fs . --format json --output trivy-report.json
trivy config .
```

### 📝 Notas Importantes

- **VAmPI es intencionalmente vulnerable** para propósitos educativos
- Los análisis SAST detectarán múltiples vulnerabilidades por diseño
- Usar estos reportes para entender patrones de vulnerabilidades
- No usar este código en producción sin remediar las vulnerabilidades

### 🛡️ Reporte de Vulnerabilidades

Si encuentras vulnerabilidades no intencionadas en la infraestructura de testing:
1. Crear un issue en GitHub
2. Etiquetar como `security`
3. Proporcionar detalles del hallazgo

### 📚 Recursos Adicionales

- [OWASP Top 10 API Security](https://owasp.org/www-project-api-security/)
- [Bandit Documentation](https://bandit.readthedocs.io/)
- [Semgrep Rules](https://semgrep.dev/explore)
- [CodeQL Documentation](https://codeql.github.com/docs/)