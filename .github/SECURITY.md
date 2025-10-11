# Documentación de Herramientas

## 🔍 Herramientas de Análisis de mentadas

Este repositorio utiliza 7 herramientas SAST (Static Application Security Testing) que analizan el código de forma automá

---

## 1. 🐍 **Bandit** - Análisis de Seguridad Python

### ¿Qué hace?
Bandit es una herramienta especializa.

### Vulnerabilidades que detecta:
- **B104**: Binding a todas las interfaces .0.0`)
- **B105**: Contraseñas hardcodeadas en strings
- **B201**: Flask ejecutándose en modo debug
de pickle
- **B324**: Algoritmos de hash débiles (MD5,A1)
- **B602**: Subprocess con shell=True
- **B605**: Uso de os.system()
- **B608**: Posible inyección SQL

### Ejemplo de detección:
```python
# B105: Hardcoded password
SECRET_KEY = "admin123"

# B602: Shell injection
subprocess.call(user_input, shell=Tre)
```

ción:
- **Severidad**: Low, Medium, High
- **Confianza**: Low, Medium, High
- **Formato**: JSON para análisis automatizado

---

## 2. 🔎 **Semgrep** - Análisis de Patrones de Código

### ¿Qué hace?
Semgrep utiliza reglas basadas en patrones para enigo.

### Rulesets utilizados:

- **p/secrets**: Detección de secretos y crees
- **p/python**: Reglas específicas de Python
- **p/flask**: Re de Flask
- **p/owasp-top-ten**: OWASP Top 10 vul

### Vulnerabilidades que detecta:

- Cross-Site Scripting (XSS)
- Deserialización insegura
- Configuraciones inseguras
- Secretos hardcodeados


ón:
```python
# SQL Injection
query = f"SELECT * FROM users WHERE id = {user_id}"

# Hardcoded JWT secret
jwt.encode(payload, key="hardcoded-secret")






### ¿Qué hace?
CodeQL convierte el código en una base de d

### Características:
- **Análisis semántico**: Entiende el flu
- **Consultas avanzadas**: securlity
- **Detección de patrones com

tecta:
- Inyección de comandos
- Path traversal
- Inyección SQL compleja
- Vulnerabilidización
- Fs


as:
- Análisis profundo del flujo de datos
- Baja tasa de falsos positivos
- Detección de vulnerabilidades complejas

--

ables

### ¿Qué hace?
Safety verifica las dependenEs).

ad:
- Escanea `requirements.txt`
.io
- Identifica paquetes con vulnerabilidades conocidas
- Proporciona información de CVEs

### Ejemplo de detección:ulnerability found in flask versas.**ficades identiidadvulnerabilr las ediaión sin remn produccgo er este códi

**No usaridad.orio de seguel laboratño d diseele dn part y formaeradasson esprramientas r estas hepoctadas idades detelnerabils. Las vus educativoósitopara propable** lnerente vulmtencionas **inAmPI e
V
e** Importantta
## ⚠️ **No
---

.io/trivy/)ithubsecurity.gps://aquation](httmentavy Docus)
- [Trigitleakks/m/gitleab.coithu/g(https:/eaks GitHub]- [GitLudit)
pypa/pip-ahub.com/tps://gitub](htudit GitHp-ay/)
- [pifetyup.io/sa/ps:/abase](http [Safety Dat
-/)csb.com/doithu://codeql.gps](httentationeQL Documre)
- [Codep.dev/explomgrttps://se](hgrep Ruleso/)
- [Semdocs.idthereas://bandit.ion](httptatDocumenit [Band**

- umentaciónas y Doc*Referenci *---

## 📚s

jecutivoeportes erar rGene**:  **Reportingentas
-herramie dos entrrar resultaCompaación**: *Correls
- *abilidadeulnerde vorense is fN**: Anális JSOosos l**Todguridad:
- tores de Seudira APa
### n CI/CD
gral eScanner inte*: y**Triv
- *e secretosción dltrae fiPrevención dtLeaks**:  **Giles
-s vulnerabdenciadepende stión dit**: Gefety/pip-au- **SaecOps:
vS De### Paraidades

ilulnerabndo de vofuAnálisis preQL**: 
- **Codeguridad de sar patronesp**: Valid**Semgre
- mit de comython antesgo Par códit**: Revis **Bandiores:
-arrollad# Para Des

##nta**ieram por Hersos de Uso

## 🎯 **Caades

---ilid de vulnerabtióngess de Sistema
- iónzacvisualiamientas de 
- Herrsara análisithon pScripts Py
- tasnsulara co
- `jq` p como:tasmienra con herrocesados pueden serN phivos JSOLos arcltados:
e Resusamiento d Proce

###-json`y-results`
- `trivesults-jsoneaks-r`gitlson`
- it-results-jaudp-pijson`
- `esults-afety-r-json`
- `seql-results- `codts-json`
rep-resul`
- `semg-jsonultsandit-res`be:
- blargaescfact JSON d un artiienta generarramheN:
Cada JSOtifacts `

### Ar: true-errorontinue-onllos**: `ca fa*Tolerancia ralelo
- *an en pajecut e jobs Todos loszación**:araleli- **Pnal
ule semah, PR, schedgers**: Pusrigción:
- **Tiza
### Automatdos**
Resultaión y ecuc## 🚀 **Ej|

---

al | JSON ner integr | Scanaforma| Multiplatrivy |
| TN it | JSOl Gstoria Hios |cretitLeaks | Se G
|ada | JSON |uzcación crerifi | Vndenciasudit | Depe
| pip-aSON || Jconocidos | CVEs ias endencfety | DepSON |
| Sacomplejo | Jo de datos ntico | Flujnálisis semáodeQL | A|
| C | JSON blesalizason per| Reglascódigo  de  | Patronesemgrep JSON |
| S Python |erabilidadeshon | VulnCódigo Pyt| ndit |
| Ba-----------|---------------------|-------------|------------|
|-------lida rmato San | Foializaciópecs | Esside Análita | Tipo | Herramien*

entas*mide Herración mpara 📊 **Co
---

##istemas
ples ecosltiorte para múnte
- Sopmezada diarialitua acse de datos
- Balisis aná deiples tipos
- Múlttodo-en-unoScanner ntajas:
- Veres

### enedoe contdades d Vulnerabilincias
-emas de licedos
- Probleas hardcodcreto
- SeIaCtions en isconfigura M
-asn dependenciEs ecta:
- CVque detelidades abi## Vulner
#ncias
dede depencencias lisis de lináas**: ALicenciLeaks
- **ilar a Gitetos**: Sim
- **Secr, DockerfileAML, JSONciones**: Yra*Configum, etc.
- *n, np Pythoquetes: Pandencias***Depeisis:
- *análde ipos 

### Tistema. s delonentess comps y otroonenfiguracicias, codependenza que analiidades erabilulncanner de v un sesce?
Trivy ### ¿Qué hama

atafores Multipldadbili de Vulneranery** - Scan🛡️ **Triv
## 7. da

---
salirmatos de iples fo Múlts
-os positivolspara falist 
- AllowonalizablesReglas perse Git
-  completo drialneo de histoEscacas:
- racterísti`

### Ca'
``""]'''""]{8,}['*['""][^EY)\s*=\sECRET_Kecret_key|Si)(s''(?
regex = '" Keyk Secretlas"Fon = cripti
desy"sk-secret-ke
id = "fla[rules]]
```toml
[:daonalizarsn pefiguració Conicios

###erv stos,ases de da**: Bconexiónde gs 
- **Strinadosrtificivadas, ceves pr**: Clatificados
- **Cergos en códieadaardcods**: HContraseña
- ** OAuth, etc.eso**: JWT,okens de accc.
- **T, etle, GitHubWS, Goog*: As API*
- **Claveecta:ettos que d secrepos de### Ti

ciales.creden y ñasntraseaves API, coos, clr secretra encontratorial) paluyendo hisincGit (repositorio el ks escanea 
GitLea# ¿Qué hace?os

##n de Secretció- Detec*GitLeaks**  6. 🔐 *---

##idades

 vulnerabildedatos  bases de ples
- Múltiitivastransias ncependee dlisis d
- Anáafetyiente de Sn independcació:
- Verifi### Ventajas
```

.385 3.089-2g68-c3qc-.2.3   GHSA
werkzeug 28,3.0.13.1      2.23-22PYSEC-202.2.3   zeug 2
werk.2.5,2.3.     2EC-2023-62  YS 2.2.2   Pflask   
 Versions         Fix ID         ion   Vers
```
Name  en VAmPI:adas detectabilidades Vulner
### 
maliciosospaquetes n de  Deteccióafety
-con Sión cruzada 
- Verificacidadesnerabilentes de vulles fu
- Múltipe indirectasas directas ncidependeisis de :
- Análicasracteríst

### Caocidas.onlidades cvulnerabiados contra  instalPythonetes aquica perifque vía e auditormienta dras una her-audit e
pip hace?

### ¿Quéhons Pytde Paquete Auditoría -audit** -# 5. 🔍 **pip

#a

---dadmena reco segur Versiónección**:sión de correr **V
-ulnerablessiones vRango de ver**: ass afectad **Versione
-jaa, Ba, Medica, Altaad**: Crítiverididad
- **See vulnerabilor d IdentificadID**:
- **CVE da:porcionación proma# Infor
```

##2.2.5ed spec: <ctAffe23-30861
205261
CVE-: 5ability IDlner2.2
Vun 2.io
-> V
```