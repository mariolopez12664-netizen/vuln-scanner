# 🔒 Vulnerability Scanner

Herramienta profesional de escaneo de vulnerabilidades para pentesting y auditorías de seguridad.

## 🎯 Características

- ✅ Escaneo de puertos con Nmap
- ✅ Detección automática de servicios
- ✅ Base de datos de vulnerabilidades conocidas
- ✅ Análisis de configuraciones incorrectas
- ✅ Generación de reportes (HTML, JSON, TXT)
- ✅ Matriz de riesgo y scoring CVSS
- ✅ Escaneo de redes completas
- ✅ Modo verbose para debugging

## 📦 Instalación

### Requisitos Previos
```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Nmap
sudo apt install nmap -y

# Instalar Python 3 y pip
sudo apt install python3 python3-pip python3-venv git -y
```

### Instalación de la Herramienta
```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/vuln-scanner.git
cd vuln-scanner

# Crear entorno virtual
python3 -m venv venv
source venv/bin/activate

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución
chmod +x vuln_scan.py
```

## 🚀 Uso

### Ejemplos Básicos
```bash
# Escanear un solo host
sudo python3 vuln_scan.py -t 192.168.1.1

# Escanear una red completa
sudo python3 vuln_scan.py -t 192.168.1.0/24

# Escanear puertos específicos
sudo python3 vuln_scan.py -t 192.168.1.1 -p 80,443,8080,3306

# Escanear desde archivo de IPs
sudo python3 vuln_scan.py -l targets.txt

# Escaneo completo (todos los puertos)
sudo python3 vuln_scan.py -t 192.168.1.1 --full-scan

# Especificar formato de reporte
sudo python3 vuln_scan.py -t 192.168.1.1 -o html,json

# Modo verbose
sudo python3 vuln_scan.py -t 192.168.1.1 -v
```

### Formato del Archivo targets.txt
```
192.168.1.1
192.168.1.10
10.0.0.0/24
scanme.nmap.org
```

## 📊 Reportes Generados

Los reportes se guardan en la carpeta `reports/` con timestamp:

- **HTML**: Reporte visual interactivo con gráficos
- **JSON**: Datos estructurados para integración con otras herramientas
- **TXT**: Reporte de texto plano para terminal

## 🗂️ Estructura del Proyecto
```
vuln-scanner/
├── vuln_scan.py          # Script principal
├── scanner/              # Módulos principales
│   ├── core.py          # Clases Host y ScanRegistry
│   ├── port_scanner.py  # Escaneo de puertos
│   ├── vuln_detector.py # Detección de vulnerabilidades
│   └── report_generator.py # Generación de reportes
├── database/            # Base de datos de vulnerabilidades
├── config/              # Archivos de configuración
├── reports/             # Reportes generados
└── logs/                # Logs de ejecución
```

## ⚙️ Configuración

Edita `config/config.yaml` para personalizar:

- Timeout de conexiones
- Puertos a escanear
- Tipos de verificaciones
- Formatos de reporte

## 🔍 Vulnerabilidades Detectadas

La herramienta detecta:

- Servicios con versiones desactualizadas
- Puertos críticos expuestos (RDP, SSH, MySQL, etc.)
- Configuraciones inseguras
- Protocolos sin cifrado
- Bases de datos expuestas
- Servicios con credenciales por defecto

## 📈 Sistema de Puntuación

- **CRITICAL** (9.0-10.0): Vulnerabilidad extrema
- **HIGH** (7.0-8.9): Riesgo alto
- **MEDIUM** (4.0-6.9): Riesgo medio
- **LOW** (0.1-3.9): Riesgo bajo
- **INFO** (0.0): Informativo

## ⚠️ Disclaimer

**USO LEGAL ÚNICAMENTE**

Esta herramienta está diseñada para:
- Auditorías de seguridad autorizadas
- Pentesting con permiso explícito
- Evaluaciones de seguridad en entornos propios
- Propósitos educativos

❌ **NO USAR PARA:**
- Acceso no autorizado a sistemas
- Ataques maliciosos
- Violación de leyes de ciberseguridad

El autor no se hace responsable del mal uso de esta herramienta.

## 📝 Licencia

MIT License - Ver archivo LICENSE

## 👤 Autor

[Tu Nombre]
- GitHub: [@tu-usuario](https://github.com/tu-usuario)
- LinkedIn: [tu-perfil](https://linkedin.com/in/tu-perfil)

## 🤝 Contribuciones

Las contribuciones son bienvenidas. Por favor:

1. Fork el proyecto
2. Crea tu feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la branch (`git push origin feature/AmazingFeature`)
5. Abre un Pull Request

## 🐛 Reportar Bugs

Si encuentras un bug, por favor crea un issue con:
- Descripción del problema
- Pasos para reproducir
- Sistema operativo y versión de Python
- Logs relevantes

## 📚 Referencias

- [Nmap Documentation](https://nmap.org/book/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CVSS Scoring System](https://www.first.org/cvss/)

---

⭐ Si te gusta el proyecto, dale una estrella en GitHub!