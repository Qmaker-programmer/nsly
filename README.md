# 🛡️ NSLY VAULT — Gestor de Contraseñas TUI

> Un gestor de contraseñas minimalista, seguro y **FACHERO** que vive en tu terminal 🖥️  
> *Porque guardar contraseñas en un post-it es 2023, amigo.*

---
## Vista previa!
![IMagen vista previa de NSL beta 1.0.0](https://private-user-images.githubusercontent.com/231296081/596965950-4960aa43-ca2f-49e2-83e7-4ac1c3f82d76.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3Nzk0NzgwNTksIm5iZiI6MTc3OTQ3Nzc1OSwicGF0aCI6Ii8yMzEyOTYwODEvNTk2OTY1OTUwLTQ5NjBhYTQzLWNhMmYtNDllMi04M2U3LTRhYzFjM2Y4MmQ3Ni5wbmc_WC1BbXotQWxnb3JpdGhtPUFXUzQtSE1BQy1TSEEyNTYmWC1BbXotQ3JlZGVudGlhbD1BS0lBVkNPRFlMU0E1M1BRSzRaQSUyRjIwMjYwNTIyJTJGdXMtZWFzdC0xJTJGczMlMkZhd3M0X3JlcXVlc3QmWC1BbXotRGF0ZT0yMDI2MDUyMlQxOTIyMzlaJlgtQW16LUV4cGlyZXM9MzAwJlgtQW16LVNpZ25hdHVyZT0xY2YzNjMyNzhiYmEzOTMwYmM4YjhjZjkwZDYyNDgzODNmMGQ2MDM5YWY4MTNkNmNmM2UyOWIxZDc3YzgyYWJhJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZyZXNwb25zZS1jb250ZW50LXR5cGU9aW1hZ2UlMkZwbmcifQ.E7p34m836L_3Ove-5tXlp6eMXXJb9_Cu5V_k3fs6Vm4)

---
## 🚀 Instalación rápida

### Prerequisitos
- **Go 1.21+** (si no lo tienes, [instálalo aquí](https://golang.org/dl))
- Un terminal que no sea de hace 15 años

### Setup en 3 pasos
**Si quieres solo instalarlo hazlo desde Releases: [Instalacion sencilla desde Releases](https://github.com/Qmaker-programmer/Nsly/releases)**
---
**Si quieres hacerlo tu mismo puedes usar Make o manualmente:**
```bash
# 1️⃣ Clona y entra al directorio
git clone https://github.com/Qmaker-programmer/Nsly.git
cd Nsly

# 2️⃣ Descarga las dependencias (go hace todo)
go mod tidy

# 3️⃣ ¡Ejecútalo ya!
go run src/main.go
```

O compila un binario permanente (Asegurate de haber hecho el paso 1 y 2)

```bash
# Linux / macOS
go build -o bin/nsly src/main.go
./bin/nsly

# Windows (obviamente .exe)
go build -o bin/nsly.exe src/main.go
bin\\nsly.exe

# O usa el Makefile (si tienes make)
make run      # ejecución directa
make build    # compilar binario
make clean    # borrar lo compilado
# O en el Makefile agrege algo para compilar a Linux, Windows y MacOS al mismo tiempo (Incluido ARM64 y AMD64), recomendado para produccion
make build-all

#todo esto quedara en bin/
```

🔐 Seguridad — Tómatelo en serio

| Capa | Tecnología | Para qué | Nivel 💪 |
|------|-----------|----------|---------|
| **Autenticación** | bcrypt cost=14 | Verificar contraseña maestra (~1s) | 🟢 Fuerte |
| **Cifrado datos** | AES-256-GCM | Cifrar cada contraseña guardada | 🟢 Militar |
| **Derivación de clave** | scrypt (N=32768) | Generar clave AES desde tu master pass | 🟢 Anti-brute-force |
| **Permisos archivos** | 0700 dir / 0600 archivos | Solo TÚ puedes leer tus secretos | 🟢 Linux/Unix |

Dónde se guardan tus secretos

Todos los archivos viven en ~/.nsly_vault/:

- master.hash — Hash bcrypt de tu contraseña maestra (NUNCA se guarda en claro)
- vault.enc — Todas tus contraseñas cifradas con AES-256-GCM (blob opaco)
- vault.meta — Metadatos de la bóveda (salt para scrypt)
- sync.json — Config de sincronización en la nube (sin datos sensibles)

¿Y en la nube?

Cuando sincronizas (☁️ Sync), tu bóveda viaja COMPLETAMENTE CIFRADA. El servidor solo ve:

```
[BLOB OPACO INCOMPRENSIBLE PARA HUMANOS Y MÁQUINAS]
```

Incluso si alguien hackea tu servidor, solo obtiene basura cifrada. 🎯

⌨️ Atajos de teclado

🌍 Global

| Tecla | Acción |
|-------|--------|
| Ctrl+C | Salir de emergencia (⚠️ sincroniza antes) |
| Esc | Volver / Bloquear bóveda |

📋 Lista de contraseñas

| Tecla | Acción |
|-------|--------|
| ↑/↓ k/j | Navegar (elegimos dos porque somos geniales 😎) |
| Enter | Ver detalle completo |
| C | Copiar contraseña al clipboard |
| D | Eliminar entrada (te pide confirmación) |

🔎 Detalle de contraseña

| Tecla | Acción |
|-------|--------|
| S | Mostrar/ocultar contraseña (discreto) |
| C | Copiar al clipboard |
| T | Copiar código TOTP (si tiene 2FA) |
| D | Eliminar entrada |

➕ Añadir contraseña

| Tecla | Acción |
|-------|--------|
| Ctrl+G | Generar contraseña aleatoria (en el campo de contraseña) |
| Enter | Avanzar al siguiente campo |
| Esc | Cancelar y volver |

🎲 Generador de contraseñas

| Tecla | Acción |
|-------|--------|
| ←/→ | Cambiar longitud |
| ↑/↓ | Navegar opciones |
| Space | Toggle: activar/desactivar conjunto de caracteres |
| C | Copiar al clipboard |
| Enter | Usar esta contraseña → crear entrada |

🔍 Búsqueda

| Tecla | Acción |
|-------|--------|
| Escribe | Filtrar en tiempo real (servicio, usuario, URL) |
| Enter | Ver detalle de resultado seleccionado |
| ↑/↓ | Navegar resultados |
| Esc | Volver |

📦 Dependencias

```
github.com/atotto/clipboard      v0.1.4   → Copiar al portapapeles sin lágrimas
github.com/charmbracelet/bubbles v0.18.0  → Componentes TUI (textinput, etc)
github.com/charmbracelet/bubbletea v0.25.0 → Framework TUI (el cerebro)
github.com/charmbracelet/lipgloss v0.10.0  → Estilos para terminal (lo bonito)
github.com/pquerna/otp           v1.4.0   → Generación de códigos TOTP 2FA
golang.org/x/crypto/bcrypt       (Go std) → Hashing seguro de contraseñas
golang.org/x/crypto              v0.18.0  → AES-256-GCM, scrypt, utils
```

🎯 Características principales

✅ Lo que YA funciona

* **✓ Cifrado AES-256-GCM — Tus contraseñas viajan blindadas**
* **✓ Generador de contraseñas seguras — Random de verdad (no AI)**
* **✓ Búsqueda en tiempo real — Encuentra esa contraseña que no recuerdas**
* **✓ Copiar al clipboard — No dejas rastro en el historial**
* **✓ Exportar JSON — Para migrar o hacer backup (¡cuidado!)**
* **✓ Medidor de fortaleza — Te dice si tu contraseña es patética**
* **✓ Confirmación antes de eliminar — Porque los accidentes suceden**
* **✓ TOTP / 2FA — Códigos de 6 dígitos para Google, GitHub, etc**
* **✓ Sincronización en la nube — Sube/descarga tu bóveda cifrada**
* **✓ Importar de otros gestores — Bitwarden, KeePass, formatos NSLY**

🚀 En el roadmap (coming soon™)

- Soporte múltiples identidades — Varias "cajas fuertes"
- Historial de cambios — Saber quién modificó qué y cuándo
- Autolock temporal — Bloquea automáticamente tras 5 min inactivo
- WebDAV / Nextcloud — Sincroniza con tu nube personal
- Biometría — Huella dactilar en lugar de contraseña maestra
- Compartir contraseña de forma segura — (cryptografía asimétrica needed)

📤 Exportar tu bóveda

```
Menú → "📤 Exportar bóveda" → ✅
Se creará un archivo nsly_export_YYYYMMDD_HHMMSS.json en tu $HOME con:

✓ Todas las contraseñas en texto plano
✓ Usuarios, URLs, notas
✓ Códigos TOTP (si tienes)
```

⚠️ ADVERTENCIA IMPORTANTE:

Este archivo es SENSIBLE. Guárdalo en un lugar seguro.
Bórralo después de importarlo a otro gestor.
No lo dejes en el escritorio ni lo subes a GitHub (please).

📥 Importar desde otros gestores

Desde Bitwarden

```
Bitwarden → Ajustes → Exportar bóveda → JSON
Luego en NSLY:

📥 Importar → Bitwarden → [selecciona el JSON]
```

Desde KeePass

```
KeePass → Archivo → Exportar → CSV (con encabezados)
Luego en NSLY:

📥 Importar → KeePass → [selecciona el CSV]
```

Desde NSLY anterior

```
📥 Importar → NSLY → [selecciona el export JSON]
```

☁️ Sincronización con la nube

Setup inicial

```
Configura tu servidor

Menú → ☁️ Sync → ⚙️ Configurar
Proporciona:

URL: https://tu-servidor.com/vault
Token: Tu bearer token de autenticación
NSLY guardará los datos de sync (sin información sensible)
```

Operaciones

```
Subir a la nube
Menú → ☁️ Sync → ⬆️ Subir
Tu bóveda cifrada se sube al servidor.

Descargar desde la nube
Menú → ☁️ Sync → ⬇️ Descargar
Tu bóveda local se reemplaza con la del servidor.
```

¿Cómo implemento el servidor?
El servidor espera:

PUT {URL} con Authorization: Bearer {token} → guarda el blob
GET {URL} con Authorization: Bearer {token} → devuelve el blob

Ejemplo mínimo en Node.js:

```javascript
const express = require('express');
const app = express();

let vault = null;

app.put('/vault', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token !== process.env.VAULT_TOKEN) return res.status(401).send('Unauthorized');
  
  let data = Buffer.alloc(0);
  req.on('data', chunk => { data = Buffer.concat([data, chunk]); });
  req.on('end', () => {
    vault = data;
    res.send('OK');
  });
});

app.get('/vault', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token !== process.env.VAULT_TOKEN) return res.status(401).send('Unauthorized');
  if (!vault) return res.status(404).send('Not found');
  res.send(vault);
});

app.listen(3000, () => console.log('NSLY Sync server ready 🚀'));
```

🛠️ Compilación y desarrollo

Estructura del proyecto

```
Nsly/
├── README.md              ← Estás aquí 👋
├── go.mod                 ← Dependencias
├── go.sum                 ← Lockfile de dependencias
├── Makefile               ← Comandos útiles
├── LICENSE                ← GPL v2
└── src/
    └── main.go            ← TODO el código (sí, en un archivo 😅)
```

Compilar para diferentes plataformas

```bash
# Linux 64-bit
GOOS=linux GOARCH=amd64 go build -o bin/nsly src/main.go

# macOS Intel
GOOS=darwin GOARCH=amd64 go build -o bin/nsly-darwin-amd64 src/main.go

# macOS Apple Silicon
GOOS=darwin GOARCH=arm64 go build -o bin/nsly-darwin-arm64 src/main.go

# Windows
GOOS=windows GOARCH=amd64 go build -o bin/nsly.exe src/main.go
```

Desarrollo

```bash
# Ejecutar directamente
make run

# Compilar y colocar en bin/
make build

# Limpiar binarios
make clean

# Verificar código
go fmt ./...
go vet ./...
```

🐛 Troubleshooting

"Error: go: no Go files in /current/directory"

```bash
cd nsly
ls src/main.go  # debe existir
go run src/main.go
```

"Error: clipboard no disponible en este terminal"

Algunos terminales remotos (SSH, WSL sin soporte) no permiten acceso a clipboard.

Solución: Copia manual desde la pantalla

"Olvidé mi contraseña maestra 😭"

No hay recuperación. Es intencional.

Tu bóveda está cifrada. Si pierdes la clave, pierdes TODO.
Escribe tu contraseña en un lugar seguro.

"¿Funciona en Windows?"

Sí, usa Windows Terminal (PowerShell). En cmd.exe los colores pueden verse raros.

"¿Y en macOS?"

Perfectamente. Go compila para cualquier cosa.

📊 Comparación con otros gestores

| Feature | NSLY | Bitwarden | KeePass | 1Password |
|---------|------|-----------|--------|-----------|
| TUI Terminal | ✅ 🎉 | ❌ | ❌ | ❌ |
| Local-first | ✅ | ❌ (cloud default) | ✅ | ❌ |
| Sincronización | ✅ (DIY) | ✅ (cloud) | ❌ | ✅ (cloud) |
| Precio | 🆓 Gratis | $10/año | 🆓 Gratis | $3.99/mes |
| 2FA/TOTP | ✅ | ✅ | ✅ | ✅ |
| Open Source | ✅ | ✅ | ✅ | ❌ |
| Importar datos | ✅ | ✅ | ✅ | ✅ |

🤝 Contribuciones

¿Encontraste un bug? ¿Quieres una feature?

Fork el repo
Crea una rama: git checkout -b feature/mi-feature
Haz tu magia ✨
Commit: git commit -m 'Add: mi-feature'
Push: git push origin feature/mi-feature
Abre un Pull Request 🎉

📜 Licencia

GNU General Public License v2 (GPL v2) — ¡Código libre para todos!

Esto significa:

✅ Puedes usar, copiar, modificar y distribuir NSLY libremente
✅ Cualquier software derivado DEBE ser también GPL v2
✅ Acceso al código fuente garantizado
✅ Sin garantías (lo usas bajo tu responsabilidad)
Lee LICENSE para detalles completos.

¡Viva el Software Libre! 🚩

🎪 Curiosidades

¿Por qué TUI? → Porque vivimos en la terminal y amamos eficiencia.
¿Por qué Go? → Binario único, sin dependencias, rápido. Zero drama.
¿Por qué scrypt + AES-256-GCM? → Porque la seguridad no es negociable.
¿Por qué GPL v2? → Porque el software es un bien común. 🚩
¿Puedo usarlo en producción? → Sí, pero asume el riesgo (y lee el código).

🚀 ¡Empecemos!

```bash
git clone https://github.com/Qmaker-programmer/Nsly.git
cd Nsly
go run src/main.go

# Crea tu contraseña maestra 🔐
# Guarda tus secretos sin miedo 🛡️
# Duerme tranquilo 😴
```

Por Andres(Qmaker) (y mucho Tè) en la terminal.
