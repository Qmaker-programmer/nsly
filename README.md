# 🛡️ NSLY VAULT — Gestor de Contraseñas TUI

> *Un gestor de contraseñas minimalista, seguro y **FACHERO** que vive en tu terminal.*

---

## 🚀 Instalación rápida

**Prerequisitos**

- *Go 1.21+* — (https://golang.org/dl)
- Un terminal moderno

---

### Setup en 3 pasos

```bash
# 1️⃣ Entra al directorio
cd nsly

# 2️⃣ Dependencias
go mod tidy

# 3️⃣ Ejecutar
go run src/main.go
```

***Opcional: compilar binario***

```bash
# Linux / macOS
go build -o bin/nsly src/main.go
./bin/nsly

# Windows
go build -o bin/nsly.exe src/main.go
bin\\nsly.exe
```

---

## 🔐 Seguridad (resumen)

| Capa | Tecnología | Nota |
|------|-----------:|------|
| **Autenticación** | bcrypt (cost=14) | *Verifica master password (~1s)* |
| **Cifrado** | AES-256-GCM | ***Confidencialidad e integridad*** |
| **Derivación** | scrypt (N=32768) | *Resistente a brute-force*

---

## ⌨️ Atajos (ejemplos)

- **Ctrl+C** — Salir (emergencia)
- *Esc* — Volver / Bloquear
- **Enter** — Abrir detalle
- `C` — Copiar al clipboard

---

## 📦 Dependencias

```text
github.com/atotto/clipboard
github.com/charmbracelet/bubbletea
golang.org/x/crypto
```

---

## �� Características

- ✅ Cifrado AES-256-GCM
- ✅ Generador de contraseñas
- ✅ TOTP / 2FA
- ✅ Sincronización (blob cifrado)

---

## 📤 Exportar / Importar

**Exportar**: Menú → "📤 Exportar bóveda" → genera `nsly_export_YYYYMMDD_HHMMSS.json` (Sensible!)

**Importar**: Soporta Bitwarden JSON, KeePass CSV y backups NSLY.

---

> ***Nota de seguridad:*** *Nunca subas archivos de export en texto plano a repositorios públicos.*

---

## ✅ Checklist rápida

- [x] README actualizado
- [ ] Tests (por añadir)
- [ ] CI (por añadir)

---

## Contribuciones

1. Fork
2. git checkout -b feature/mi-feature
3. Commit y PR

---

Made with ❤️ en la terminal.  
Last updated: 2026-05-14  
License: **GNU GPL v2**
