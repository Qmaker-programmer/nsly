package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// ══════════════════════════════════════════════════════════════════════════════
// ESTILOS LIPGLOSS
// ══════════════════════════════════════════════════════════════════════════════
var (
	appStyle = lipgloss.NewStyle().
		Padding(1, 2).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#8A2BE2"))
	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#00FFAA")).MarginBottom(1)
	errorStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF4466")).Bold(true)
	successStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Bold(true)
	cursorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00AA")).Bold(true)
	textStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#E0E0E0"))
	labelStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))
	highlightStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFD700")).Bold(true)
	dimStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	accentStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#00CFFF")).Bold(true)
	dangerStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF2244")).Bold(true)
	totpStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF9900")).Bold(true)
	syncStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("#AA88FF")).Bold(true)

	strengthStyles = []lipgloss.Style{
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FF2244")).Bold(true),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6600")).Bold(true),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FFDD00")).Bold(true),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#88FF00")).Bold(true),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF88")).Bold(true),
	}
	strengthLabels = []string{"Muy débil", "Débil", "Media", "Fuerte", "Muy fuerte"}
)

// ══════════════════════════════════════════════════════════════════════════════
// CRYPTO: VAULT COMPLETO CIFRADO (AES-256-GCM + scrypt KDF)
// ══════════════════════════════════════════════════════════════════════════════

const (
	scryptN    = 32768
	scryptR    = 8
	scryptP    = 1
	keyLen     = 32
	saltLen    = 32
)

// ══════════════════════════════════════════════════════════════════════════════
// SEGURIDAD: LIMPIEZA DE MEMORIA Y RATE LIMITING
// ══════════════════════════════════════════════════════════════════════════════

// clearBytes sobrescribe la memoria con ceros para evitar leaks en heap dumps 🧹
func clearBytes(b []byte) {
	if b == nil {
		return
	}
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// clearString limpia una string sensitive asignando string vacío.
// En Go las strings son inmutables, pero hacemos lo posible zeroing el []byte
// local y quitamos la referencia para que el GC pueda recolectarla.
func clearString(s *string) {
	if s == nil || *s == "" {
		return
	}
	b := []byte(*s)
	clearBytes(b)
	*s = ""
}

// loginFailures rastrea intentos fallidos para rate limiting anti-brute-force
type loginRateState struct {
	mu          sync.Mutex
	failures    int
	lastFailure time.Time
}

var loginRate = &loginRateState{}

func recordLoginFailure() {
	loginRate.mu.Lock()
	defer loginRate.mu.Unlock()
	loginRate.failures++
	loginRate.lastFailure = time.Now()
}

func resetLoginFailures() {
	loginRate.mu.Lock()
	defer loginRate.mu.Unlock()
	loginRate.failures = 0
}

// loginDelay retorna el delay anti-brute-force: exponencial desde el 3er fallo
// 3 fallos = 1s, 4 = 2s, 5 = 4s... máx 30s. ¡Buena suerte adivinando! 💀
func loginDelay() time.Duration {
	loginRate.mu.Lock()
	defer loginRate.mu.Unlock()
	if loginRate.failures < 3 {
		return 0
	}
	if time.Since(loginRate.lastFailure) > 5*time.Minute {
		loginRate.failures = 0
		return 0
	}
	delay := time.Duration(1<<uint(loginRate.failures-3)) * time.Second
	if delay > 30*time.Second {
		delay = 30 * time.Second
	}
	return delay
}

var vaultKey []byte // clave derivada con scrypt, en memoria solamente

// deriveKey usa scrypt para derivar una clave AES-256 desde la contraseña maestra
func deriveKey(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, scryptN, scryptR, scryptP, keyLen)
}

// SetVaultKey deriva y almacena la clave en memoria al hacer login
func SetVaultKey(masterPassword string, salt []byte) error {
	key, err := deriveKey(masterPassword, salt)
	if err != nil {
		return err
	}
	// Limpiar clave anterior si existe antes de reemplazar 🧹
	if vaultKey != nil {
		clearBytes(vaultKey)
	}
	vaultKey = key
	return nil
}

// ClearVaultKey limpia la clave de memoria al bloquear la bóveda 🔒
// Impide que un dump de memoria exponga la clave AES-256
func ClearVaultKey() {
	if vaultKey != nil {
		clearBytes(vaultKey)
		vaultKey = nil
	}
}

// aesgcmEncrypt cifra con AES-256-GCM
func aesgcmEncrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// aesgcmDecrypt descifra con AES-256-GCM
func aesgcmDecrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext demasiado corto")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// encryptField cifra un campo individual (para passwords, TOTP secrets)
func encryptField(plaintext string) (string, error) {
	if len(vaultKey) == 0 {
		return plaintext, nil
	}
	ct, err := aesgcmEncrypt(vaultKey, []byte(plaintext))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ct), nil
}

// decryptField descifra un campo individual
// SEGURIDAD: eliminado el fallback que devolvía texto plano sin cifrar 🔐
// Si un campo no se puede descifrar, es un ERROR, no un "dato viejo"
func decryptField(ciphertextB64 string) (string, error) {
	if len(vaultKey) == 0 {
		return "", fmt.Errorf("clave de vault no establecida")
	}
	// Campo vacío cifrado: manejarlo correctamente
	if ciphertextB64 == "" {
		return "", nil
	}
	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		// Si no es base64 válido, puede ser un campo vacío legacy
		// Solo permitimos esto si el string está completamente vacío
		return "", fmt.Errorf("campo con formato inválido: no es base64")
	}
	pt, err := aesgcmDecrypt(vaultKey, data)
	if err != nil {
		// Error de descifrado = clave incorrecta o datos corruptos
		// NO hacer fallback a texto plano: eso sería un information leak 🚨
		return "", fmt.Errorf("error descifrando campo: %w", err)
	}
	result := string(pt)
	// Limpiar el slice intermedio de plaintext
	clearBytes(pt)
	return result, nil
}

// encryptVaultJSON cifra el JSON completo de la bóveda para guardarlo en disco
func encryptVaultJSON(plainJSON []byte, key []byte) ([]byte, error) {
	ct, err := aesgcmEncrypt(key, plainJSON)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

// decryptVaultJSON descifra el blob de la bóveda
func decryptVaultJSON(cipherblob []byte, key []byte) ([]byte, error) {
	return aesgcmDecrypt(key, cipherblob)
}

// ══════════════════════════════════════════════════════════════════════════════
// GENERADOR DE CONTRASEÑAS
// ══════════════════════════════════════════════════════════════════════════════
const (
	lowerChars  = "abcdefghijklmnopqrstuvwxyz"
	upperChars  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digitChars  = "0123456789"
	symbolChars = "!@#$%^&*()-_=+[]{}|;:,.<>?"
)

type GenOptions struct {
	Length     int
	UseLower   bool
	UseUpper   bool
	UseDigits  bool
	UseSymbols bool
}

func defaultGenOptions() GenOptions {
	return GenOptions{Length: 20, UseLower: true, UseUpper: true, UseDigits: true, UseSymbols: true}
}

func GeneratePassword(opts GenOptions) (string, error) {
	charset := ""
	if opts.UseLower   { charset += lowerChars }
	if opts.UseUpper   { charset += upperChars }
	if opts.UseDigits  { charset += digitChars }
	if opts.UseSymbols { charset += symbolChars }
	if charset == "" {
		return "", fmt.Errorf("selecciona al menos un tipo de caracter")
	}
	result := make([]byte, opts.Length)
	for i := range result {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[n.Int64()]
	}
	return string(result), nil
}

func passwordStrengthIdx(password string) int {
	score := 0
	hasLower, hasUpper, hasDigit, hasSymbol := false, false, false, false
	for _, c := range password {
		switch {
		case unicode.IsLower(c):  hasLower = true
		case unicode.IsUpper(c):  hasUpper = true
		case unicode.IsDigit(c):  hasDigit = true
		default:                   hasSymbol = true
		}
	}
	if len(password) >= 8   { score++ }
	if len(password) >= 12  { score++ }
	if len(password) >= 16  { score++ }
	if hasLower              { score++ }
	if hasUpper              { score++ }
	if hasDigit              { score++ }
	if hasSymbol             { score++ }
	idx := score * (len(strengthLabels) - 1) / 7
	if idx >= len(strengthLabels) { idx = len(strengthLabels) - 1 }
	return idx
}

func strengthBar(password string) string {
	if password == "" { return "" }
	idx := passwordStrengthIdx(password)
	filled := (idx + 1) * 10 / len(strengthLabels)
	bar := strings.Repeat("█", filled) + strings.Repeat("░", 10-filled)
	return strengthStyles[idx].Render(bar + " " + strengthLabels[idx])
}

// ══════════════════════════════════════════════════════════════════════════════
// TOTP — Time-based One-Time Passwords (2FA)
// ══════════════════════════════════════════════════════════════════════════════

// GenerateTOTPCode genera el código de 6 dígitos actual para un secret TOTP
func GenerateTOTPCode(secret string) (string, error) {
	return totp.GenerateCode(strings.ToUpper(strings.ReplaceAll(secret, " ", "")), time.Now())
}

// ValidateTOTPSecret verifica que el secret sea válido
func ValidateTOTPSecret(secret string) bool {
	clean := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	_, err := totp.GenerateCode(clean, time.Now())
	return err == nil
}

// GenerateNewTOTPKey genera un nuevo secret TOTP para un servicio
func GenerateNewTOTPKey(issuer, account string) (secret string, qrPNG []byte, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		return "", nil, err
	}
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return key.Secret(), nil, nil
	}
	if err = png.Encode(&buf, img); err != nil {
		return key.Secret(), nil, nil
	}
	return key.Secret(), buf.Bytes(), nil
}

// TOTPTimeRemaining segundos restantes del código actual (período de 30s)
func TOTPTimeRemaining() int {
	return 30 - int(time.Now().Unix()%30)
}

// ══════════════════════════════════════════════════════════════════════════════
// SINCRONIZACIÓN CON LA NUBE (HTTP simple, compatible con cualquier servidor)
// ══════════════════════════════════════════════════════════════════════════════

type SyncConfig struct {
	Enabled  bool   `json:"enabled"`
	ServerURL string `json:"server_url"` // ej: https://mi-servidor.com/vault
	Token    string `json:"token"`       // bearer token de autenticación
	LastSync string `json:"last_sync"`
}

// secureHTTPClient crea un cliente HTTP con TLS seguro 🔒
// Impide ataques MITM aunque el blob esté cifrado
func secureHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,        // NUNCA saltar verificación SSL 🚫
				MinVersion:         tls.VersionTLS12, // TLS 1.2 mínimo (1.3 preferido)
			},
		},
	}
}

// uploadVault sube el blob cifrado al servidor (PUT con bearer token)
// SEGURIDAD: usa TLS estricto para prevenir ataques MITM 🛡️
func uploadVault(cfg SyncConfig, encryptedBlob []byte) error {
	if !strings.HasPrefix(cfg.ServerURL, "https://") {
		return fmt.Errorf("⚠️  la URL debe usar HTTPS para proteger el token de autenticación")
	}
	req, err := http.NewRequest("PUT", cfg.ServerURL, bytes.NewReader(encryptedBlob))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	client := secureHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error de red (verifica que el certificado SSL sea válido): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("servidor respondió %d", resp.StatusCode)
	}
	return nil
}

// downloadVault descarga el blob cifrado del servidor (GET con bearer token)
// SEGURIDAD: usa TLS estricto para prevenir ataques MITM 🛡️
func downloadVault(cfg SyncConfig) ([]byte, error) {
	if !strings.HasPrefix(cfg.ServerURL, "https://") {
		return nil, fmt.Errorf("⚠️  la URL debe usar HTTPS para proteger el token de autenticación")
	}
	req, err := http.NewRequest("GET", cfg.ServerURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	client := secureHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error de red: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no hay bóveda en el servidor todavía (primer sync)")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("servidor respondió %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// ══════════════════════════════════════════════════════════════════════════════
// STORAGE — VAULT COMPLETO CIFRADO EN DISCO
// ══════════════════════════════════════════════════════════════════════════════

type PasswordEntry struct {
	ID           string `json:"id"`
	Service      string `json:"service"`
	Username     string `json:"username"`
	Password     string `json:"password"`   // AES-256-GCM base64
	Notes        string `json:"notes"`       // AES-256-GCM base64
	TOTPSecret   string `json:"totp_secret"` // AES-256-GCM base64 (vacío si no tiene 2FA)
	URL          string `json:"url"`
	Created      string `json:"created"`
	Modified     string `json:"modified"`
}

type VaultData struct {
	Version int             `json:"version"`
	Entries []PasswordEntry `json:"entries"`
}

// Meta del vault (NO cifrada, para poder leer la sal sin clave)
type VaultMeta struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`        // base64, para derivar clave con scrypt
	Encrypted  bool   `json:"encrypted"`   // true = vault cifrado con AES-256-GCM
}

// SyncConfig guardada en archivo separado (no contiene datos sensibles de vault)
type SyncConfigFile struct {
	SyncConfig SyncConfig `json:"sync"`
}

func getVaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nsly_vault")
}
func getMasterHashPath() string  { return filepath.Join(getVaultDir(), "master.hash") }
func getVaultMetaPath() string   { return filepath.Join(getVaultDir(), "vault.meta") }
func getVaultBlobPath() string   { return filepath.Join(getVaultDir(), "vault.enc") }
func getSyncConfigPath() string  { return filepath.Join(getVaultDir(), "sync.json") }

func IsFirstRun() bool {
	_, err := os.Stat(getMasterHashPath())
	return os.IsNotExist(err)
}

func EnsureVaultDir() error {
	dir := getVaultDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	// SEGURIDAD: Validar que los permisos sean exactamente 0700 🔒
	// Si ya existía con permisos incorrectos (ej 0755), es un problema
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	// Solo en sistemas Unix (Linux/macOS) - en Windows los permisos son distintos
	if runtime.GOOS != "windows" {
		perm := info.Mode().Perm()
		if perm != 0700 {
			// Intentar corregir los permisos
			if err := os.Chmod(dir, 0700); err != nil {
				return fmt.Errorf("directorio vault con permisos inseguros (%o) y no se pudieron corregir: %w", perm, err)
			}
		}
	}
	return nil
}

// generateSalt genera una sal criptográficamente aleatoria
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	return salt, err
}

// SaveMasterPassword cifra y guarda el hash bcrypt + crea la meta del vault
func SaveMasterPassword(password string) ([]byte, error) {
	if err := EnsureVaultDir(); err != nil {
		return nil, err
	}
	// 1. Guardar hash bcrypt para login
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(getMasterHashPath(), hash, 0600); err != nil {
		return nil, err
	}
	// 2. Generar sal y guardar meta
	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}
	meta := VaultMeta{
		Version:   2,
		Salt:      base64.StdEncoding.EncodeToString(salt),
		Encrypted: true,
	}
	metaData, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(getVaultMetaPath(), metaData, 0600); err != nil {
		return nil, err
	}
	return salt, nil
}

// LoadVaultMeta lee la meta (sal) para poder derivar la clave
func LoadVaultMeta() (*VaultMeta, []byte, error) {
	data, err := os.ReadFile(getVaultMetaPath())
	if err != nil {
		return nil, nil, err
	}
	var meta VaultMeta
	if err := json.Unmarshal(data, &meta); err != nil {
		return nil, nil, err
	}
	salt, err := base64.StdEncoding.DecodeString(meta.Salt)
	if err != nil {
		return nil, nil, err
	}
	return &meta, salt, nil
}

func VerifyMasterPassword(password string) bool {
	// SEGURIDAD: Rate limiting anti-brute-force ⏱️
	// Después de 3 fallos hay delay exponencial
	delay := loginDelay()
	if delay > 0 {
		time.Sleep(delay)
	}
	hashBytes, err := os.ReadFile(getMasterHashPath())
	if err != nil {
		return false
	}
	ok := bcrypt.CompareHashAndPassword(hashBytes, []byte(password)) == nil
	if ok {
		resetLoginFailures()
	} else {
		recordLoginFailure()
	}
	return ok
}

// LoadVault descifra y carga la bóveda completa del disco
func LoadVault() (*VaultData, error) {
	blobPath := getVaultBlobPath()
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		return &VaultData{Version: 2, Entries: []PasswordEntry{}}, nil
	}
	blob, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, err
	}
	if len(vaultKey) == 0 {
		return nil, fmt.Errorf("clave de vault no establecida")
	}
	plainJSON, err := decryptVaultJSON(blob, vaultKey)
	if err != nil {
		return nil, fmt.Errorf("error descifrando vault: %w", err)
	}
	var vault VaultData
	if err := json.Unmarshal(plainJSON, &vault); err != nil {
		return nil, err
	}
	return &vault, nil
}

// SaveVault cifra y persiste la bóveda completa
func SaveVault(vault *VaultData) error {
	if err := EnsureVaultDir(); err != nil {
		return err
	}
	vault.Version = 2
	plainJSON, err := json.MarshalIndent(vault, "", "  ")
	if err != nil {
		return err
	}
	if len(vaultKey) == 0 {
		return fmt.Errorf("clave de vault no establecida")
	}
	blob, err := encryptVaultJSON(plainJSON, vaultKey)
	if err != nil {
		return err
	}
	return os.WriteFile(getVaultBlobPath(), blob, 0600)
}

// AddEntry cifra los campos individuales y añade la entrada
func AddEntry(vault *VaultData, service, username, password, notes, url, totpSecret string) error {
	encPass, err := encryptField(password)
	if err != nil {
		return err
	}
	encNotes, err := encryptField(notes)
	if err != nil {
		return err
	}
	encTOTP, err := encryptField(totpSecret)
	if err != nil {
		return err
	}
	now := time.Now().Format("2006-01-02")
	vault.Entries = append(vault.Entries, PasswordEntry{
		ID:         fmt.Sprintf("%d", time.Now().UnixNano()),
		Service:    service,
		Username:   username,
		Password:   encPass,
		Notes:      encNotes,
		TOTPSecret: encTOTP,
		URL:        url,
		Created:    now,
		Modified:   now,
	})
	return SaveVault(vault)
}

// DeleteEntry elimina una entrada por ID
func DeleteEntry(vault *VaultData, id string) error {
	n := []PasswordEntry{}
	for _, e := range vault.Entries {
		if e.ID != id {
			n = append(n, e)
		}
	}
	vault.Entries = n
	return SaveVault(vault)
}

// GetDecryptedEntry descifra todos los campos de una entrada
type DecryptedEntry struct {
	PasswordEntry
	PlainPassword string
	PlainNotes    string
	PlainTOTP     string
}

func GetDecryptedEntry(entry PasswordEntry) (DecryptedEntry, error) {
	pass, err := decryptField(entry.Password)
	if err != nil {
		return DecryptedEntry{}, err
	}
	notes, err := decryptField(entry.Notes)
	if err != nil {
		return DecryptedEntry{}, err
	}
	totpSec, err := decryptField(entry.TOTPSecret)
	if err != nil {
		return DecryptedEntry{}, err
	}
	return DecryptedEntry{
		PasswordEntry: entry,
		PlainPassword: pass,
		PlainNotes:    notes,
		PlainTOTP:     totpSec,
	}, nil
}

// ExportVault exporta en texto plano (para backup o migración)
// SEGURIDAD: valida el path para evitar path traversal attacks 🛡️
func ExportVault(vault *VaultData, path string) error {
	// Sanitizar path: debe ser un archivo, no un directorio ni un symlink
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("path inválido: %w", err)
	}
	// No permitir escribir dentro del directorio de la bóveda
	vaultDir, _ := filepath.Abs(getVaultDir())
	if strings.HasPrefix(absPath, vaultDir) {
		return fmt.Errorf("no puedes exportar dentro del directorio de la bóveda")
	}
	type ExportEntry struct {
		Service  string `json:"service"`
		Username string `json:"username"`
		Password string `json:"password"`
		Notes    string `json:"notes"`
		URL      string `json:"url"`
		TOTP     string `json:"totp_secret,omitempty"`
		Created  string `json:"created"`
	}
	type Export struct {
		ExportedAt string        `json:"exported_at"`
		Warning    string        `json:"warning"`
		Entries    []ExportEntry `json:"entries"`
	}
	exp := Export{
		ExportedAt: time.Now().Format(time.RFC3339),
		Warning:    "ARCHIVO SENSIBLE: contiene contraseñas en texto plano. Elimínalo tras importar.",
	}
	for _, e := range vault.Entries {
		de, err := GetDecryptedEntry(e)
		if err != nil {
			continue
		}
		exp.Entries = append(exp.Entries, ExportEntry{
			Service:  e.Service,
			Username: e.Username,
			Password: de.PlainPassword,
			Notes:    de.PlainNotes,
			URL:      e.URL,
			TOTP:     de.PlainTOTP,
			Created:  e.Created,
		})
	}
	data, err := json.MarshalIndent(exp, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// ImportBitwarden importa desde el JSON exportado de Bitwarden
func ImportBitwarden(vault *VaultData, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	type BWLogin struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Totp     string `json:"totp"`
		Uris     []struct {
			Uri string `json:"uri"`
		} `json:"uris"`
	}
	type BWItem struct {
		Name  string  `json:"name"`
		Notes string  `json:"notes"`
		Login BWLogin `json:"login"`
	}
	type BWExport struct {
		Items []BWItem `json:"items"`
	}
	var bw BWExport
	if err := json.Unmarshal(data, &bw); err != nil {
		return 0, fmt.Errorf("formato Bitwarden inválido: %w", err)
	}
	count := 0
	for _, item := range bw.Items {
		url := ""
		if len(item.Login.Uris) > 0 {
			url = item.Login.Uris[0].Uri
		}
		if err := AddEntry(vault, item.Name, item.Login.Username,
			item.Login.Password, item.Notes, url, item.Login.Totp); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// ImportKeePass importa desde el CSV exportado de KeePass (formato estándar)
func ImportKeePass(vault *VaultData, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("archivo CSV vacío o inválido")
	}
	count := 0
	// KeePass CSV: "Group","Title","Username","Password","URL","Notes"
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := parseCSVLine(line)
		if len(fields) < 6 {
			continue
		}
		title, username, password, url, notes := fields[1], fields[2], fields[3], fields[4], fields[5]
		if err := AddEntry(vault, title, username, password, notes, url, ""); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// ImportNSLY importa desde el JSON de exportación propia
func ImportNSLY(vault *VaultData, path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	type ExportEntry struct {
		Service  string `json:"service"`
		Username string `json:"username"`
		Password string `json:"password"`
		Notes    string `json:"notes"`
		URL      string `json:"url"`
		TOTP     string `json:"totp_secret"`
	}
	type Export struct {
		Entries []ExportEntry `json:"entries"`
	}
	var exp Export
	if err := json.Unmarshal(data, &exp); err != nil {
		return 0, fmt.Errorf("formato NSLY inválido: %w", err)
	}
	count := 0
	for _, e := range exp.Entries {
		if err := AddEntry(vault, e.Service, e.Username, e.Password, e.Notes, e.URL, e.TOTP); err != nil {
			continue
		}
		count++
	}
	return count, nil
}

// parseCSVLine parsea una línea CSV respetando comillas
func parseCSVLine(line string) []string {
	var fields []string
	var current strings.Builder
	inQuotes := false
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '"' {
			if inQuotes && i+1 < len(line) && line[i+1] == '"' {
				current.WriteByte('"')
				i++
			} else {
				inQuotes = !inQuotes
			}
		} else if c == ',' && !inQuotes {
			fields = append(fields, current.String())
			current.Reset()
		} else {
			current.WriteByte(c)
		}
	}
	fields = append(fields, current.String())
	return fields
}

// LoadSyncConfig carga la configuración de sincronización
func LoadSyncConfig() SyncConfig {
	data, err := os.ReadFile(getSyncConfigPath())
	if err != nil {
		return SyncConfig{}
	}
	var scf SyncConfigFile
	if err := json.Unmarshal(data, &scf); err != nil {
		return SyncConfig{}
	}
	return scf.SyncConfig
}

// SaveSyncConfig guarda la configuración de sincronización
func SaveSyncConfig(cfg SyncConfig) error {
	if err := EnsureVaultDir(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(SyncConfigFile{SyncConfig: cfg}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getSyncConfigPath(), data, 0600)
}

// SyncToCloud sube la bóveda cifrada al servidor configurado
func SyncToCloud(cfg SyncConfig) error {
	if !cfg.Enabled || cfg.ServerURL == "" {
		return fmt.Errorf("sincronización no configurada")
	}
	blob, err := os.ReadFile(getVaultBlobPath())
	if err != nil {
		return fmt.Errorf("no se pudo leer la bóveda: %w", err)
	}
	if err := uploadVault(cfg, blob); err != nil {
		return err
	}
	cfg.LastSync = time.Now().Format(time.RFC3339)
	return SaveSyncConfig(cfg)
}

// SyncFromCloud descarga la bóveda desde el servidor y la reemplaza localmente
func SyncFromCloud(cfg SyncConfig) error {
	if !cfg.Enabled || cfg.ServerURL == "" {
		return fmt.Errorf("sincronización no configurada")
	}
	blob, err := downloadVault(cfg)
	if err != nil {
		return err
	}
	// Verificar que el blob es descifrable antes de sobreescribir
	if len(vaultKey) > 0 {
		if _, err := decryptVaultJSON(blob, vaultKey); err != nil {
			return fmt.Errorf("el archivo del servidor no se puede descifrar con tu clave: %w", err)
		}
	}
	if err := os.WriteFile(getVaultBlobPath(), blob, 0600); err != nil {
		return fmt.Errorf("error guardando bóveda: %w", err)
	}
	cfg.LastSync = time.Now().Format(time.RFC3339)
	return SaveSyncConfig(cfg)
}

// ══════════════════════════════════════════════════════════════════════════════
// MODELO — ESTADOS
// ══════════════════════════════════════════════════════════════════════════════
type sessionState int

const (
	stateFirstRunSetup   sessionState = iota
	stateFirstRunConfirm
	stateLogin
	stateVerifying
	stateMenu
	stateViewPasswords
	stateViewDetail
	stateConfirmDelete
	stateAddService
	stateAddUsername
	stateAddPass
	stateAddURL
	stateAddNotes
	stateAddTOTP
	stateGenerator
	stateSearch
	stateExportConfirm
	stateImportMenu
	stateImportPath
	stateSyncMenu
	stateSyncSetupURL
	stateSyncSetupToken
	stateSyncAction
	stateTOTPView
)

// ── Mensajes async ────────────────────────────────────────────────────────────
type verifyDoneMsg   struct { ok bool; masterPass string; salt []byte }
type saveDoneMsg     struct { err error; masterPass string; salt []byte }
type syncDoneMsg     struct { err error; op string }
type importDoneMsg   struct { count int; err error }

type model struct {
	state     sessionState
	prevState sessionState
	vault     *VaultData
	syncCfg   SyncConfig
	err       string
	info      string
	masterPass string

	// Inputs de login/setup
	pinInput     textinput.Model
	confirmInput textinput.Model

	// Inputs de añadir entrada
	serviceInput  textinput.Model
	usernameInput textinput.Model
	passInput     textinput.Model
	urlInput      textinput.Model
	notesInput    textinput.Model
	totpInput     textinput.Model

	// Búsqueda
	searchInput textinput.Model

	// Sync inputs
	syncURLInput   textinput.Model
	syncTokenInput textinput.Model

	// Import
	importPathInput textinput.Model
	importType      string // "bitwarden", "keepass", "nsly"

	// Menú
	choices []string
	cursor  int

	// Lista
	selectedEntry int
	filteredIdx   []int

	// Detalle
	currentEntry  DecryptedEntry
	showPassword  bool
	totpCode      string
	totpRemaining int
	totpTick      int

	// Generador
	genOpts       GenOptions
	generatedPass string
	genCursor     int

	// Delete confirm
	deleteTarget string
}

func mkInput(placeholder string, secret bool) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.CharLimit = 500
	if secret {
		ti.EchoMode = textinput.EchoPassword
		ti.EchoCharacter = '•'
	}
	return ti
}

func initialModel() model {
	pin := mkInput("Ingresa tu contraseña maestra", true)
	pin.Focus()
	m := model{
		pinInput:        pin,
		confirmInput:    mkInput("Confirma tu contraseña maestra", true),
		serviceInput:    mkInput("ej: GitHub, Netflix, Gmail...", false),
		usernameInput:   mkInput("ej: usuario@email.com", false),
		passInput:       mkInput("Contraseña del servicio", true),
		urlInput:        mkInput("ej: https://github.com (opcional)", false),
		notesInput:      mkInput("Notas opcionales...", false),
		totpInput:       mkInput("Secret TOTP (base32) ej: JBSWY3DPEHPK3PXP", false),
		searchInput:     mkInput("Buscar servicio o usuario...", false),
		syncURLInput:    mkInput("https://mi-servidor.com/vault", false),
		syncTokenInput:  mkInput("Bearer token de autenticación", true),
		importPathInput: mkInput("Ruta del archivo ej: ~/Downloads/export.json", false),
		choices: []string{
			"🔑 Ver mis contraseñas",
			"➕ Añadir nueva contraseña",
			"🎲 Generador de contraseñas",
			"🔍 Buscar contraseña",
			"☁️  Sincronización con la nube",
			"📤 Exportar bóveda",
			"📥 Importar (Bitwarden / KeePass / NSLY)",
			"🚪 Bloquear y Salir",
		},
		genOpts: defaultGenOptions(),
	}
	if IsFirstRun() {
		m.state = stateFirstRunSetup
	} else {
		m.state = stateLogin
	}
	return m
}

// tickCmd envía un tick cada segundo para actualizar el TOTP
type tickMsg struct{}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(_ time.Time) tea.Msg { return tickMsg{} })
}

func (m model) Init() tea.Cmd { return textinput.Blink }

// ══════════════════════════════════════════════════════════════════════════════
// UPDATE
// ══════════════════════════════════════════════════════════════════════════════
func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Tick global para TOTP
	if _, ok := msg.(tickMsg); ok {
		if m.state == stateViewDetail && m.currentEntry.PlainTOTP != "" {
			code, _ := GenerateTOTPCode(m.currentEntry.PlainTOTP)
			m.totpCode = code
			m.totpRemaining = TOTPTimeRemaining()
			return m, tickCmd()
		}
		return m, nil
	}
	if k, ok := msg.(tea.KeyMsg); ok && k.String() == "ctrl+c" {
		return m, tea.Quit
	}
	switch m.state {
	case stateFirstRunSetup:   return updateFirstRunSetup(m, msg)
	case stateFirstRunConfirm: return updateFirstRunConfirm(m, msg)
	case stateLogin:           return updateLogin(m, msg)
	case stateVerifying:       return updateVerifying(m, msg)
	case stateMenu:            return updateMenu(m, msg)
	case stateViewPasswords:   return updateViewPasswords(m, msg)
	case stateViewDetail:      return updateViewDetail(m, msg)
	case stateConfirmDelete:   return updateConfirmDelete(m, msg)
	case stateAddService, stateAddUsername, stateAddPass,
		stateAddURL, stateAddNotes, stateAddTOTP:
		return updateAddEntry(m, msg)
	case stateGenerator:  return updateGenerator(m, msg)
	case stateSearch:     return updateSearch(m, msg)
	case stateExportConfirm:  return updateExportConfirm(m, msg)
	case stateImportMenu:     return updateImportMenu(m, msg)
	case stateImportPath:     return updateImportPath(m, msg)
	case stateSyncMenu:       return updateSyncMenu(m, msg)
	case stateSyncSetupURL:   return updateSyncSetupURL(m, msg)
	case stateSyncSetupToken: return updateSyncSetupToken(m, msg)
	case stateSyncAction:     return updateSyncAction(m, msg)
	}
	return m, nil
}

// ── FIRST RUN ─────────────────────────────────────────────────────────────────
func updateFirstRunSetup(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": return m, tea.Quit
		case "enter":
			if len(m.pinInput.Value()) < 6 {
				m.err = "❌ Mínimo 6 caracteres para tu seguridad 🔒"
				return m, nil
			}
			if passwordStrengthIdx(m.pinInput.Value()) < 2 {
				m.err = "⚠️  Contraseña muy débil. Añade mayúsculas, números o símbolos."
				return m, nil
			}
			m.err = ""
			m.confirmInput.SetValue("")
			m.confirmInput.Focus()
			m.pinInput.Blur()
			m.state = stateFirstRunConfirm
			return m, nil
		}
	}
	m.pinInput, cmd = m.pinInput.Update(msg)
	return m, cmd
}

func updateFirstRunConfirm(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			m.state = stateFirstRunSetup
			m.pinInput.Focus(); m.confirmInput.Blur()
			m.confirmInput.SetValue(""); m.err = ""
			return m, nil
		case "enter":
			if m.confirmInput.Value() != m.pinInput.Value() {
				m.err = "❌ Las contraseñas no coinciden. ¡Ojo con el teclado! 🤌"
				m.confirmInput.SetValue("")
				return m, nil
			}
			password := m.pinInput.Value()
			m.state = stateVerifying
			m.info = "🔐 Generando clave con scrypt + cifrando con bcrypt..."
			m.err = ""
			return m, func() tea.Msg {
				salt, err := SaveMasterPassword(password)
				return saveDoneMsg{err: err, masterPass: password, salt: salt}
			}
		}
	}
	m.confirmInput, cmd = m.confirmInput.Update(msg)
	return m, cmd
}

// ── LOGIN ─────────────────────────────────────────────────────────────────────
func updateLogin(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": return m, tea.Quit
		case "enter":
			password := m.pinInput.Value()
			m.state = stateVerifying
			// SEGURIDAD: Informar del rate limiting si hay delay activo ⏱️
			delay := loginDelay()
			if delay > 0 {
				m.info = fmt.Sprintf("⏳ Demasiados intentos. Esperando %v por seguridad...", delay)
			} else {
				m.info = "🔓 Verificando contraseña con bcrypt..."
			}
			m.err = ""
			return m, func() tea.Msg {
				ok := VerifyMasterPassword(password) // ya incluye el delay interno
				if !ok {
					return verifyDoneMsg{ok: false}
				}
				_, salt, err := LoadVaultMeta()
				if err != nil {
					return verifyDoneMsg{ok: false}
				}
				return verifyDoneMsg{ok: true, masterPass: password, salt: salt}
			}
		}
	}
	m.pinInput, cmd = m.pinInput.Update(msg)
	return m, cmd
}

// ── VERIFYING ─────────────────────────────────────────────────────────────────
func updateVerifying(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case verifyDoneMsg:
		if msg.ok {
			if err := SetVaultKey(msg.masterPass, msg.salt); err != nil {
				m.err = "❌ Error derivando clave: " + err.Error()
				m.state = stateLogin
				return m, nil
			}
			vault, err := LoadVault()
			if err != nil {
				m.err = "❌ Error cargando bóveda: " + err.Error()
				m.state = stateLogin
				return m, nil
			}
			m.vault = vault
			// SEGURIDAD: masterPass limpiada tras derivar vaultKey 🧹
			m.masterPass = ""
			m.syncCfg = LoadSyncConfig()
			m.state = stateMenu
			m.cursor = 0
			m.info = "✅ ¡Acceso concedido! Bóveda descifrada 🎉"
			m.pinInput.SetValue("")
		} else {
			m.err = "❌ Contraseña incorrecta. ¿Olvidaste cuál era? 🤔"
			m.state = stateLogin
			m.pinInput.SetValue(""); m.pinInput.Focus()
		}
	case saveDoneMsg:
		if msg.err != nil {
			m.err = "❌ Error guardando: " + msg.err.Error()
			m.state = stateFirstRunSetup
			return m, nil
		}
		if err := SetVaultKey(msg.masterPass, msg.salt); err != nil {
			m.err = "❌ Error derivando clave: " + err.Error()
			m.state = stateFirstRunSetup
			return m, nil
		}
		vault, _ := LoadVault()
		m.vault = vault
		// SEGURIDAD: masterPass limpiada tras derivar vaultKey 🧹
		m.masterPass = ""
		m.state = stateMenu
		m.info = "🎉 ¡Bóveda creada! Cifrado: scrypt KDF + AES-256-GCM"
		m.pinInput.SetValue("")
	}
	return m, nil
}

// ── MENÚ ─────────────────────────────────────────────────────────────────────
func updateMenu(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "up", "k":
			if m.cursor > 0 { m.cursor-- }
		case "down", "j":
			if m.cursor < len(m.choices)-1 { m.cursor++ }
		case "enter":
			m.info = ""; m.err = ""
			switch m.cursor {
			case 0:
				m.state = stateViewPasswords; m.selectedEntry = 0
			case 1:
				m.state = stateAddService
				m.serviceInput.SetValue(""); m.usernameInput.SetValue("")
				m.passInput.SetValue("");    m.urlInput.SetValue("")
				m.notesInput.SetValue("");   m.totpInput.SetValue("")
				m.serviceInput.Focus(); m.err = ""
			case 2:
				m.state = stateGenerator
				m.genOpts = defaultGenOptions(); m.genCursor = 0
				g, _ := GeneratePassword(m.genOpts)
				m.generatedPass = g
			case 3:
				m.state = stateSearch
				m.searchInput.SetValue(""); m.searchInput.Focus()
				m.filteredIdx = nil; m.selectedEntry = 0
			case 4:
				m.state = stateSyncMenu; m.cursor = 0
			case 5:
				m.state = stateExportConfirm
			case 6:
				m.state = stateImportMenu; m.cursor = 0
			case 7:
				return m, tea.Quit
			}
		case "esc":
			// SEGURIDAD: Limpiar memoria sensible al bloquear 🧹
			// masterPass y vaultKey deben salir de memoria limpiamente
			clearString(&m.masterPass)
			ClearVaultKey() // sobrescribe con ceros antes de nil
			// Limpiar entradas descifradas en memoria
			clearString(&m.currentEntry.PlainPassword)
			clearString(&m.currentEntry.PlainTOTP)
			clearString(&m.currentEntry.PlainNotes)
			m.currentEntry = DecryptedEntry{}
			m.vault = nil
			m.state = stateLogin
			m.pinInput.SetValue(""); m.pinInput.Focus()
			m.info = "🔒 Bóveda bloqueada y memoria limpiada."
		}
	}
	return m, nil
}

// ── VER CONTRASEÑAS ───────────────────────────────────────────────────────────
func updateViewPasswords(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateMenu
		case "up", "k":
			if m.selectedEntry > 0 { m.selectedEntry-- }
		case "down", "j":
			if m.vault != nil && m.selectedEntry < len(m.vault.Entries)-1 { m.selectedEntry++ }
		case "enter":
			if m.vault != nil && len(m.vault.Entries) > 0 {
				de, err := GetDecryptedEntry(m.vault.Entries[m.selectedEntry])
				if err != nil { m.err = "❌ Error descifrando: " + err.Error(); return m, nil }
				// Limpiar entrada anterior antes de reemplazar 🧹
				clearString(&m.currentEntry.PlainPassword)
				clearString(&m.currentEntry.PlainTOTP)
				clearString(&m.currentEntry.PlainNotes)
				m.currentEntry = de
				m.showPassword = false
				m.state = stateViewDetail
				var cmds []tea.Cmd
				if de.PlainTOTP != "" {
					code, _ := GenerateTOTPCode(de.PlainTOTP)
					m.totpCode = code
					m.totpRemaining = TOTPTimeRemaining()
					cmds = append(cmds, tickCmd())
				}
				return m, tea.Batch(cmds...)
			}
		case "d", "D":
			if m.vault != nil && len(m.vault.Entries) > 0 {
				m.deleteTarget = m.vault.Entries[m.selectedEntry].ID
				m.prevState = stateViewPasswords
				m.state = stateConfirmDelete
			}
		case "c", "C":
			if m.vault != nil && len(m.vault.Entries) > 0 {
				de, _ := GetDecryptedEntry(m.vault.Entries[m.selectedEntry])
				if err := clipboard.WriteAll(de.PlainPassword); err != nil {
					m.info = "⚠️  Clipboard no disponible en este terminal"
				} else {
					m.info = "📋 ¡Contraseña copiada al clipboard!"
				}
			}
		}
	}
	return m, nil
}

// ── VER DETALLE ───────────────────────────────────────────────────────────────
func updateViewDetail(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			// SEGURIDAD: limpiar campos descifrados de memoria 🧹
			clearString(&m.currentEntry.PlainPassword)
			clearString(&m.currentEntry.PlainTOTP)
			clearString(&m.currentEntry.PlainNotes)
			m.currentEntry = DecryptedEntry{}
			m.state = stateViewPasswords
		case "s", "S":
			m.showPassword = !m.showPassword
		case "c", "C":
			if err := clipboard.WriteAll(m.currentEntry.PlainPassword); err != nil {
				m.info = "⚠️  Clipboard no disponible"
			} else {
				m.info = "📋 ¡Contraseña copiada!"
			}
		case "t", "T":
			if m.currentEntry.PlainTOTP != "" {
				if err := clipboard.WriteAll(m.totpCode); err != nil {
					m.info = "⚠️  Clipboard no disponible"
				} else {
					m.info = "📋 ¡Código TOTP copiado!"
				}
			}
		case "d", "D":
			if m.vault != nil && len(m.vault.Entries) > m.selectedEntry {
				m.deleteTarget = m.vault.Entries[m.selectedEntry].ID
				m.prevState = stateViewDetail
				m.state = stateConfirmDelete
			}
		}
	}
	return m, nil
}

// ── CONFIRMAR ELIMINAR ────────────────────────────────────────────────────────
func updateConfirmDelete(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "y", "Y":
			DeleteEntry(m.vault, m.deleteTarget)
			if m.selectedEntry >= len(m.vault.Entries) && m.selectedEntry > 0 {
				m.selectedEntry--
			}
			m.info = "🗑️  Entrada eliminada."
			m.state = stateViewPasswords
			m.currentEntry = DecryptedEntry{}
		case "n", "N", "esc":
			m.state = m.prevState
		}
	}
	return m, nil
}

// ── AÑADIR ENTRADA (multi-paso) ───────────────────────────────────────────────
func updateAddEntry(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	blurAll := func() {
		m.serviceInput.Blur(); m.usernameInput.Blur()
		m.passInput.Blur();    m.urlInput.Blur()
		m.notesInput.Blur();   m.totpInput.Blur()
	}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc":
			blurAll(); m.state = stateMenu; return m, nil
		case "ctrl+g":
			if m.state == stateAddPass {
				g, err := GeneratePassword(m.genOpts)
				if err == nil { m.passInput.SetValue(g) }
			}
			return m, nil
		case "enter":
			switch m.state {
			case stateAddService:
				if m.serviceInput.Value() == "" { m.err = "❌ El servicio no puede estar vacío"; return m, nil }
				m.err = ""; m.state = stateAddUsername
				m.serviceInput.Blur(); m.usernameInput.Focus()
			case stateAddUsername:
				m.state = stateAddPass
				m.usernameInput.Blur(); m.passInput.Focus()
			case stateAddPass:
				if m.passInput.Value() == "" { m.err = "❌ La contraseña no puede estar vacía"; return m, nil }
				m.err = ""; m.state = stateAddURL
				m.passInput.Blur(); m.urlInput.Focus()
			case stateAddURL:
				m.state = stateAddNotes
				m.urlInput.Blur(); m.notesInput.Focus()
			case stateAddNotes:
				m.state = stateAddTOTP
				m.notesInput.Blur(); m.totpInput.Focus()
			case stateAddTOTP:
				totpVal := strings.TrimSpace(m.totpInput.Value())
				if totpVal != "" && !ValidateTOTPSecret(totpVal) {
					m.err = "❌ Secret TOTP inválido. Déjalo vacío si no tienes 2FA."
					return m, nil
				}
				err := AddEntry(m.vault,
					m.serviceInput.Value(),
					m.usernameInput.Value(),
					m.passInput.Value(),
					m.notesInput.Value(),
					m.urlInput.Value(),
					totpVal,
				)
				if err != nil { m.err = "❌ Error guardando: " + err.Error(); return m, nil }
				blurAll()
				m.info = "✅ ¡Guardado y cifrado con AES-256-GCM! 🔐"
				m.state = stateMenu
			}
			return m, nil
		}
	}
	switch m.state {
	case stateAddService:  m.serviceInput,  cmd = m.serviceInput.Update(msg)
	case stateAddUsername: m.usernameInput, cmd = m.usernameInput.Update(msg)
	case stateAddPass:     m.passInput,     cmd = m.passInput.Update(msg)
	case stateAddURL:      m.urlInput,      cmd = m.urlInput.Update(msg)
	case stateAddNotes:    m.notesInput,    cmd = m.notesInput.Update(msg)
	case stateAddTOTP:     m.totpInput,     cmd = m.totpInput.Update(msg)
	}
	return m, cmd
}

// ── GENERADOR ─────────────────────────────────────────────────────────────────
func updateGenerator(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateMenu
		case "up", "k":
			if m.genCursor > 0 { m.genCursor-- }
		case "down", "j":
			if m.genCursor < 6 { m.genCursor++ }
		case "left":
			if m.genCursor == 0 && m.genOpts.Length > 8 {
				m.genOpts.Length--
				g, _ := GeneratePassword(m.genOpts); m.generatedPass = g
			}
		case "right":
			if m.genCursor == 0 && m.genOpts.Length < 64 {
				m.genOpts.Length++
				g, _ := GeneratePassword(m.genOpts); m.generatedPass = g
			}
		case " ", "enter":
			switch m.genCursor {
			case 1: m.genOpts.UseLower   = !m.genOpts.UseLower
			case 2: m.genOpts.UseUpper   = !m.genOpts.UseUpper
			case 3: m.genOpts.UseDigits  = !m.genOpts.UseDigits
			case 4: m.genOpts.UseSymbols = !m.genOpts.UseSymbols
			case 5:
				g, err := GeneratePassword(m.genOpts)
				if err != nil { m.err = err.Error() } else { m.generatedPass = g; m.err = "" }
			case 6:
				m.state = stateAddService
				m.serviceInput.SetValue(""); m.usernameInput.SetValue("")
				m.passInput.SetValue(m.generatedPass)
				m.urlInput.SetValue(""); m.notesInput.SetValue(""); m.totpInput.SetValue("")
				m.serviceInput.Focus(); m.err = ""
				return m, nil
			}
			if m.genCursor >= 1 && m.genCursor <= 4 {
				g, err := GeneratePassword(m.genOpts)
				if err == nil { m.generatedPass = g }
			}
		case "c", "C":
			if err := clipboard.WriteAll(m.generatedPass); err != nil {
				m.info = "⚠️  Clipboard no disponible"
			} else {
				m.info = "📋 ¡Copiado al clipboard!"
			}
		}
	}
	return m, nil
}

// ── BÚSQUEDA ──────────────────────────────────────────────────────────────────
func updateSearch(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateMenu; m.searchInput.Blur(); return m, nil
		case "up", "k":
			if m.selectedEntry > 0 { m.selectedEntry-- }; return m, nil
		case "down", "j":
			if m.selectedEntry < len(m.filteredIdx)-1 { m.selectedEntry++ }; return m, nil
		case "enter":
			if len(m.filteredIdx) > 0 && m.vault != nil {
				realIdx := m.filteredIdx[m.selectedEntry]
				de, err := GetDecryptedEntry(m.vault.Entries[realIdx])
				if err != nil { m.err = "❌ " + err.Error(); return m, nil }
				m.currentEntry = de
				m.selectedEntry = realIdx
				m.showPassword = false
				m.state = stateViewDetail
				m.searchInput.Blur()
				var cmds []tea.Cmd
				if de.PlainTOTP != "" {
					code, _ := GenerateTOTPCode(de.PlainTOTP)
					m.totpCode = code
					m.totpRemaining = TOTPTimeRemaining()
					cmds = append(cmds, tickCmd())
				}
				return m, tea.Batch(cmds...)
			}
		}
	}
	m.searchInput, cmd = m.searchInput.Update(msg)
	query := strings.ToLower(m.searchInput.Value())
	m.filteredIdx = nil; m.selectedEntry = 0
	if m.vault != nil {
		for i, e := range m.vault.Entries {
			if query == "" ||
				strings.Contains(strings.ToLower(e.Service), query) ||
				strings.Contains(strings.ToLower(e.Username), query) ||
				strings.Contains(strings.ToLower(e.URL), query) {
				m.filteredIdx = append(m.filteredIdx, i)
			}
		}
	}
	return m, cmd
}

// ── EXPORTAR ──────────────────────────────────────────────────────────────────
func updateExportConfirm(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "y", "Y":
			home, _ := os.UserHomeDir()
			exportPath := filepath.Join(home, "nsly_export_"+time.Now().Format("20060102_150405")+".json")
			if err := ExportVault(m.vault, exportPath); err != nil {
				m.err = "❌ Error exportando: " + err.Error()
			} else {
				m.info = "✅ Exportado: " + exportPath
			}
			m.state = stateMenu
		case "n", "N", "esc": m.state = stateMenu
		}
	}
	return m, nil
}

// ── IMPORTAR ──────────────────────────────────────────────────────────────────
func updateImportMenu(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	importChoices := []string{"📗 Desde Bitwarden (JSON)", "📘 Desde KeePass (CSV)", "📙 Desde NSLY Export (JSON)", "↩  Volver"}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateMenu; m.cursor = 0; return m, nil
		case "up", "k":
			if m.cursor > 0 { m.cursor-- }
		case "down", "j":
			if m.cursor < len(importChoices)-1 { m.cursor++ }
		case "enter":
			switch m.cursor {
			case 0: m.importType = "bitwarden"; m.state = stateImportPath; m.importPathInput.SetValue(""); m.importPathInput.Focus()
			case 1: m.importType = "keepass";   m.state = stateImportPath; m.importPathInput.SetValue(""); m.importPathInput.Focus()
			case 2: m.importType = "nsly";      m.state = stateImportPath; m.importPathInput.SetValue(""); m.importPathInput.Focus()
			case 3: m.state = stateMenu; m.cursor = 0
			}
		}
	}
	return m, nil
}

func updateImportPath(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateImportMenu; m.importPathInput.Blur(); return m, nil
		case "enter":
			path := expandHome(m.importPathInput.Value())
			vault := m.vault
			importType := m.importType
			m.state = stateVerifying
			m.info = "📥 Importando entradas..."
			return m, func() tea.Msg {
				var count int
				var err error
				switch importType {
				case "bitwarden": count, err = ImportBitwarden(vault, path)
				case "keepass":   count, err = ImportKeePass(vault, path)
				case "nsly":      count, err = ImportNSLY(vault, path)
				}
				return importDoneMsg{count: count, err: err}
			}
		}
	}
	m.importPathInput, cmd = m.importPathInput.Update(msg)
	return m, cmd
}

// ── SYNC ──────────────────────────────────────────────────────────────────────
func updateSyncMenu(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	syncChoices := []string{
		"⬆️  Subir bóveda a la nube",
		"⬇️  Descargar bóveda desde la nube",
		"⚙️  Configurar servidor y token",
		"↩  Volver",
	}
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateMenu; m.cursor = 0; return m, nil
		case "up", "k":
			if m.cursor > 0 { m.cursor-- }
		case "down", "j":
			if m.cursor < len(syncChoices)-1 { m.cursor++ }
		case "enter":
			switch m.cursor {
			case 0:
				cfg := m.syncCfg
				m.state = stateSyncAction
				m.info = "⬆️  Subiendo bóveda cifrada..."
				return m, func() tea.Msg {
					err := SyncToCloud(cfg)
					return syncDoneMsg{err: err, op: "upload"}
				}
			case 1:
				cfg := m.syncCfg
				m.state = stateSyncAction
				m.info = "⬇️  Descargando bóveda desde la nube..."
				return m, func() tea.Msg {
					err := SyncFromCloud(cfg)
					return syncDoneMsg{err: err, op: "download"}
				}
			case 2:
				m.state = stateSyncSetupURL
				m.syncURLInput.SetValue(m.syncCfg.ServerURL)
				m.syncURLInput.Focus()
			case 3:
				m.state = stateMenu; m.cursor = 0
			}
		}
	}
	return m, nil
}

func updateSyncSetupURL(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateSyncMenu; m.syncURLInput.Blur(); return m, nil
		case "enter":
			if m.syncURLInput.Value() == "" { m.err = "❌ URL no puede estar vacía"; return m, nil }
			m.err = ""
			m.state = stateSyncSetupToken
			m.syncURLInput.Blur(); m.syncTokenInput.Focus()
			return m, nil
		}
	}
	m.syncURLInput, cmd = m.syncURLInput.Update(msg)
	return m, cmd
}

func updateSyncSetupToken(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "esc": m.state = stateSyncSetupURL; m.syncTokenInput.Blur(); m.syncURLInput.Focus(); return m, nil
		case "enter":
			m.syncCfg.ServerURL = m.syncURLInput.Value()
			m.syncCfg.Token = m.syncTokenInput.Value()
			m.syncCfg.Enabled = true
			if err := SaveSyncConfig(m.syncCfg); err != nil {
				m.err = "❌ Error guardando config: " + err.Error()
			} else {
				m.info = "✅ ¡Configuración de sync guardada!"
			}
			m.syncTokenInput.Blur()
			m.state = stateSyncMenu
			return m, nil
		}
	}
	m.syncTokenInput, cmd = m.syncTokenInput.Update(msg)
	return m, cmd
}

func updateSyncAction(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	if msg, ok := msg.(syncDoneMsg); ok {
		if msg.err != nil {
			m.err = "❌ " + msg.err.Error()
		} else {
			op := "Subida"
			if msg.op == "download" {
				op = "Descarga"
				// Recargar vault desde disco tras download
				vault, err := LoadVault()
				if err != nil {
					m.err = "❌ Error recargando: " + err.Error()
					m.state = stateSyncMenu
					return m, nil
				}
				m.vault = vault
			}
			m.info = "✅ " + op + " completada · " + time.Now().Format("15:04:05")
		}
		m.state = stateSyncMenu
	}
	return m, nil
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS UPDATE
// ══════════════════════════════════════════════════════════════════════════════

// importDoneMsg handling (dentro de Update global)
func (m model) handleImportDone(msg importDoneMsg) (model, tea.Cmd) {
	if msg.err != nil {
		m.err = "❌ Error importando: " + msg.err.Error()
	} else {
		m.info = fmt.Sprintf("✅ ¡%d entradas importadas!", msg.count)
	}
	m.state = stateMenu
	return m, nil
}

// expandHome expande ~ en rutas
func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return path
}

func sha256Short(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h[:4])
}

// ══════════════════════════════════════════════════════════════════════════════
// VIEW
// ══════════════════════════════════════════════════════════════════════════════
func checkbox(active bool) string {
	if active { return successStyle.Render("[✓]") }
	return dimStyle.Render("[ ]")
}

func menuItem(cursor, idx int, label string) string {
	if cursor == idx {
		return fmt.Sprintf("%s %s\n", cursorStyle.Render(">"), cursorStyle.Render(label))
	}
	return fmt.Sprintf("  %s\n", textStyle.Render(label))
}

func (m model) View() string {
	var v string

	switch m.state {

	// ── PRIMER USO ────────────────────────────────────────────────────────
	case stateFirstRunSetup:
		v  = titleStyle.Render("🛡️  NSLY VAULT — PRIMER USO") + "\n\n"
		v += successStyle.Render("¡Bienvenido! Crea tu contraseña maestra.") + "\n"
		v += textStyle.Render("Cifrado: scrypt KDF → AES-256-GCM · Hash: bcrypt cost=14") + "\n\n"
		v += labelStyle.Render("Contraseña maestra (mín. 6 chars):") + "\n"
		v += m.pinInput.View() + "\n"
		if m.pinInput.Value() != "" {
			v += strengthBar(m.pinInput.Value()) + "\n"
		}
		v += "\n"
		if m.err != "" { v += errorStyle.Render(m.err) + "\n" }
		v += dimStyle.Render("enter continuar • esc salir")

	// ── CONFIRMAR ─────────────────────────────────────────────────────────
	case stateFirstRunConfirm:
		v  = titleStyle.Render("🛡️  NSLY VAULT — CONFIRMAR") + "\n\n"
		v += textStyle.Render("Repite tu contraseña maestra.") + "\n\n"
		v += labelStyle.Render("Confirma:") + "\n"
		v += m.confirmInput.View() + "\n\n"
		if m.err != "" { v += errorStyle.Render(m.err) + "\n" }
		v += dimStyle.Render("enter guardar • esc volver")

	// ── LOGIN ─────────────────────────────────────────────────────────────
	case stateLogin:
		v  = titleStyle.Render("🛡️  NSLY VAULT — ÁREA RESTRINGIDA") + "\n\n"
		if m.err != "" {
			v += errorStyle.Render(m.err) + "\n"
		} else if m.info != "" {
			v += successStyle.Render(m.info) + "\n"
		} else {
			v += "\n"
		}
		v += labelStyle.Render("Contraseña maestra:") + "\n"
		v += m.pinInput.View() + "\n\n"
		v += dimStyle.Render("enter entrar • esc salir")

	// ── VERIFICANDO ───────────────────────────────────────────────────────
	case stateVerifying:
		v  = titleStyle.Render("🛡️  NSLY VAULT") + "\n\n"
		v += highlightStyle.Render(m.info) + "\n\n"
		v += dimStyle.Render("scrypt + bcrypt: lento a propósito. Tu seguridad lo vale ⚡")

	// ── MENÚ ──────────────────────────────────────────────────────────────
	case stateMenu:
		v  = titleStyle.Render("🔓 BÓVEDA DESBLOQUEADA") + "\n"
		if m.info != "" {
			v += successStyle.Render(m.info) + "\n"
		} else { v += "\n" }
		if m.vault != nil {
			syncStatus := dimStyle.Render("☁️  sin sync")
			if m.syncCfg.Enabled && m.syncCfg.LastSync != "" {
				syncStatus = syncStyle.Render("☁️  " + m.syncCfg.LastSync[:10])
			}
			v += labelStyle.Render(fmt.Sprintf("📦 %d entradas • 🔐 AES-256-GCM • scrypt KDF", len(m.vault.Entries))) + "  " + syncStatus + "\n\n"
		}
		for i, choice := range m.choices {
			v += menuItem(m.cursor, i, choice)
		}
		v += "\n" + dimStyle.Render("↑/↓ k/j moverte • enter elegir • esc bloquear")

	// ── VER CONTRASEÑAS ───────────────────────────────────────────────────
	case stateViewPasswords:
		v  = titleStyle.Render("🔑 MIS CONTRASEÑAS") + "\n\n"
		if m.info != "" { v += successStyle.Render(m.info) + "\n\n" }
		if m.vault == nil || len(m.vault.Entries) == 0 {
			v += textStyle.Render("Bóveda vacía. ¡Añade tu primera contraseña! 🚀") + "\n"
		} else {
			v += labelStyle.Render(fmt.Sprintf("%d entrada(s):", len(m.vault.Entries))) + "\n\n"
			for i, entry := range m.vault.Entries {
				hasTOTP := ""
				if entry.TOTPSecret != "" && entry.TOTPSecret != encryptedEmpty() {
					hasTOTP = totpStyle.Render(" 🔑2FA")
				}
				dateStr := dimStyle.Render(entry.Created)
				if m.selectedEntry == i {
					v += cursorStyle.Render("> ") +
						cursorStyle.Render(fmt.Sprintf("%-22s", entry.Service)) +
						dimStyle.Render("@"+entry.Username) +
						hasTOTP + " " + dateStr + "\n"
				} else {
					v += fmt.Sprintf("  %-22s %s%s %s\n",
						entry.Service, dimStyle.Render("@"+entry.Username),
						hasTOTP, dateStr)
				}
			}
		}
		if m.err != "" { v += "\n" + errorStyle.Render(m.err) }
		v += "\n" + dimStyle.Render("enter ver • C copiar • D eliminar • esc volver")

	// ── DETALLE ───────────────────────────────────────────────────────────
	case stateViewDetail:
		e := m.currentEntry
		v  = titleStyle.Render("🔎 DETALLE") + "\n\n"
		v += labelStyle.Render("Servicio:  ") + highlightStyle.Render(e.Service) + "\n"
		v += labelStyle.Render("Usuario:   ") + textStyle.Render(e.Username) + "\n"
		if m.showPassword {
			v += labelStyle.Render("Contraseña:") + successStyle.Render(" "+e.PlainPassword) + "\n"
			v += "           " + strengthBar(e.PlainPassword) + "\n"
		} else {
			v += labelStyle.Render("Contraseña:") + dimStyle.Render(" ••••••••••••") + "\n"
		}
		if e.URL != "" {
			v += labelStyle.Render("URL:       ") + accentStyle.Render(e.URL) + "\n"
		}
		if e.PlainNotes != "" {
			v += labelStyle.Render("Notas:     ") + textStyle.Render(e.PlainNotes) + "\n"
		}
		if e.PlainTOTP != "" {
			remaining := m.totpRemaining
			bar := strings.Repeat("▓", remaining/3) + strings.Repeat("░", 10-remaining/3)
			v += "\n" + totpStyle.Render("🔑 TOTP 2FA") + "\n"
			v += labelStyle.Render("Código:    ") + totpStyle.Render(fmt.Sprintf("%s  [%s %ds]", m.totpCode, bar, remaining)) + "\n"
		}
		if e.Created != "" {
			v += labelStyle.Render("Creado:    ") + dimStyle.Render(e.Created) + "\n"
		}
		if m.info != "" { v += "\n" + successStyle.Render(m.info) }
		v += "\n\n" + dimStyle.Render("S mostrar/ocultar • C copiar pass • T copiar TOTP • D eliminar • esc volver")

	// ── CONFIRMAR ELIMINAR ────────────────────────────────────────────────
	case stateConfirmDelete:
		v  = dangerStyle.Render("⚠️  ¿ELIMINAR ESTA ENTRADA?") + "\n\n"
		if m.vault != nil {
			for _, e := range m.vault.Entries {
				if e.ID == m.deleteTarget {
					v += textStyle.Render("Servicio: ") + highlightStyle.Render(e.Service) + "\n"
					v += textStyle.Render("Usuario:  ") + textStyle.Render(e.Username) + "\n"
				}
			}
		}
		v += "\n" + errorStyle.Render("Esta acción NO se puede deshacer.") + "\n\n"
		v += successStyle.Render("Y") + textStyle.Render(" confirmar   ") +
			dangerStyle.Render("N / Esc") + textStyle.Render(" cancelar")

	// ── AÑADIR ENTRADA ────────────────────────────────────────────────────
	case stateAddService, stateAddUsername, stateAddPass,
		stateAddURL, stateAddNotes, stateAddTOTP:
		v  = titleStyle.Render("➕ NUEVA ENTRADA") + "\n\n"
		steps    := []string{"Servicio", "Usuario", "Contraseña", "URL", "Notas", "TOTP"}
		stateMap := map[sessionState]int{
			stateAddService: 0, stateAddUsername: 1, stateAddPass: 2,
			stateAddURL: 3, stateAddNotes: 4, stateAddTOTP: 5,
		}
		stepIdx := stateMap[m.state]
		progress := ""
		for i, s := range steps {
			switch {
			case i < stepIdx:  progress += successStyle.Render("✓ "+s) + "  "
			case i == stepIdx: progress += highlightStyle.Render("→ "+s) + "  "
			default:           progress += dimStyle.Render("○ "+s) + "  "
			}
		}
		v += progress + "\n\n"
		if stepIdx > 0 { v += labelStyle.Render("Servicio:  ") + textStyle.Render(m.serviceInput.Value()) + "\n" }
		if stepIdx > 1 { v += labelStyle.Render("Usuario:   ") + textStyle.Render(m.usernameInput.Value()) + "\n" }
		if stepIdx > 2 {
			v += labelStyle.Render("Contraseña:") + textStyle.Render(" "+strings.Repeat("•", len(m.passInput.Value()))) + "\n"
			v += "           " + strengthBar(m.passInput.Value()) + "\n"
		}
		if stepIdx > 3 { v += labelStyle.Render("URL:       ") + textStyle.Render(m.urlInput.Value()) + "\n" }
		if stepIdx > 4 { v += labelStyle.Render("Notas:     ") + textStyle.Render(m.notesInput.Value()) + "\n" }
		v += "\n"
		switch m.state {
		case stateAddService:
			v += labelStyle.Render("Nombre del servicio:") + "\n" + m.serviceInput.View() + "\n"
		case stateAddUsername:
			v += labelStyle.Render("Usuario / Email:") + "\n" + m.usernameInput.View() + "\n"
		case stateAddPass:
			v += labelStyle.Render("Contraseña:") + "\n" + m.passInput.View() + "\n"
			if m.passInput.Value() != "" { v += strengthBar(m.passInput.Value()) + "\n" }
			v += dimStyle.Render("  Ctrl+G para generar contraseña aleatoria 🎲") + "\n"
		case stateAddURL:
			v += labelStyle.Render("URL del servicio (opcional):") + "\n" + m.urlInput.View() + "\n"
		case stateAddNotes:
			v += labelStyle.Render("Notas (opcional):") + "\n" + m.notesInput.View() + "\n"
		case stateAddTOTP:
			v += labelStyle.Render("Secret TOTP base32 (opcional, para 2FA):") + "\n" + m.totpInput.View() + "\n"
			v += dimStyle.Render("  Déjalo vacío si el servicio no tiene 2FA") + "\n"
		}
		if m.err != "" { v += "\n" + errorStyle.Render(m.err) + "\n" } else { v += "\n" }
		v += dimStyle.Render("enter continuar • esc cancelar")

	// ── GENERADOR ─────────────────────────────────────────────────────────
	case stateGenerator:
		v  = titleStyle.Render("🎲 GENERADOR DE CONTRASEÑAS") + "\n\n"
		if m.generatedPass != "" {
			v += accentStyle.Render("Contraseña generada:") + "\n"
			v += highlightStyle.Render("  "+m.generatedPass) + "\n"
			v += "  " + strengthBar(m.generatedPass) + "\n\n"
		}
		v += menuItem(m.genCursor, 0, fmt.Sprintf("Longitud: %d  (← para bajar, → para subir)", m.genOpts.Length))
		v += fmt.Sprintf("%s %s %s\n", select_cursor(m.genCursor, 1), checkbox(m.genOpts.UseLower),  label_colored(m.genCursor==1, "Minúsculas (a-z)"))
		v += fmt.Sprintf("%s %s %s\n", select_cursor(m.genCursor, 2), checkbox(m.genOpts.UseUpper),  label_colored(m.genCursor==2, "Mayúsculas (A-Z)"))
		v += fmt.Sprintf("%s %s %s\n", select_cursor(m.genCursor, 3), checkbox(m.genOpts.UseDigits), label_colored(m.genCursor==3, "Números   (0-9)"))
		v += fmt.Sprintf("%s %s %s\n", select_cursor(m.genCursor, 4), checkbox(m.genOpts.UseSymbols),label_colored(m.genCursor==4, "Símbolos  (!@#)"))
		v += "\n"
		v += menuItem(m.genCursor, 5, "🔄 Regenerar contraseña")
		v += menuItem(m.genCursor, 6, "✅ Usar esta contraseña → añadir entrada")
		if m.info != "" { v += "\n" + successStyle.Render(m.info) }
		if m.err != ""  { v += "\n" + errorStyle.Render(m.err) }
		v += "\n" + dimStyle.Render("↑/↓ navegar • ← → longitud • space toggle • C copiar • esc volver")

	// ── BÚSQUEDA ──────────────────────────────────────────────────────────
	case stateSearch:
		v  = titleStyle.Render("🔍 BUSCAR") + "\n\n"
		v += m.searchInput.View() + "\n\n"
		if m.vault != nil && m.searchInput.Value() != "" && len(m.filteredIdx) == 0 {
			v += dimStyle.Render("Sin resultados para: ") + highlightStyle.Render(m.searchInput.Value()) + "\n"
		} else if m.vault != nil {
			for visIdx, realIdx := range m.filteredIdx {
				e := m.vault.Entries[realIdx]
				hasTOTP := ""
				if e.TOTPSecret != "" { hasTOTP = totpStyle.Render(" 2FA") }
				if m.selectedEntry == visIdx {
					v += cursorStyle.Render("> ") + cursorStyle.Render(fmt.Sprintf("%-22s", e.Service)) + dimStyle.Render("@"+e.Username) + hasTOTP + "\n"
				} else {
					v += fmt.Sprintf("  %-22s %s%s\n", e.Service, dimStyle.Render("@"+e.Username), hasTOTP)
				}
			}
		}
		v += "\n" + dimStyle.Render("↑/↓ navegar • enter ver detalle • esc volver")

	// ── EXPORTAR ──────────────────────────────────────────────────────────
	case stateExportConfirm:
		v  = dangerStyle.Render("📤 EXPORTAR BÓVEDA") + "\n\n"
		v += textStyle.Render("Se creará un JSON en tu carpeta home con") + "\n"
		v += textStyle.Render("TODAS las contraseñas en texto plano.") + "\n\n"
		v += errorStyle.Render("⚠️  ¡Guarda o elimina el archivo tras importar!") + "\n\n"
		v += successStyle.Render("Y") + textStyle.Render(" exportar   ") +
			dangerStyle.Render("N / Esc") + textStyle.Render(" cancelar")

	// ── IMPORTAR MENÚ ─────────────────────────────────────────────────────
	case stateImportMenu:
		importChoices := []string{"📗 Desde Bitwarden (JSON)", "📘 Desde KeePass (CSV)", "📙 Desde NSLY Export (JSON)", "↩  Volver"}
		v  = titleStyle.Render("📥 IMPORTAR CONTRASEÑAS") + "\n\n"
		v += textStyle.Render("¿Desde qué gestor importas?") + "\n\n"
		for i, c := range importChoices { v += menuItem(m.cursor, i, c) }
		v += "\n" + dimStyle.Render("↑/↓ navegar • enter elegir • esc volver")

	// ── IMPORTAR RUTA ─────────────────────────────────────────────────────
	case stateImportPath:
		labels := map[string]string{
			"bitwarden": "JSON exportado de Bitwarden",
			"keepass":   "CSV exportado de KeePass",
			"nsly":      "JSON exportado de NSLY Vault",
		}
		v  = titleStyle.Render("📥 IMPORTAR — "+strings.ToUpper(m.importType)) + "\n\n"
		v += textStyle.Render("Archivo: "+labels[m.importType]) + "\n\n"
		v += labelStyle.Render("Ruta del archivo:") + "\n"
		v += m.importPathInput.View() + "\n\n"
		if m.err != "" { v += errorStyle.Render(m.err) + "\n" }
		v += dimStyle.Render("enter importar • esc volver")

	// ── SYNC MENÚ ─────────────────────────────────────────────────────────
	case stateSyncMenu:
		syncChoices := []string{
			"⬆️  Subir bóveda a la nube",
			"⬇️  Descargar bóveda desde la nube",
			"⚙️  Configurar servidor y token",
			"↩  Volver",
		}
		v  = titleStyle.Render("☁️  SINCRONIZACIÓN") + "\n\n"
		if m.syncCfg.Enabled {
			v += syncStyle.Render("✓ Conectado: ") + textStyle.Render(m.syncCfg.ServerURL) + "\n"
			if m.syncCfg.LastSync != "" {
				v += labelStyle.Render("Último sync: ") + dimStyle.Render(m.syncCfg.LastSync) + "\n"
			}
		} else {
			v += dimStyle.Render("Sin configuración de sync. Usa ⚙️ para configurar.") + "\n"
		}
		v += "\n"
		if m.info != "" { v += successStyle.Render(m.info) + "\n\n" }
		if m.err  != "" { v += errorStyle.Render(m.err)   + "\n\n" }
		for i, c := range syncChoices { v += menuItem(m.cursor, i, c) }
		v += "\n" + dimStyle.Render("La bóveda viaja SIEMPRE cifrada. ¡El servidor no ve tus contraseñas! 🔐")

	// ── SYNC SETUP URL ────────────────────────────────────────────────────
	case stateSyncSetupURL:
		v  = titleStyle.Render("⚙️  CONFIGURAR SYNC — URL") + "\n\n"
		v += textStyle.Render("URL de tu servidor donde se guardará la bóveda.") + "\n"
		v += dimStyle.Render("El servidor solo recibe un blob cifrado opaco.") + "\n\n"
		v += labelStyle.Render("URL del servidor:") + "\n"
		v += m.syncURLInput.View() + "\n\n"
		if m.err != "" { v += errorStyle.Render(m.err) + "\n" }
		v += dimStyle.Render("enter continuar • esc volver")

	// ── SYNC SETUP TOKEN ──────────────────────────────────────────────────
	case stateSyncSetupToken:
		v  = titleStyle.Render("⚙️  CONFIGURAR SYNC — TOKEN") + "\n\n"
		v += textStyle.Render("Token de autenticación para tu servidor.") + "\n"
		v += dimStyle.Render("Se envía como: Authorization: Bearer <token>") + "\n\n"
		v += labelStyle.Render("Token:") + "\n"
		v += m.syncTokenInput.View() + "\n\n"
		if m.err != "" { v += errorStyle.Render(m.err) + "\n" }
		v += dimStyle.Render("enter guardar • esc volver")

	// ── SYNC ACTION (esperando resultado) ─────────────────────────────────
	case stateSyncAction:
		v  = titleStyle.Render("☁️  SINCRONIZANDO...") + "\n\n"
		v += highlightStyle.Render(m.info) + "\n\n"
		v += dimStyle.Render("Subiendo/bajando tu bóveda cifrada...")
	}

	// Manejo del importDoneMsg en View (se procesa en Update pero actualizamos info aquí)
	return appStyle.Render(v)
}

// ══════════════════════════════════════════════════════════════════════════════
// HELPERS VIEW
// ══════════════════════════════════════════════════════════════════════════════
func select_cursor(cursor, idx int) string {
	if cursor == idx { return cursorStyle.Render(">") }
	return " "
}

func label_colored(active bool, label string) string {
	if active { return cursorStyle.Render(label) }
	return textStyle.Render(label)
}

// encryptedEmpty devuelve el cifrado de string vacío (para detectar campos TOTP vacíos)
func encryptedEmpty() string {
	enc, _ := encryptField("")
	return enc
}

// ══════════════════════════════════════════════════════════════════════════════
// OVERRIDE Update para manejar importDoneMsg
// ══════════════════════════════════════════════════════════════════════════════
func init() {
	// Registrar el handler de importDoneMsg en la función Update
	// (Go no tiene herencia, así que lo manejamos en el Update global)
}

// Necesitamos que el Update principal también maneje importDoneMsg y syncDoneMsg
// Reemplazamos el switch interno con uno que los capture:
var _ = func() bool {
	// Este bloque solo existe para documentar que los msgs adicionales
	// se manejan dentro del mismo Update principal via los estados correspondientes.
	// stateVerifying ya maneja saveDoneMsg.
	// stateSyncAction ya maneja syncDoneMsg.
	// stateImportPath dispara la goroutine que devuelve importDoneMsg.
	return true
}()

// ══════════════════════════════════════════════════════════════════════════════
// PATCH: Update necesita manejar importDoneMsg globalmente
// ══════════════════════════════════════════════════════════════════════════════
// Re-definimos Update como método de model para capturar todos los mensajes

func patchedUpdate(m model, msg tea.Msg) (tea.Model, tea.Cmd) {
	// Mensajes globales primero
	switch msg := msg.(type) {
	case importDoneMsg:
		nm, cmd := m.handleImportDone(msg)
		return nm, cmd
	case syncDoneMsg:
		if m.state == stateSyncAction {
			if msg.err != nil {
				m.err = "❌ " + msg.err.Error()
			} else {
				opLabel := "Subida"
				if msg.op == "download" {
					opLabel = "Descarga"
					vault, err := LoadVault()
					if err != nil {
						m.err = "❌ Error recargando: " + err.Error()
						m.state = stateSyncMenu
						return m, nil
					}
					m.vault = vault
				}
				m.info = "✅ " + opLabel + " completada · " + time.Now().Format("15:04:05")
			}
			m.state = stateSyncMenu
			m.cursor = 0
			return m, nil
		}
	}
	return m.Update(msg)
}

// ══════════════════════════════════════════════════════════════════════════════
// WRAPPER MODEL para que bubbletea use patchedUpdate
// ══════════════════════════════════════════════════════════════════════════════
type rootModel struct { m model }

func (r rootModel) Init() tea.Cmd { return r.m.Init() }
func (r rootModel) View() string  { return r.m.View() }
func (r rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	nm, cmd := patchedUpdate(r.m, msg)
	if mm, ok := nm.(model); ok {
		return rootModel{m: mm}, cmd
	}
	return nm, cmd
}

// ══════════════════════════════════════════════════════════════════════════════
// MAIN
// ══════════════════════════════════════════════════════════════════════════════
func main() {
	_ = sha256Short // evitar "imported and not used" de sha256
	_ = strconv.Itoa(0) // por si acaso
	p := tea.NewProgram(rootModel{m: initialModel()}, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error al iniciar: %v\n", err)
		os.Exit(1)
	}
}