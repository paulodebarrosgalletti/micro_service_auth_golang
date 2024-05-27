package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Estrutura para representar um usuário
type Usuario struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

// Estrutura para representar um JWT
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

var jwtKey = []byte("my_secret_key")

// Simulação de um banco de dados em memória
var users = make(map[string]Usuario)
var mutex sync.Mutex

// Handler para login
func login(w http.ResponseWriter, r *http.Request) {
	var creds Usuario
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	user, exists := users[creds.Username]
	mutex.Unlock()

	if !exists || user.Password != creds.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

// Handler para cadastro
func register(w http.ResponseWriter, r *http.Request) {
	// Verificar se o método da solicitação é POST
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verificar se o Content-Type é application/json
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	// Decodificar o novo usuário do corpo da solicitação
	var newUser Usuario
	err := json.NewDecoder(r.Body).Decode(&newUser)
	if err != nil {
		http.Error(w, "Invalid JSON format", http.StatusBadRequest)
		return
	}

	// Verificar se os campos obrigatórios estão presentes e preenchidos
	if newUser.Username == "" || newUser.Email == "" || newUser.Password == "" {
		http.Error(w, "Username, email, and password are required", http.StatusBadRequest)
		return
	}

	mutex.Lock()
	defer mutex.Unlock()

	// Verificar se o usuário já existe
	if _, exists := users[newUser.Username]; exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Adicionar o novo usuário ao banco de dados simulado
	users[newUser.Username] = newUser

	w.WriteHeader(http.StatusCreated)
}

// Handler para health check
func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Função principal
func main() {
	http.HandleFunc("/login", login)
	http.HandleFunc("/register", register)
	http.HandleFunc("/health", healthCheck)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}
