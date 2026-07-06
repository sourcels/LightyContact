package config

import (
	"log/slog"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port          string
	DBPath        string
	JWTSecret     string
	AllowedOrigin string
	MaxBodySize   int64
	RootPassword  string
}

func Load() *Config {

	if err := godotenv.Load(); err != nil {
		slog.Info(".env file not found, falling back to system environment variables")
	}

	return &Config{
		Port:          getEnv("PORT", "8080"),
		DBPath:        getEnv("DB_PATH", "messenger.db"),
		JWTSecret:     getEnv("JWT_SECRET", ""),
		AllowedOrigin: getEnv("ALLOWED_ORIGIN", "*"),
		MaxBodySize:   getEnvAsInt64("MAX_BODY_SIZE", 1048576),
		RootPassword:  getEnv("ROOT_PASSWORD", ""),
	}
}

func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func getEnvAsInt64(key string, fallback int64) int64 {
	strValue := getEnv(key, "")
	if strValue == "" {
		return fallback
	}

	value, err := strconv.ParseInt(strValue, 10, 64)
	if err != nil {
		slog.Warn("Environment variable must be a number, using default value",
			"env_var", key,
			"fallback_value", fallback,
		)
		return fallback
	}

	return value
}
