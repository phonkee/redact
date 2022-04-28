# redact

Redact secrets from structs and convert to map[string]interface{} for safe logging via zap logger.

# example

```golang
type Config struct {
    Username string
    Password string `redact:"protect"`
    Tokens []string `redact:"omit"`
    URL string `redact:"url"`
}

zap.L().Info("config", redact.Field("config", &Config{
	Username: "shown",
	Password: "not shown",
	Tokens: []string{"not", "shown"},
	URL: "http://username:password@localhost", // password will be removed
}))

```

# author

Peter Vrba <phonkee@phonkee.eu>
