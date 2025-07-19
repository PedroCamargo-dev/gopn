package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"gopn/internal/config"
	"gopn/internal/vpn"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

func Run() {
	if len(os.Args) < 2 {
		printHelp()
		return
	}
	command := os.Args[1]
	switch command {
	case "add":
		handleAdd(os.Args[2:])
	case "connect":
		handleConnect(os.Args[2:])
	case "disconnect":
		handleDisconnect(os.Args[2:])
	case "list":
		handleList()
	case "help":
		printHelp()
	default:
		fmt.Printf("Comando desconhecido: %s\n", command)
		printHelp()
	}
}

func handleAdd(args []string) {
	if len(args) != 3 {
		fmt.Println("Uso: gopn add <nome_do_perfil> <arquivo.ovpn> <username>")
		return
	}
	name, ovpn, user := args[0], args[1], args[2]

	if _, err := os.Stat(ovpn); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("Arquivo %s não encontrado.\n", ovpn)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Erro carregando config: %v\n", err)
		return
	}

	if _, exists := cfg.Profiles[name]; exists {
		fmt.Printf("Perfil '%s' já existe. Sobrescrever? (s/N): ", name)
		var resp string
		fmt.Scanln(&resp)
		if !strings.EqualFold(resp, "s") {
			fmt.Println("Cancelado.")
			return
		}
	}

	cfg.Profiles[name] = config.Profile{
		Name:     name,
		OvpnPath: ovpn,
		Username: user,
	}

	if err := cfg.Save(); err != nil {
		fmt.Printf("Erro salvando: %v\n", err)
		return
	}
	fmt.Printf("Perfil '%s' salvo.\n", name)
}

func handleConnect(args []string) {

	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	askUser := fs.Bool("ask-user", false, "Perguntar username mesmo se já salvo")
	mfaFlag := fs.Bool("mfa", false, "Forçar pergunta de MFA")
	verbose := fs.Bool("v", false, "Verbose")
	timeoutSec := fs.Int("timeout", 0, "Timeout (segundos) opcional")
	if err := fs.Parse(args); err != nil {
		return
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Println("Uso: gopn connect [flags] <nome_do_perfil>")
		fs.PrintDefaults()
		return
	}
	profileName := rest[0]

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Erro carregando config: %v\n", err)
		return
	}

	prof, ok := cfg.Profiles[profileName]
	if !ok {
		fmt.Printf("Perfil '%s' não encontrado.\n", profileName)
		return
	}

	reader := bufio.NewReader(os.Stdin)

	username := prof.Username
	if *askUser || username == "" {
		fmt.Print("Usuário: ")
		u, _ := reader.ReadString('\n')
		username = strings.TrimSpace(u)
	} else {
		fmt.Printf("Usuário: %s (do perfil)\n", username)
	}

	fmt.Print("Senha: ")
	pwBytes, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	password := string(pwBytes)

	var mfaCode string
	if *mfaFlag {

		fmt.Print("Código MFA (6 dígitos, deixe vazio se não houver): ")
		txt, _ := reader.ReadString('\n')
		mfaCode = strings.TrimSpace(txt)
	} else {

		fmt.Print("Possui MFA (TOTP)? (s/N): ")
		resp, _ := reader.ReadString('\n')
		if strings.EqualFold(strings.TrimSpace(resp), "s") {
			fmt.Print("Código MFA: ")
			txt, _ := reader.ReadString('\n')
			mfaCode = strings.TrimSpace(txt)
		}
	}

	authSecret := password + mfaCode

	ctx := context.Background()
	var timeoutOpt int = *timeoutSec
	opt := vpn.Options{
		ConfigPath: prof.OvpnPath,
		Username:   username,
		AuthSecret: authSecret,
		Verbose:    *verbose,
	}
	if timeoutOpt > 0 {
		opt.Timeout = (intToDuration(timeoutOpt))
	}

	if err := vpn.Connect(ctx, opt); err != nil {
		fmt.Printf("Erro durante conexão: %v\n", err)
	}
}

func intToDuration(sec int) (d time.Duration) {
	return time.Duration(sec) * time.Second
}

func handleDisconnect(args []string) {
	if len(args) == 0 {

		if err := vpn.DisconnectAll(); err != nil {
			fmt.Printf("Erro ao desconectar: %v\n", err)
		}
		return
	}

	profileName := args[0]
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Erro carregando config: %v\n", err)
		return
	}
	prof, ok := cfg.Profiles[profileName]
	if !ok {
		fmt.Printf("Perfil '%s' não encontrado.\n", profileName)
		return
	}
	if err := vpn.DisconnectProfile(prof.OvpnPath); err != nil {
		fmt.Printf("Erro: %v\n", err)
	}
}

func handleList() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("Erro carregando config: %v\n", err)
		return
	}
	if len(cfg.Profiles) == 0 {
		fmt.Println("Nenhum perfil.")
		return
	}
	fmt.Println("Perfis:")
	for name, p := range cfg.Profiles {
		fmt.Printf("  - %s (user=%s, ovpn=%s)\n", name, p.Username, p.OvpnPath)
	}
}

func printHelp() {
	fmt.Println(`
gopn - Wrapper simplificado para openvpn3

Uso:
  gopn <comando> [args]

Comandos:
  add <nome> <arquivo.ovpn> <usuario>   Adiciona perfil.
  connect [flags] <nome>                Conecta usando perfil.
  disconnect [<nome>]                   Desconecta todas as sessões ou só a do perfil.
  list                                  Lista perfis.
  help                                  Ajuda.

Exemplos:
  gopn disconnect           # Desconecta tudo
  gopn disconnect corp      # Desconecta somente a sessão do perfil 'corp'
`)
}
