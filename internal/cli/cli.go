package cli

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/PedroCamargo-dev/gopn/internal/config"
	"github.com/PedroCamargo-dev/gopn/internal/vpn"

	"golang.org/x/term"
)

const errLoadConfigFmt = "❌ Erro ao carregar configuração: %v\n"

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
		fmt.Printf("❌ Comando desconhecido: '%s'\n", command)
		fmt.Println("   Use 'gopn help' para ver os comandos disponíveis.")
		printHelp()
	}
}

func handleAdd(args []string) {
	if len(args) != 3 {
		fmt.Println("❌ Uso: gopn add <nome_do_perfil> <arquivo.ovpn> <username>")
		fmt.Println("   Exemplo: gopn add trabalho /home/user/empresa.ovpn joao.silva")
		return
	}
	name, ovpn, user := args[0], args[1], args[2]

	absOvpn, err := filepath.Abs(ovpn)
	if err != nil {
		fmt.Printf("❌ Erro ao resolver caminho absoluto: %v\n", err)
		return
	}

	if _, err := os.Stat(absOvpn); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("❌ Erro: O arquivo '%s' não foi encontrado.\n", absOvpn)
		fmt.Println("   Verifique se o caminho está correto e se o arquivo existe.")
		return
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf(errLoadConfigFmt, err)
		return
	}

	if _, exists := cfg.Profiles[name]; exists {
		fmt.Printf("⚠️  O perfil '%s' já existe. Deseja sobrescrever? (s/N): ", name)
		var resp string
		fmt.Scanln(&resp)
		if !strings.EqualFold(resp, "s") {
			fmt.Println("❌ Operação cancelada.")
			return
		}
	}

	cfg.Profiles[name] = config.Profile{
		Name:     name,
		OvpnPath: absOvpn,
		Username: user,
	}

	if err := cfg.Save(); err != nil {
		fmt.Printf("❌ Erro ao salvar perfil: %v\n", err)
		return
	}
	fmt.Printf("✅ Perfil '%s' salvo com sucesso!\n", name)
	fmt.Printf("   📁 Caminho: %s\n", absOvpn)
	fmt.Printf("   👤 Usuário: %s\n", user)
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
		fmt.Println("❌ Uso: gopn connect [opções] <nome_do_perfil>")
		fmt.Println("\nOpções disponíveis:")
		fs.PrintDefaults()
		fmt.Println("\nExemplo: gopn connect --mfa --verbose trabalho")
		return
	}
	profileName := rest[0]

	cfg, err := config.Load()
	if err != nil {
		fmt.Printf(errLoadConfigFmt, err)
		return
	}

	prof, ok := cfg.Profiles[profileName]
	if !ok {
		fmt.Printf("❌ Erro: Perfil '%s' não encontrado.\n", profileName)
		fmt.Println("   Use 'gopn list' para ver os perfis disponíveis.")
		return
	}

	reader := bufio.NewReader(os.Stdin)

	username := prof.Username
	if *askUser || username == "" {
		fmt.Print("👤 Digite seu usuário: ")
		u, _ := reader.ReadString('\n')
		username = strings.TrimSpace(u)
	} else {
		fmt.Printf("👤 Usuário: %s (salvo no perfil)\n", username)
	}

	fmt.Print("🔐 Digite sua senha: ")
	pwBytes, _ := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	password := string(pwBytes)

	var mfaCode string
	if *mfaFlag {
		fmt.Print("🔢 Digite o código MFA (6 dígitos, deixe vazio se não houver): ")
		txt, _ := reader.ReadString('\n')
		mfaCode = strings.TrimSpace(txt)
	} else {
		fmt.Print("🔐 Possui autenticação MFA/2FA? (s/N): ")
		resp, _ := reader.ReadString('\n')
		if strings.EqualFold(strings.TrimSpace(resp), "s") {
			fmt.Print("🔢 Digite o código MFA: ")
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
		fmt.Printf("❌ Erro durante a conexão VPN: %v\n", err)
		fmt.Println("   Verifique suas credenciais e tente novamente.")
	}
}

func intToDuration(sec int) (d time.Duration) {
	return time.Duration(sec) * time.Second
}

func handleDisconnect(args []string) {
	if len(args) == 0 {
		fmt.Println("🔌 Desconectando todas as sessões VPN...")
		if err := vpn.DisconnectAll(); err != nil {
			fmt.Printf("❌ Erro ao desconectar: %v\n", err)
		} else {
			fmt.Println("✅ Todas as conexões VPN foram encerradas.")
		}
		return
	}

	profileName := args[0]
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf(errLoadConfigFmt, err)
		return
	}
	prof, ok := cfg.Profiles[profileName]
	if !ok {
		fmt.Printf("❌ Erro: Perfil '%s' não encontrado.\n", profileName)
		fmt.Println("   Use 'gopn list' para ver os perfis disponíveis.")
		return
	}
	fmt.Printf("🔌 Desconectando perfil '%s'...\n", profileName)
	if err := vpn.DisconnectProfile(prof.OvpnPath); err != nil {
		fmt.Printf("❌ Erro ao desconectar: %v\n", err)
	} else {
		fmt.Printf("✅ Perfil '%s' desconectado com sucesso.\n", profileName)
	}
}

func handleList() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Printf("❌ Erro ao carregar configuração: %v\n", err)
		return
	}
	if len(cfg.Profiles) == 0 {
		fmt.Println("📋 Nenhum perfil VPN configurado.")
		fmt.Println("   Use 'gopn add' para adicionar um novo perfil.")
		return
	}
	fmt.Printf("📋 Perfis VPN configurados (%d encontrados):\n", len(cfg.Profiles))
	for name, p := range cfg.Profiles {
		fmt.Printf("  🔹 %s\n", name)
		fmt.Printf("     👤 Usuário: %s\n", p.Username)
		fmt.Printf("     📁 Arquivo: %s\n", p.OvpnPath)
		fmt.Println()
	}
}

func printHelp() {
	helpText := `
🔗 GOPN - Gerenciador simplificado para OpenVPN3

📖 USO:
   gopn <comando> [opções] [argumentos]

📋 COMANDOS DISPONÍVEIS:
   add <nome> <arquivo.ovpn> <usuario>   📝 Adiciona um novo perfil VPN
   connect [opções] <nome>               🔌 Conecta usando um perfil existente  
   disconnect [<nome>]                   🔌 Desconecta sessões VPN (todas ou específica)
   list                                  📋 Lista todos os perfis configurados
   help                                  ❓ Exibe esta ajuda

🔧 OPÇÕES DO CONNECT:
   --ask-user      Solicita o nome de usuário mesmo se já estiver salvo
   --mfa           Força a solicitação do código MFA/2FA
   --v             Modo verboso (exibe mais detalhes)
   --timeout <n>   Define timeout em segundos (opcional)

💡 EXEMPLOS:
   gopn add trabalho /home/user/empresa.ovpn joao.silva
   gopn connect trabalho
   gopn connect --mfa --verbose trabalho
   gopn disconnect                    # Desconecta todas as sessões
   gopn disconnect trabalho           # Desconecta apenas o perfil 'trabalho'
   gopn list

📧 Para mais informações, visite: https://github.com/PedroCamargo-dev/gopn
	
`
	fmt.Print(helpText)
}
