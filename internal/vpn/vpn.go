package vpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"
)

type Options struct {
	ConfigPath string
	Username   string
	AuthSecret string
	Verbose    bool
	Timeout    time.Duration
}

type SessionInfo struct {
	Path   string
	Config string
}

var sessionPathRegex = regexp.MustCompile(`/net/openvpn/v3/sessions/[a-f0-9\-]+`)

func Connect(ctx context.Context, opt Options) error {
	if err := validateOptions(opt); err != nil {
		return err
	}

	fmt.Printf("Iniciando sessão VPN usando: %s\n", opt.ConfigPath)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	handleSignals(ctx, cancel)

	cmd, stdin, stdout, stderr, err := setupCommand(ctx, opt.ConfigPath)
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("falha ao iniciar openvpn3: %w", err)
	}

	outputReader := io.MultiReader(stdout, stderr)
	doneCh := make(chan error, 1)
	var sessionPath string

	go processOutput(stdin, outputReader, opt, doneCh, &sessionPath)

	if opt.Timeout > 0 {
		ctx, cancelTimeout := context.WithTimeout(ctx, opt.Timeout)
		defer cancelTimeout()
		go handleTimeout(ctx, cmd)
	}

	if err := cmd.Wait(); err != nil {
		handleDoneCh(doneCh)
		if ctx.Err() == context.Canceled {
			return errors.New("conexão cancelada pelo usuário")
		}
		if strings.Contains(err.Error(), "exit status 8") {
			return errors.New("autenticação falhou (exit status 8)")
		}
		return fmt.Errorf("openvpn3 terminou com erro: %w", err)
	}

	select {
	case rerr := <-doneCh:
		if rerr != nil {
			return fmt.Errorf("erro leitura: %w", rerr)
		}
	default:
	}

	if sessionPath == "" {
		return errors.New("não foi possível estabelecer a sessão vpn. verifique as credenciais e a conexão")
	}

	fmt.Println("\n----------------------------------------------------")
	fmt.Println("✅ Sessão VPN iniciada com sucesso!")
	fmt.Println("   Para desconectar: gopn disconnect")
	fmt.Println("----------------------------------------------------")

	zeroBytes(opt.AuthSecret)

	return nil
}

func validateOptions(opt Options) error {
	if opt.ConfigPath == "" {
		return errors.New("config ovpn não especificada")
	}
	if opt.Username == "" {
		return errors.New("username vazio")
	}
	if opt.AuthSecret == "" {
		return errors.New("authSecret vazio (senha [+ mfa])")
	}
	return nil
}

func handleSignals(ctx context.Context, cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-sigCh:
			fmt.Println("\nCancelando conexão (Ctrl+C recebido)...")
			cancel()
		case <-ctx.Done():
		}
	}()
}

func setupCommand(ctx context.Context, configPath string) (*exec.Cmd, io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	cmd := exec.CommandContext(ctx, "openvpn3", "session-start", "--config", configPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("stderr pipe: %w", err)
	}
	return cmd, stdin, stdout, stderr, nil
}

func processOutput(stdin io.WriteCloser, outputReader io.Reader, opt Options, doneCh chan error, sessionPath *string) {
	defer stdin.Close()
	const windowMax = 512
	window := make([]byte, 0, windowMax)
	injectedUser := false
	injectedPass := false
	buf := make([]byte, 256)
	for {
		n, rerr := outputReader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			os.Stdout.Write(chunk)
			window = updateWindow(window, chunk, windowMax)
			winStr := string(window)
			injectedUser, injectedPass = injectCredentials(stdin, winStr, opt, injectedUser, injectedPass)
			if match := sessionPathRegex.FindString(winStr); match != "" {
				*sessionPath = match
			}
		}
		if rerr != nil {
			if rerr != io.EOF {
				doneCh <- rerr
			} else {
				doneCh <- nil
			}
			return
		}
	}
}

func updateWindow(window, chunk []byte, windowMax int) []byte {
	if len(window)+len(chunk) > windowMax {
		overflow := len(window) + len(chunk) - windowMax
		if overflow < len(window) {
			window = window[overflow:]
		} else {
			window = window[:0]
		}
	}
	return append(window, chunk...)
}

func injectCredentials(stdin io.WriteCloser, winStr string, opt Options, injectedUser, injectedPass bool) (bool, bool) {
	lowerWinStr := strings.ToLower(winStr)

	if !injectedUser {
		injectedUser = tryInjectUsername(stdin, lowerWinStr, opt)
	}

	if !injectedPass {
		injectedPass = tryInjectPassword(stdin, lowerWinStr, opt)
	}

	return injectedUser, injectedPass
}

func tryInjectUsername(stdin io.WriteCloser, lowerWinStr string, opt Options) bool {
	usernamePrompts := []string{"username:", "user name:", "auth user name:"}
	for _, prompt := range usernamePrompts {
		if strings.Contains(lowerWinStr, prompt) {
			if opt.Verbose {
				fmt.Printf("[debug] Injetando username (detectado: %s)\n", prompt)
			}
			_, _ = io.WriteString(stdin, opt.Username+"\n")
			return true
		}
	}
	return false
}

func tryInjectPassword(stdin io.WriteCloser, lowerWinStr string, opt Options) bool {
	passwordPrompts := []string{"password:", "auth password:"}
	for _, prompt := range passwordPrompts {
		if strings.Contains(lowerWinStr, prompt) {
			if opt.Verbose {
				fmt.Printf("[debug] Injetando password (detectado: %s)\n", prompt)
			}
			_, _ = io.WriteString(stdin, opt.AuthSecret+"\n")
			return true
		}
	}
	return false
}

func handleTimeout(ctx context.Context, cmd *exec.Cmd) {
	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		fmt.Println("\nTempo limite atingido — encerrando processo.")
		_ = cmd.Process.Kill()
	}
}

func handleDoneCh(doneCh chan error) {
	select {
	case rerr := <-doneCh:
		if rerr != nil {
			fmt.Printf("Erro durante leitura de saída: %v\n", rerr)
		}
	default:
	}
}

func zeroBytes(s string) {
	b := []byte(s)
	for i := range b {
		b[i] = 0
	}
}

func getSessions() ([]SessionInfo, error) {
	out, err := exec.Command("openvpn3", "sessions-list").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("erro ao listar sessões: %v\nSaída:\n%s", err, string(out))
	}

	var sessions []SessionInfo
	var currentSession SessionInfo
	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Path:") {
			if currentSession.Path != "" {
				sessions = append(sessions, currentSession)
			}
			currentSession = SessionInfo{Path: strings.TrimSpace(strings.TrimPrefix(line, "Path:"))}
		} else if strings.HasPrefix(line, "Config:") {
			currentSession.Config = strings.TrimSpace(strings.TrimPrefix(line, "Config:"))
		}
	}
	if currentSession.Path != "" {
		sessions = append(sessions, currentSession)
	}

	return sessions, nil
}

func DisconnectAll() error {
	sessions, err := getSessions()
	if err != nil {
		return err
	}

	if len(sessions) == 0 {
		fmt.Println("Nenhuma sessão ativa encontrada.")
		return nil
	}

	fmt.Printf("Encontradas %d sessão(ões). Desconectando...\n", len(sessions))
	var failures []string
	for _, s := range sessions {
		cmd := exec.Command("openvpn3", "session-manage", "--session-path", s.Path, "--disconnect")
		if cOut, cErr := cmd.CombinedOutput(); cErr != nil {
			failures = append(failures, fmt.Sprintf("%s -> %v (%s)", s.Path, cErr, strings.TrimSpace(string(cOut))))
		} else {
			fmt.Printf("✓ Desconectado: %s\n", s.Path)
		}
	}

	if len(failures) > 0 {
		return fmt.Errorf("falha ao desconectar algumas sessões:\n  %s",
			strings.Join(failures, "\n  "))
	}

	fmt.Println("Todas as sessões foram desconectadas.")
	return nil
}

func DisconnectProfile(ovpnPath string) error {
	if ovpnPath == "" {
		return errors.New("ovpnPath vazio")
	}

	sessions, err := getSessions()
	if err != nil {
		return err
	}

	var sessionToDisconnect string
	for _, s := range sessions {
		if s.Config == ovpnPath {
			sessionToDisconnect = s.Path
			break
		}
	}

	if sessionToDisconnect == "" {
		return fmt.Errorf("nenhuma sessão ativa associada ao arquivo: %s", ovpnPath)
	}

	cmd := exec.Command("openvpn3", "session-manage", "--session-path", sessionToDisconnect, "--disconnect")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("erro ao desconectar perfil (%s): %v\nSaída:\n%s", ovpnPath, err, string(out))
	}

	fmt.Printf("Sessão associada a %s desconectada.\n", ovpnPath)
	return nil
}
