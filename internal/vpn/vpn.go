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

var sessionPathRegex = regexp.MustCompile(`/net/openvpn/v3/sessions/[a-f0-9\-]+`)

func Connect(ctx context.Context, opt Options) error {
	if opt.ConfigPath == "" {
		return errors.New("config ovpn não especificada")
	}
	if opt.Username == "" {
		return errors.New("username vazio")
	}
	if opt.AuthSecret == "" {
		return errors.New("authSecret vazio (senha [+ mfa])")
	}

	fmt.Printf("Iniciando sessão VPN usando: %s\n", opt.ConfigPath)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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

	cmd := exec.CommandContext(ctx, "openvpn3", "session-start", "--config", opt.ConfigPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("falha ao iniciar openvpn3: %w", err)
	}

	outputReader := io.MultiReader(stdout, stderr)

	const windowMax = 512
	window := make([]byte, 0, windowMax)

	injectedUser := false
	injectedPass := false

	doneCh := make(chan error, 1)

	go func() {
		defer stdin.Close()
		buf := make([]byte, 256)
		for {
			n, rerr := outputReader.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				os.Stdout.Write(chunk)

				if len(window)+len(chunk) > windowMax {

					overflow := len(window) + len(chunk) - windowMax
					if overflow < len(window) {
						window = window[overflow:]
					} else {
						window = window[:0]
					}
				}
				window = append(window, chunk...)
				winStr := string(window)

				if !injectedUser && strings.Contains(winStr, "Auth User name:") {
					if opt.Verbose {
						fmt.Println("[debug] Injetando username")
					}
					_, _ = io.WriteString(stdin, opt.Username+"\n")
					injectedUser = true
				}
				if !injectedPass && strings.Contains(winStr, "Auth Password:") {
					if opt.Verbose {
						fmt.Println("[debug] Injetando password (senha+MFA se houver)")
					}
					_, _ = io.WriteString(stdin, opt.AuthSecret+"\n")
					injectedPass = true
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
	}()

	if opt.Timeout > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, opt.Timeout)
		defer cancelTimeout()
		go func() {
			<-ctx.Done()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				fmt.Println("\nTempo limite atingido — encerrando processo.")
				_ = cmd.Process.Kill()
			}
		}()
	}

	if err := cmd.Wait(); err != nil {

		select {
		case rerr := <-doneCh:
			if rerr != nil {
				fmt.Printf("Erro durante leitura de saída: %v\n", rerr)
			}
		default:
		}
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

	fmt.Println("\n----------------------------------------------------")
	fmt.Println("✅ Sessão VPN iniciada com sucesso!")
	fmt.Println("   Para desconectar: gopn disconnect")
	fmt.Println("----------------------------------------------------")

	zeroBytes(opt.AuthSecret)

	return nil
}

func zeroBytes(s string) {

	b := []byte(s)
	for i := range b {
		b[i] = 0
	}
}

func DisconnectAll() error {
	out, err := exec.Command("openvpn3", "sessions-list").CombinedOutput()
	if err != nil {
		return fmt.Errorf("erro ao listar sessões: %v\nSaída:\n%s", err, string(out))
	}

	paths := parseSessionPaths(string(out))
	if len(paths) == 0 {
		fmt.Println("Nenhuma sessão ativa encontrada.")
		return nil
	}

	fmt.Printf("Encontradas %d sessão(ões). Desconectando...\n", len(paths))
	var failures []string
	for _, p := range paths {
		cmd := exec.Command("openvpn3", "session-manage", "--session-path", p, "--disconnect")
		if cOut, cErr := cmd.CombinedOutput(); cErr != nil {
			failures = append(failures, fmt.Sprintf("%s -> %v (%s)", p, cErr, strings.TrimSpace(string(cOut))))
		} else {
			fmt.Printf("✓ Desconectado: %s\n", p)
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
	cmd := exec.Command("openvpn3", "session-manage", "--config", ovpnPath, "--disconnect")
	out, err := cmd.CombinedOutput()
	if err != nil {
		txt := string(out)

		if strings.Contains(strings.ToLower(txt), "no such session") ||
			strings.Contains(strings.ToLower(txt), "not found") {
			return fmt.Errorf("nenhuma sessão ativa associada ao arquivo: %s", ovpnPath)
		}
		return fmt.Errorf("erro ao desconectar perfil (%s): %v\nSaída:\n%s", ovpnPath, err, txt)
	}
	fmt.Printf("Sessão associada a %s desconectada.\n", ovpnPath)
	return nil
}

func parseSessionPaths(output string) []string {
	var paths []string
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()

		if strings.Contains(line, "/net/openvpn/v3/sessions/") {
			matches := sessionPathRegex.FindAllString(line, -1)
			for _, m := range matches {
				if !contains(paths, m) {
					paths = append(paths, m)
				}
			}
		} else {

			if strings.HasPrefix(strings.TrimSpace(strings.ToLower(line)), "path:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					candidate := strings.TrimSpace(parts[1])
					if strings.HasPrefix(candidate, "/net/openvpn/v3/sessions/") && !contains(paths, candidate) {
						paths = append(paths, candidate)
					}
				}
			}
		}
	}
	return paths
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
