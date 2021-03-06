package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
	lru "github.com/hashicorp/golang-lru"
	"github.com/paulbellamy/ratecounter"
)

// Flags

var tFlag = flag.Int("t", 5, "Number of workers per provider")
var nFlag = flag.Int("n", 2, "Number of providers to scan at once")
var cFlag = flag.Int("c", 150000, "Domain cache size")
var bFlag = flag.Bool("b", false, "Test cache size and exit")

// Global Domain Cache
var domainCache *lru.Cache

var domainValidator *regexp.Regexp = regexp.MustCompile(`(?mi)^[\w-\*]*(?:\.[\w-]+)+$`)

type CTLog struct {
	Name string `json:"name"`
	URI  string `json:"uri"`
}

type Config struct {
	CTLogs map[string][]CTLog `json:"providers"`
}

type scanConfig struct {
	provider    string
	ctLog       *CTLog
	domainQueue chan string
	errorQueue  chan int64
	stop        chan bool
}

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func parseConfig(file []byte, cfg *Config) error {
	err := json.Unmarshal([]byte(file), cfg)
	if err != nil {
		return err
	}
	return nil
}

func ctlogStats(wg *sync.WaitGroup, cfg scanConfig) {
	var ndomains, nerrors uint64 = 0, 0
	defer wg.Done()

	f, err := os.Create(fmt.Sprintf("%v-%v.domains", cfg.provider, cfg.ctLog.Name))
	check(err)
	defer f.Close()
	gf := gzip.NewWriter(f)
	defer gf.Close()
	outfile := bufio.NewWriter(gf)
	defer outfile.Flush()

	counter := ratecounter.NewRateCounter(1 * time.Second)
	quit := make(chan bool)
	go func() {
		f, err := os.Create(fmt.Sprintf("%v-%v.stats", cfg.provider, cfg.ctLog.Name))
		check(err)
		defer f.Close()
		for {
			select {
			case <-quit:
				return
			default:
			}
			f.Truncate(0)
			f.Seek(0, 0)
			f.WriteString(fmt.Sprintf(" %v domains/s\n", counter.Rate()))
			time.Sleep(1 * time.Second)
		}
	}()

	fmt.Printf("Scanning %v %v\n", cfg.provider, cfg.ctLog.Name)
	for {
		select {
		case d := <-cfg.domainQueue:

			// Store domain
			if !domainCache.Contains(d) {
				domainCache.Add(d, struct{}{})
				outfile.WriteString(d)
				outfile.WriteByte('\n')
				counter.Incr(1)
				ndomains++
			}
		case e := <-cfg.errorQueue:
			nerrors++
			fmt.Fprintf(
				os.Stderr,
				"[Error]: %v: Failed to parse index %v in %v\n",
				cfg.provider,
				e,
				cfg.ctLog.Name,
			)
		case <-cfg.stop:
			// Print Stats
			fmt.Printf(
				"Done scanning %v %v\nDomains: %v\nErrors: %v\n",
				cfg.provider, cfg.ctLog.Name,
				ndomains,
				nerrors,
			)
			quit <- true
			return
		}
	}
}

func isDomain(domain string) bool {
	return domainValidator.MatchString(domain)
}

func startScan(cfg scanConfig) {
	scanClient, err := client.New(cfg.ctLog.URI, &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSHandshakeTimeout:   30 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			MaxIdleConnsPerHost:   10,
			DisableKeepAlives:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	},
		jsonclient.Options{UserAgent: "ct-go-scanlog/1.0"}, // maybe its whitelisted?
	)
	check(err)
	scanOpts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1000,
			ParallelFetch: *tFlag,
			StartIndex:    0,
			EndIndex:      0,
			Continuous:    false,
		},
		Matcher:    scanner.MatchAll{},
		NumWorkers: 1,
	}
	s := scanner.NewScanner(scanClient, scanOpts)
	s.Scan(context.Background(),
		// Process Cert
		func(rawLog *ct.RawLogEntry) {
			entry, err := rawLog.ToLogEntry()
			if x509.IsFatal(err) || entry.X509Cert == nil {
				cfg.errorQueue <- rawLog.Index
				return
			} else {
				if isDomain(entry.X509Cert.Subject.CommonName) {
					cfg.domainQueue <- entry.X509Cert.Subject.CommonName
				}
				for _, alt := range entry.X509Cert.DNSNames {
					if isDomain(alt) {
						cfg.domainQueue <- alt
					}
				}
			}
		},
		// Process PreCert
		func(rawLog *ct.RawLogEntry) {
			entry, err := rawLog.ToLogEntry()
			if x509.IsFatal(err) || entry.Precert == nil {
				cfg.errorQueue <- rawLog.Index
				return
			} else {
				if isDomain(entry.Precert.TBSCertificate.Subject.CommonName) {
					cfg.domainQueue <- entry.Precert.TBSCertificate.Subject.CommonName
				}
				for _, alt := range entry.Precert.TBSCertificate.DNSNames {
					if isDomain(alt) {
						cfg.domainQueue <- alt
					}
				}
			}
		},
	)
}

func scanProvider(wg *sync.WaitGroup, provider string, ctlogs []CTLog) {
	defer wg.Done()
	// Scan each log in this provider one at a time
	for _, c := range ctlogs {
		cfg := scanConfig{
			provider:    provider,
			ctLog:       &c,
			domainQueue: make(chan string, 1024),
			errorQueue:  make(chan int64, 512),
			stop:        make(chan bool),
		}
		wg.Add(1)
		go ctlogStats(wg, cfg)
		startScan(cfg)
		for len(cfg.domainQueue) > 0 && len(cfg.errorQueue) > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		cfg.stop <- true
	}
}

func cacheTest() {
	c, err := lru.New(*cFlag)
	check(err)
	for i := 0; i < *cFlag; i++ {
		c.Add(fmt.Sprintf("%v.subdomain.test.example.com", i), struct{}{})
	}
	fmt.Println("Cache Filled")
	// Give time for user to view system memory
	time.Sleep(10 * time.Second)
	fmt.Println("Cache Test Successful")
}

func main() {
	var cfg Config
	flag.Parse()
	if *bFlag {
		cacheTest()
		os.Exit(0)
	}

	data, err := ioutil.ReadFile("CTLogs.json")
	check(err)
	err = parseConfig(data, &cfg)
	check(err)

	domainCache, err = lru.New(*cFlag)
	check(err)
	var scannerWg sync.WaitGroup
	activeProviders := 0
	// Parallelize each provider scan
	for provider, ctlogs := range cfg.CTLogs {
		if activeProviders >= *nFlag {
			scannerWg.Wait()
			activeProviders = 0
		}
		scannerWg.Add(1)
		activeProviders += 1
		ctLogsCpy := make([]CTLog, len(ctlogs))
		copy(ctLogsCpy, ctlogs)
		go scanProvider(&scannerWg, provider, ctLogsCpy)
	}
	scannerWg.Wait()
}
