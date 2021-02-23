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
	"sync"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/client"
	"github.com/google/certificate-transparency-go/jsonclient"
	"github.com/google/certificate-transparency-go/scanner"
	"github.com/google/certificate-transparency-go/x509"
)

var domainQueue chan string

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

func storeDomainWorker(domains chan string, finished chan bool) {
	f, err := os.Create("domains")
	check(err)
	defer f.Close()
	gf := gzip.NewWriter(f)
	defer gf.Close()
	outfile := bufio.NewWriter(gf)
	defer outfile.Flush()
	uniqueDomains := make(map[string]struct{})
	for domain := range domains {
		// Store domain
		if _, ok := uniqueDomains[domain]; !ok {
			uniqueDomains[domain] = struct{}{}
			outfile.WriteString(domain)
			outfile.WriteByte('\n')
		}
	}
	fmt.Printf("Unique Domains: %v\n", len(uniqueDomains))
	finished <- true
}

func ctlogStats(wg *sync.WaitGroup, cfg scanConfig) {
	var ndomains, nerrors uint64 = 0, 0
	defer wg.Done()
	fmt.Printf("Scanning %v %v\n", cfg.provider, cfg.ctLog.Name)
	for {
		select {
		case d := <-cfg.domainQueue:
			ndomains++
			domainQueue <- d
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
			if len(cfg.domainQueue) == 0 && len(cfg.errorQueue) == 0 {
				// Print Stats
				fmt.Printf(
					"Done scanning %v %v\nDomains: %v\nErrors: %v\n",
					cfg.provider, cfg.ctLog.Name,
					ndomains,
					nerrors,
				)
				return
			} else {
				cfg.stop <- true
			}
		}
	}
}

func startScan(cfg scanConfig) {
	scanClient, err := client.New(cfg.ctLog.URI, &http.Client{
		Timeout: 10 * time.Second,
	},
		jsonclient.Options{},
	)
	check(err)
	scanOpts := scanner.ScannerOptions{
		FetcherOptions: scanner.FetcherOptions{
			BatchSize:     1024,
			ParallelFetch: 1,
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
				cfg.domainQueue <- entry.X509Cert.Subject.CommonName
			}
		},
		// Process PreCert
		func(rawLog *ct.RawLogEntry) {
			entry, err := rawLog.ToLogEntry()
			if x509.IsFatal(err) || entry.Precert == nil {
				cfg.errorQueue <- rawLog.Index
				return
			} else {
				cfg.domainQueue <- entry.Precert.TBSCertificate.Subject.CommonName
			}
		})
}

func scanProvider(wg *sync.WaitGroup, provider string, ctlogs []CTLog) {
	defer wg.Done()
	// Scan each log in this provider one at a time
	for _, c := range ctlogs {
		cfg := scanConfig{
			provider:    provider,
			ctLog:       &c,
			domainQueue: make(chan string, 512),
			errorQueue:  make(chan int64, 512),
		}
		wg.Add(1)
		go ctlogStats(wg, cfg)
		startScan(cfg)
		cfg.stop <- true
	}
}

func main() {
	var cfg Config
	flag.Parse()
	data, err := ioutil.ReadFile("CTLogs.json")
	check(err)
	err = parseConfig(data, &cfg)
	check(err)

	domainQueue = make(chan string, 1024)
	finished := make(chan bool)
	go storeDomainWorker(domainQueue, finished)
	var scannerWg sync.WaitGroup
	// Parallelize each provider scan
	for provider, ctlogs := range cfg.CTLogs {
		scannerWg.Add(1)
		go scanProvider(&scannerWg, provider, ctlogs)
	}
	scannerWg.Wait()
	close(domainQueue)
	<-finished
}
