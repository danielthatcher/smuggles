package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/ryanuber/go-glob"
	flag "github.com/spf13/pflag"
)

var mutations map[string]string

type baseResult struct {
	t time.Duration
	u *url.URL
}

// baseWorker fetches urls on a channel and times how long it takes to fetch those URLs
func baseWorker(urls <-chan *url.URL, results chan<- baseResult, errs chan<- error, done func()) {
	for u := range urls {
		req := baseReq(u)
		start := time.Now()
		_, err, _ := sendRequest(req, u, 30*time.Second)
		end := time.Now()
		duration := end.Sub(start)
		if err != nil {
			errs <- err
			continue
		}

		results <- baseResult{duration, u}
	}
	done()
}

// smuggleType represents the type of smuggling vulnerability - either CL.TE or TE.CL
type smuggleType string

const (
	SAFE = ""
	CLTE = "CL.TE"
	TECL = "TE.CL"
)

// smuggleTest represents the parameters for a test of CL.TE and TE.CL smuggling against
// a single URL using a single method and a single Transfer-Encoding header mutation
type smuggleTest struct {
	// The URL to test
	u *url.URL

	// The method to test
	method string

	// The name of the mutation to use. Should be a key in mutations
	mutation string

	// The delay that will indicate the service is vulnerable. Should be calculated off
	// of the time take for the base request to this service
	timeout time.Duration

	// The type of attack the service is vulnerable to
	status smuggleType
}

// smuggleWorker sends requests URLs using the given Transfer-Encoding header,
// and checks for CL.TE then TE.CL vulnerabilities
func smuggleWorker(tests <-chan smuggleTest, results chan<- smuggleTest, errs chan<- error, done func()) {
	for t := range tests {
		// First test for CL.TE
		req := clte(t.method, t.u, mutations[t.mutation])
		_, err, isTimeout := sendRequest(req, t.u, t.timeout)
		if isTimeout {
			t.status = CLTE
			results <- t
			continue
		} else if err != nil {
			errs <- err
			continue
		}

		// First test for TE.CL
		req = tecl(t.method, t.u, mutations[t.mutation])
		_, err, isTimeout = sendRequest(req, t.u, t.timeout)
		if isTimeout {
			t.status = TECL
			results <- t
			continue
		} else if err != nil {
			errs <- err
			continue
		}
	}
	done()
}

// sendRequest sends the specified request, but doesn't try to parse the response,
// and instead just returns it
func sendRequest(req []byte, u *url.URL, timeout time.Duration) (resp []byte, err error, isTimeout bool) {
	var cerr error
	var conn io.ReadWriteCloser

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	target := fmt.Sprintf("%s:%s", u.Hostname(), port)
	if u.Scheme == "https" {
		conf := &tls.Config{InsecureSkipVerify: true}
		conn, cerr = tls.DialWithDialer(&net.Dialer{
			Timeout: timeout,
		}, "tcp", target, conf)

	} else {
		d := net.Dialer{Timeout: timeout}
		conn, cerr = d.Dial("tcp", target)
	}

	if cerr != nil {
		err = cerr
		return
	}

	_, err = conn.Write(req)
	if err != nil {
		return
	}

	// See if we can read before the timeout
	c := make(chan []byte)
	go func() {
		r, err := ioutil.ReadAll(conn)
		if err == nil {
			c <- r
		}
	}()

	select {
	case resp = <-c:
	case <-time.After(timeout):
		isTimeout = true
		conn.Close()
	}

	return
}

func main() {
	workers := flag.IntP("workers", "c", 10, "the number of concurrent workers")
	outfile := flag.StringP("output", "o", "", "the logfile to write to")
	verbose := flag.BoolP("verbose", "v", false, "print scanned hosts to stdout")
	basefile := flag.StringP("base", "b", "smuggles.base", "the base file with request times to use")
	methods := flag.StringSliceP("methods", "m", []string{"GET", "POST", "PUT", "DELETE"}, "the methods to test")
	delay := flag.DurationP("delay", "", 5*time.Second, "the extra time delay on top of the base time that indicates the service is vulnerable")
	list := flag.BoolP("list", "l", false, "list the enabled mutation names and exit")
	enabled := flag.StringSliceP("enable", "e", nil, "globs of modules to enable")
	disabled := flag.StringSliceP("disable", "d", nil, "globs of modules to disable")
	stopAfter := flag.UintP("stop-after", "x", 0, "the number of smuggling vulnerabilities to find in a host before stopping testing on it. This won't cancel already queued tests, so slightly more than this number of vulnerabilities may be found")
	flag.Parse()

	// Generate the enable mutations
	all := generateMutations()
	mutations = make(map[string]string, 0)
	for m := range all {
		include := true

		if enabled != nil && len(*enabled) > 0 {
			include = false
			for _, e := range *enabled {
				if glob.Glob(e, m) {
					include = true
					break
				}
			}
		}

		if disabled != nil && len(*disabled) > 0 {
			for _, d := range *disabled {
				if glob.Glob(d, m) {
					include = false
					break
				}
			}
		}

		if include {
			mutations[m] = all[m]
		}
	}

	if *list {
		keys := make([]string, len(mutations))
		i := 0
		for k := range mutations {
			keys[i] = k
			i++
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Println(k)
		}
		os.Exit(0)
	}

	urls := make([]*url.URL, 0)

	// Logging
	log.SetFlags(0)
	if *outfile != "" {
		f, err := os.OpenFile(*outfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		mw := io.MultiWriter(os.Stdout, f)
		log.SetOutput(mw)
	}

	// The base times for standard requests
	var base map[string]time.Duration
	baseFile, err := os.OpenFile(*basefile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to open base file: %v\n", err)
		os.Exit(1)
	}
	defer baseFile.Close()
	jsonBytes, err := ioutil.ReadAll(baseFile)
	if err != nil {
		fmt.Printf("Failed to read base file: %v\n", err)
		os.Exit(1)
	}

	if len(jsonBytes) > 0 {
		err = json.Unmarshal(jsonBytes, &base)
		if err != nil {
			fmt.Printf("Failed to parse base file as JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		base = make(map[string]time.Duration, 0)
	}

	// Make sure we save the base file on exit
	defer func() {
		l := log.New(os.Stderr, "", 0)
		b, err := json.Marshal(base)
		if err != nil {
			l.Printf("Error marshalling base times to JSON: %v\n", err)
			return
		}

		_, err = baseFile.Seek(0, 0)
		if err != nil {
			l.Printf("Error seeking to start of file: %v\n", err)
		}

		_, err = baseFile.Write(b)
		if err != nil {
			l.Printf("Error writing base to file: %v\n", err)
		}
	}()

	// Fill in any missing entries in the base file
	fmt.Println("Getting missing base times...")
	baseUrls := make(chan *url.URL)
	errs := make(chan error)
	baseResults := make(chan baseResult)
	baseWg := sync.WaitGroup{}
	baseWg.Add(*workers)
	for i := 0; i < *workers; i++ {
		go baseWorker(baseUrls, baseResults, errs, baseWg.Done)
	}

	// Read from stdin
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urlStr := scanner.Text()
			u, err := url.Parse(urlStr)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
			}
			_, exists := base[u.String()]
			if !exists {
				baseUrls <- u
			}
			urls = append(urls, u)
		}
		close(baseUrls)
	}()

	// Wait for workers to all be done
	go func() {
		baseWg.Wait()
		close(baseResults)
	}()

	// Handle errors
	go func() {
		l := log.New(os.Stderr, "", 0)
		for err := range errs {
			l.Printf("ERROR: %v\n", err)
		}
	}()

	for r := range baseResults {
		base[r.u.String()] = r.t
		if *verbose {
			fmt.Printf("%s %d\n", r.u, r.t)
		}
	}

	// Now smuggle test
	fmt.Println("Testing smuggling...")
	vulns := make(map[string]uint, 0)
	vulnsMux := sync.RWMutex{}

	// Generate a slice of all the tests to choose from at random
	tests := make([]smuggleTest, 0)
	for _, u := range urls {
		// We only want to run the tests if we have a base time for this URL
		if _, ok := base[u.String()]; !ok {
			continue
		}

		for m := range mutations {
			for _, v := range *methods {
				timeout := base[u.String()] + *delay
				t := smuggleTest{
					u:        u,
					method:   v,
					mutation: m,
					status:   SAFE,
					timeout:  timeout,
				}
				tests = append(tests, t)
			}
		}
	}

	// Start the workers
	testsChan := make(chan smuggleTest)
	testResults := make(chan smuggleTest)
	testsWg := sync.WaitGroup{}
	testsWg.Add(*workers)
	for i := 0; i < *workers; i++ {
		go smuggleWorker(testsChan, testResults, errs, testsWg.Done)
	}

	// Send tests
	go func() {
		for len(tests) > 0 {
			rand.Seed(time.Now().Unix())
			i := rand.Intn(len(tests))
			t := tests[i]
			tests = append(tests[:i], tests[i+1:]...)
			send := true
			if *stopAfter > 0 {
				vulnsMux.RLock()
				send = vulns[t.u.String()] < *stopAfter
				vulnsMux.RUnlock()

			}
			if send {
				testsChan <- t
			}
			if *verbose {
				fmt.Printf("Testing: %s %s %s\n", t.method, t.u, t.mutation)
			}
		}
		close(testsChan)
	}()

	// Wait for workers to be done
	go func() {
		testsWg.Wait()
		close(testResults)
	}()

	for t := range testResults {
		if t.status != SAFE {
			log.Printf("%s %s %s %s\n", t.method, t.u, t.status, t.mutation)
			if *stopAfter > 0 {
				vulnsMux.Lock()
				vulns[t.u.String()] += 1
				vulnsMux.Unlock()
			}
		}
	}
}
