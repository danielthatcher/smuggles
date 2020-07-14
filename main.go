package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"

	flag "github.com/spf13/pflag"
	"github.com/tomnomnom/rawhttp"
)

var mutations map[string]string

type baseResult struct {
	t time.Duration
	u string
}

// baseWorker fetches urls on a channel and times how long it takes to fetch those URLs
func baseWorker(urls <-chan string, results chan<- baseResult, errs chan<- error, done func()) {
	for u := range urls {
		req, err := rawhttp.FromURL("GET", u)
		if err != nil {
			errs <- err
			continue
		}

		req.AddHeader("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246")
		req.AutoSetHost()
		req.Timeout = 5 * time.Second
		start := time.Now()
		_, err = rawhttp.Do(req)
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
	u string

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
		req, err := rawhttp.FromURL(t.method, t.u)
		if err != nil {
			errs <- err
			continue
		}
		req.AutoSetHost()
		req.Body = "1\r\nZ\r\nQ"
		req.AddHeader(mutations[t.mutation])
		req.AddHeader("Content-Length: 4")

		req.Timeout = t.timeout
		_, err = rawhttp.Do(req)
		if err, ok := err.(net.Error); ok && err.Timeout() {
			t.status = CLTE
			results <- t
			continue
		} else if err != nil {
			errs <- err
			continue
		}

		// Then test for TECL
		req, err = rawhttp.FromURL(t.method, t.u)
		if err != nil {
			errs <- err
			continue
		}
		req.AutoSetHost()
		req.Body = "0\r\n\r\nX"
		req.AddHeader(mutations[t.mutation])
		req.AddHeader("Content-Length: 6")

		req.Timeout = t.timeout
		_, err = rawhttp.Do(req)
		if err, ok := err.(net.Error); ok && err.Timeout() {
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

func main() {
	workers := flag.IntP("workers", "c", 1, "the number of concurrent workers")
	outfile := flag.StringP("output", "o", "", "the logfile to write to")
	verbose := flag.BoolP("verbose", "v", false, "print scanned hosts to stdout")
	basefile := flag.StringP("base", "b", "smuggles.base", "the base file with request times to use")
	methods := flag.StringSliceP("methods", "m", []string{"GET", "POST", "PUT", "DELETE"}, "the methods to test")
	delay := flag.DurationP("delay", "d", 4*time.Second, "the extra time delay on top of the base time that indicates the service is vulnerable")
	flag.Parse()

	urls := make([]string, 0)

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
	f, err := os.OpenFile(*basefile, os.O_RDWR|os.O_CREATE, 0644)
	if err != nil {
		fmt.Printf("Failed to open base file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()
	jsonBytes, err := ioutil.ReadAll(f)
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

		_, err = f.Seek(0, 0)
		if err != nil {
			l.Printf("Error seeking to start of file: %v\n", err)
		}

		_, err = f.Write(b)
		if err != nil {
			l.Printf("Error writing base to file: %v\n", err)
		}
	}()

	// Fill in any missing entries in the base file
	fmt.Println("Getting missing base times...")
	baseUrls := make(chan string)
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
			u := scanner.Text()
			_, exists := base[u]
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
		base[r.u] = r.t
		if *verbose {
			fmt.Printf("%s %d\n", r.u, r.t)
		}
	}

	// Now smuggle test
	fmt.Println("Testing smuggling...")
	mutations = generateMutations()

	// Generate a slice of all the tests to choose from at random
	tests := make([]smuggleTest, 0)
	for _, u := range urls {
		for m := range mutations {
			for _, v := range *methods {
				timeout := base[u] + *delay
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
			testsChan <- t
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
		if *verbose {
			fmt.Printf("Result: %s %s %s %s\n", t.method, t.u, t.mutation, t.status)
		}
		if t.status != SAFE {
			log.Printf("%s %s %s %s\n", t.method, t.u, t.status, t.mutation)
		}
	}
}
