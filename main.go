package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/ryanuber/go-glob"
	"github.com/schollz/progressbar/v3"
	flag "github.com/spf13/pflag"
)

var mutations map[string]string
var debug *bool

func main() {
	// Scanning options
	workers := flag.IntP("workers", "c", 10, "the number of concurrent workers")
	methods := flag.StringSliceP("methods", "m", []string{"GET", "POST", "PUT", "DELETE"}, "the methods to test")
	delay := flag.DurationP("delay", "", 5*time.Second, "the extra time delay on top of the base time that indicates the service is vulnerable")
	enabled := flag.StringSliceP("enable", "e", nil, "globs of modules to enable")
	disabled := flag.StringSliceP("disable", "d", nil, "globs of modules to disable")
	stopAfter := flag.UintP("stop-after", "x", 0, "the number of smuggling vulnerabilities to find in a host before stopping testing on it. This won't cancel already queued tests, so slightly more than this number of vulnerabilities may be found")

	// Output display options
	showProgress := flag.BoolP("progress", "p", false, "show a progress bar instead of output discovered vulnerabilities to stdout")
	verbose := flag.BoolP("verbose", "v", false, "print scanned hosts to stdout")
	debug = flag.BoolP("debug", "", false, "time each request and output the times to stdout")

	// Output file options
	outfilename := flag.StringP("output", "o", "", "the log file to write to")
	basefilename := flag.StringP("base", "b", "", "the base file with request times to use (default \"smuggles.base\")")
	errfilename := flag.StringP("error-log", "", "", "the file to log errors to")
	outDir := flag.StringP("dir", "O", "", "the directory to output the log, error log, and base file to")

	// Early exit flags
	generatePoc := flag.BoolP("poc", "", false, "generate a PoC from a provided line of the log file of format <method> <url> <desync type> <mutation name> and exit")
	generateScript := flag.StringP("script", "", "", "generate a Turbo Intruder script using the specified file as a base, to verify the smuggling issue with a 404 request from a provided line of the log file of format <method> <url> <desync type> <mutation name>")
	gadget := flag.StringP("mutation", "", "", "print the specified Transfer-Encoding header mutation and exit")
	list := flag.BoolP("list", "l", false, "list the enabled mutation names and exit")

	flag.Parse()

	// Generate the enabled mutations
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

	// Check for options that lead to early exit
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

	if *gadget != "" {
		header, ok := mutations[*gadget]
		if ok {
			fmt.Println(header)
			os.Exit(0)
		} else {
			fmt.Println("Mutation not found")
			os.Exit(1)
		}
	}

	if *generatePoc || *generateScript != "" {
		if flag.NArg() != 4 {
			fmt.Println("Positional arguments should be: <method> <url> <desync type> <mutation name>")
			if *generatePoc {
				fmt.Println("e.g.: smuggles --poc GET https://example.com CL.TE lineprefix-space")
			} else {
				fmt.Println("e.g.: smuggles --script resources/clte.py GET https://example.com CL.TE lineprefix-space")
			}
			os.Exit(1)
		}

		u, err := url.Parse(flag.Arg(1))
		if err != nil {
			fmt.Printf("Couldn't parse URL: %v\n", err)
			os.Exit(1)
		}
		mutation, ok := mutations[flag.Arg(3)]
		if !ok {
			fmt.Printf("Mutation %s not found\n", flag.Arg(3))
			os.Exit(1)
		}
		method := flag.Arg(0)
		desyncType := flag.Arg(2)

		if *generatePoc {
			var req []byte
			if desyncType == CLTE {
				req = clte(method, u, mutation)
			} else if desyncType == TECL {
				req = tecl(method, u, mutation)
			} else {
				fmt.Printf("Unknown desync type: %s\n", desyncType)
				os.Exit(1)
			}

			fmt.Println(string(req))
			os.Exit(0)
		} else {
			type scriptParams struct {
				Host     string
				Method   string
				Path     string
				Mutation string
			}
			mutation = strings.ReplaceAll(mutation, "\r", "\\r")
			mutation = strings.ReplaceAll(mutation, "\n", "\\n")
			path := "/"
			if u.Path != "" {
				path = u.Path
			}
			params := scriptParams{
				Host:     u.Host,
				Method:   method,
				Path:     path,
				Mutation: mutation,
			}

			t, err := template.ParseFiles(*generateScript)
			if err != nil {
				fmt.Printf("Failed to parse template file: %v\n", err)
			}
			if err = t.Execute(os.Stdout, params); err != nil {
				fmt.Printf("Failed to fill script template: %v\n", err)
			}
			os.Exit(0)
		}
	}

	urls := make([]*url.URL, 0)

	// Logging
	var reslog *log.Logger
	var errlog *log.Logger
	if *outDir != "" {
		if *outfilename == "" {
			*outfilename = path.Join(*outDir, "smuggles.log")
		}
		if *basefilename == "" {
			*basefilename = path.Join(*outDir, "smuggles.base")
		}
		if *errfilename == "" {
			*errfilename = path.Join(*outDir, "smuggles.errors")
		}
	}

	if *outfilename != "" {
		f, err := os.OpenFile(*outfilename, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outputs := []io.Writer{f}
		if !*showProgress {
			outputs = append(outputs, os.Stdout)
		}
		mw := io.MultiWriter(outputs...)
		reslog = log.New(mw, "", 0)
	} else if *showProgress {
		fmt.Println("WARNING: progress bar being shown and no output file specified - discovered vulnerabilities will not be outputted anywhere!")
		reslog = log.New(ioutil.Discard, "", 0)
	} else {
		reslog = log.New(os.Stdout, "", 0)
	}

	if *errfilename != "" {
		f, err := os.OpenFile(*errfilename, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Printf("Failed to open error log file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		outputs := []io.Writer{f}
		if !*showProgress {
			outputs = append(outputs, os.Stdout)
		}

		mw := io.MultiWriter(outputs...)
		errlog = log.New(mw, "ERROR:", 0)
	} else {
		errlog = log.New(os.Stderr, "ERROR:", 0)
	}

	// The base times for standard requests
	var base map[string]time.Duration
	if *basefilename == "" {
		*basefilename = "smuggles.base"
	}
	baseFile, err := os.OpenFile(*basefilename, os.O_RDWR|os.O_CREATE, 0644)
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

	// Fill in any missing entries in the base file
	fmt.Println("Getting missing base times...")
	baseUrls := make(chan *url.URL)
	errs := make(chan error)
	baseResults := make(chan baseResult)
	baseWg := sync.WaitGroup{}
	baseWg.Add(*workers)
	baseMux := sync.RWMutex{}
	for i := 0; i < *workers; i++ {
		go baseWorker(baseUrls, baseResults, errs, baseWg.Done)
	}

	// Read from stdin
	go func() {
		var bar *progressbar.ProgressBar
		if *showProgress {
			bar = progressbar.Default(-1)
		}
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			urlStr := scanner.Text()
			u, err := url.Parse(urlStr)
			if err != nil {
				errlog.Println(err)
			}
			baseMux.RLock()
			_, exists := base[u.String()]
			baseMux.RUnlock()
			if !exists {
				baseUrls <- u
				if *showProgress {
					bar.Add(1)
				}
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
		for err := range errs {
			errlog.Println(err)
		}
	}()

	for r := range baseResults {
		baseMux.Lock()
		base[r.u.String()] = r.t
		baseMux.Unlock()
		if *verbose {
			fmt.Printf("%s %d\n", r.u, r.t)
		}
	}

	// Save the file
	b, err := json.Marshal(base)
	if err != nil {
		errlog.Printf("Error marshalling base times to JSON: %v\n", err)
		return
	}

	_, err = baseFile.Seek(0, 0)
	if err != nil {
		errlog.Printf("Error seeking to start of file: %v\n", err)
	}

	_, err = baseFile.Write(b)
	if err != nil {
		errlog.Printf("Error writing base to file: %v\n", err)
	}
	baseFile.Close()

	// Now smuggle test
	fmt.Println("Testing smuggling...")

	// Counts the number of issues found on each host for use with the -x flag
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
		var bar *progressbar.ProgressBar
		if *showProgress {
			bar = progressbar.Default(int64(len(tests)))
		}

		rand.Seed(time.Now().Unix())
		for len(tests) > 0 {
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
			if *showProgress {
				bar.Add(1)
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
			reslog.Printf("%s %s %s %s\n", t.method, t.u, t.status, t.mutation)
			if *stopAfter > 0 {
				vulnsMux.Lock()
				vulns[t.u.String()] += 1
				vulnsMux.Unlock()
			}
		}
	}
}
