package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"sync"
	"time"
)

type Worker struct {
	Conf         Config
	Errs         chan<- error
	ErrCounts    *map[string]uint
	ErrCountsMux *sync.RWMutex
}

type BaseResult struct {
	Time time.Duration
	Url  *url.URL
}

// BaseTimes fetches urls on a channel and times how long it takes to fetch those URLs
func (w *Worker) BaseTimes(urls <-chan *url.URL, results chan<- BaseResult, done func()) {
	for u := range urls {
		req := baseReq(u, w.Conf.Headers)
		start := time.Now()
		_, err, _ := w.SendRequest(req, u, 30*time.Second)
		end := time.Now()
		duration := end.Sub(start)
		if err != nil {
			w.Errs <- err
			continue
		}

		results <- BaseResult{duration, u}
	}
	done()
}

// SmuggleType represents the type of smuggling vulnerability - either CL.TE or TE.CL
type SmuggleType string

const (
	SAFE = ""
	CLTE = "CL.TE"
	TECL = "TE.CL"
)

// SmuggleTest represents the parameters for a test of CL.TE and TE.CL smuggling against
// a single URL using a single method and a single Transfer-Encoding header mutation
type SmuggleTest struct {
	// The URL to test
	Url *url.URL

	// The Method to test
	Method string

	// The name of the Mutation to use. Should be a key in mutations
	Mutation string

	// The delay that will indicate the service is vulnerable. Should be calculated off
	// of the time take for the base request to this service
	Timeout time.Duration

	// The type of attack the service is vulnerable to
	Status SmuggleType
}

// Equals returns whether two SmuggleTests are equal
func (t SmuggleTest) Equals(s SmuggleTest) bool {
	return t.Url.String() == s.Url.String() && t.Method == s.Method && t.Mutation == s.Mutation
}

// smuggleWorker sends requests URLs using the given Transfer-Encoding header,
// and checks for CL.TE then TE.CL vulnerabilities
func (w *Worker) SmuggleTest(tests <-chan SmuggleTest, results chan<- SmuggleTest, done func()) {
	for t := range tests {
		// Skip test if we've received too many errors for this URL
		if w.Conf.MaxErrors > 0 {
			w.ErrCountsMux.RLock()
			if (*w.ErrCounts)[t.Url.String()] >= w.Conf.MaxErrors {
				continue
			}
			w.ErrCountsMux.RUnlock()
		}

		// First test for CL.TE
		req := clte(t.Method, t.Url, w.Conf.Mutations[t.Mutation], w.Conf.Headers)
		_, err, isTimeout := w.SendRequest(req, t.Url, t.Timeout)
		if isTimeout {
			// Send the verification request
			req = clteVerify(t.Method, t.Url, w.Conf.Mutations[t.Mutation], w.Conf.Headers)
			_, err, verifyTimeout := w.SendRequest(req, t.Url, t.Timeout)

			if !verifyTimeout {
				t.Status = CLTE
				results <- t
				continue
			} else if err != nil {
				w.ErrCountsMux.Lock()
				(*w.ErrCounts)[t.Url.String()]++
				w.ErrCountsMux.Unlock()
				w.Errs <- err
			}
		} else if err != nil {
			w.ErrCountsMux.Lock()
			(*w.ErrCounts)[t.Url.String()]++
			w.ErrCountsMux.Unlock()
			w.Errs <- err
		}

		// First test for TE.CL
		req = tecl(t.Method, t.Url, w.Conf.Mutations[t.Mutation], w.Conf.Headers)
		_, err, isTimeout = w.SendRequest(req, t.Url, t.Timeout)
		if isTimeout {
			// Send the verification request
			req = teclVerify(t.Method, t.Url, w.Conf.Mutations[t.Mutation], w.Conf.Headers)
			_, err, verifyTimeout := w.SendRequest(req, t.Url, t.Timeout)

			if !verifyTimeout {
				t.Status = TECL
				results <- t
				continue
			} else if err != nil {
				w.ErrCountsMux.Lock()
				(*w.ErrCounts)[t.Url.String()]++
				w.ErrCountsMux.Unlock()
				w.Errs <- err
			}
		} else if err != nil {
			w.ErrCountsMux.Lock()
			(*w.ErrCounts)[t.Url.String()]++
			w.ErrCountsMux.Unlock()
			w.Errs <- err
		}

		results <- t
	}
	done()
}

// sendRequest sends the specified request, but doesn't try to parse the response,
// and instead just returns it
func (w *Worker) SendRequest(req []byte, u *url.URL, timeout time.Duration) (resp []byte, err error, isTimeout bool) {
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
	e := make(chan error)
	go func() {
		r, err := ioutil.ReadAll(conn)
		if err != nil {
			e <- err
		} else {
			c <- r
		}
	}()

	var start time.Time
	if w.Conf.Debug {
		start = time.Now()
	}

	select {
	case resp = <-c:
	case err = <-e:
	case <-time.After(timeout):
		isTimeout = true
		conn.Close()
	}

	if w.Conf.Debug {
		d := time.Now().Sub(start)
		fmt.Printf("Request to %s took %dms (timeout: %t)\n", u.String(), d.Milliseconds(), isTimeout)
		fmt.Println(string(req))
		fmt.Println("---")
	}

	return
}
