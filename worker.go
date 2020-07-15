package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/url"
	"time"
)

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
			// Send the verification request
			req = clteVerify(t.method, t.u, mutations[t.mutation])
			_, err, verifyTimeout := sendRequest(req, t.u, t.timeout)

			if !verifyTimeout {
				t.status = CLTE
				results <- t
				continue
			} else if err != nil {
				errs <- err
			}
		} else if err != nil {
			errs <- err
		}

		// First test for TE.CL
		req = tecl(t.method, t.u, mutations[t.mutation])
		_, err, isTimeout = sendRequest(req, t.u, t.timeout)
		if isTimeout {
			// Send the verification request
			req = teclVerify(t.method, t.u, mutations[t.mutation])
			_, err, verifyTimeout := sendRequest(req, t.u, t.timeout)

			if !verifyTimeout {
				t.status = TECL
				results <- t
				continue
			} else if err != nil {
				errs <- err
			}
		} else if err != nil {
			errs <- err
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
	e := make(chan error)
	go func() {
		r, err := ioutil.ReadAll(conn)
		if err != nil {
			e <- err
		} else {
			c <- r
		}
	}()

	select {
	case resp = <-c:
	case err = <-e:
	case <-time.After(timeout):
		isTimeout = true
		conn.Close()
	}

	return
}
