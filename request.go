package main

import (
	"fmt"
	"net/url"
)

// baseReq returns a base request used to test the service
func baseReq(u *url.URL) []byte {
	path := "/"
	if u.Path != "" {
		path = u.Path
	}

	f := fmt.Sprintf("GET %s HTTP/1.1\r\n", path)
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "\r\n"

	return []byte(f)
}

// clte returns a CL.TE test request for the given URL using the given method and Transfer-Encoding header.
// If a CL.TE issue is exploitable with the giiven TE header, then this request should timeout.
func clte(method string, u *url.URL, te string) []byte {
	path := "/"
	if u.Path != "" {
		path = u.Path

	}

	f := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	f += te + "\r\n"
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "Content-Length: 4\r\n"
	f += "\r\n"
	f += "1\r\nZ\r\nQ"

	return []byte(f)
}

// tecl returns a TE.Cl test request for the given URL using the given method and Transfer-Encoding header.
// If a TE.CL issue is exploitable with the giiven TE header, then this request should timeout.
func tecl(method string, u *url.URL, te string) []byte {
	path := "/"
	if u.Path != "" {
		path = u.Path

	}

	f := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	f += te + "\r\n"
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "Content-Length: 6\r\n"
	f += "\r\n"
	f += "0\r\n\r\nX"

	return []byte(f)
}

// clteVerif returns a CL.TE verification request for the given URL using the given method and Transfer-Encoding header.
// If a CL.TE issue is exploitable with the given TE header, then this request should not timeout, but will likely
// return an error status code due to an invalid content length.
func clteVerify(method string, u *url.URL, te string) []byte {
	path := "/"
	if u.Path != "" {
		path = u.Path

	}

	f := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	f += te + "\r\n"
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "Content-Length: 7\r\n"
	f += "\r\n"
	f += "1\r\nZ\r\nQ"

	return []byte(f)
}

// teclVerify returns a TE.Cl verification request for the given URL using the given method and Transfer-Encoding header
// If a TE.CL issue is exploitable with the given TE header, then this request should not timeout.
func teclVerify(method string, u *url.URL, te string) []byte {
	path := "/"
	if u.Path != "" {
		path = u.Path

	}

	f := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path)
	f += te + "\r\n"
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "Content-Length: 5\r\n"
	f += "\r\n"
	f += "0\r\n\r\n"

	return []byte(f)
}
