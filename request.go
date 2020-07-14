package main

import (
	"fmt"
	"net/url"
)

// baseReq returns a base request used to test the service
func baseReq(u *url.URL) []byte {
	f := fmt.Sprintf("GET %s HTTP/1.1\r\n", u.Path)
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "\r\n"

	return []byte(f)
}

// clte returns a CL.TE test request for the given URL using the given method and Transfer-Encoding header
func clte(method string, u *url.URL, te string) []byte {
	f := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, u.Path)
	f += te + "\r\n"
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "Content-Length: 4\r\n"
	f += "\r\n"
	f += "1\r\nZ\r\nQ"

	return []byte(f)
}

// tecl returns a TE.Cl test request for the given URL using the given method and Transfer-Encoding header
func tecl(method string, u *url.URL, te string) []byte {
	f := fmt.Sprintf("%s %s HTTP/1.1\r\n", method, u.Path)
	f += te + "\r\n"
	f += fmt.Sprintf("Host: %s\r\n", u.Hostname())
	f += "Connection: close\r\n"
	f += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.246\r\n"
	f += "Content-Length: 6\r\n"
	f += "\r\n"
	f += "0\r\n\r\nX"

	return []byte(f)
}
