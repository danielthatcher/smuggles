package main

import "fmt"

// generateMutations returns a map of TE header mutations, indexed by name
func generateMutations() map[string]string {
	m := make(map[string]string, 0)

	m["standard"] = "Transfer-Encoding: chunked"
	m["nospace"] = "Transfer-Encoding:chunked"

	// Invalid start of header lines
	m["lineprefix-space"] = " Transfer-Encoding: chunked"
	m["lineprefix-tab"] = "\tTransfer-Encoding: chunked"

	// Characters at end of header lines
	m["line-appendix-space"] = "Transfer-Encoding: chunked "
	m["line-appendix-tab"] = "Transfer-Encoding: chunked\t"
	m["line-appendix-cr"] = "Transfer-Encoding: chunked\r"
	m["line-appendix-nl"] = "Transfer-Encoding: chunked\n"
	m["line-appendix-vtab"] = "Transfer-Encoding: chunked\x0b"

	// Characters around colon
	m["colon-pre-null"] = "Transfer-Encoding\x00: chunked"
	m["colon-post-null"] = "Transfer-Encoding:\x00chunked"
	m["colon-post-tab"] = "Transfer-Encoding:\tchunked"
	m["colon-wrap-tab"] = "Transfer-Encoding\t:\tchunked"
	m["colon-post-vtab"] = "Transfer-Encoding:\x0bchunked"
	m["colon-wrap-vtab"] = "Transfer-Encoding\x0b:\x0bchunked"
	m["colon-pre-cr"] = "Transfer-Encoding\r: chunked"
	m["colon-post-cr"] = "Transfer-Encoding: \rchunked"
	m["colon-wrapped-space"] = "Transfer-Encoding : chunked"
	m["colon-pre-nl"] = "Transfer-Encoding\n: chunked"
	m["colon-post-nl"] = "Transfer-Encoding:\nchunked"
	m["colon-post-ff"] = "Transfer-Encoding:\xffchunked"
	m["headername-junk"] = "Transfer-Encoding abcdef: chunked"

	// Quotes
	m["single-qoute"] = "Transfer-Encoding: 'chunked'"
	m["double-qoute"] = "Transfer-Encoding: \"chunked\""

	// Cases
	m["uppercase"] = "TRANSFER-ENCODING: chunked"
	m["lowercase"] = "transfer-encoding: chunked"
	m["mixedcase"] = "tRANsfEr-ENCodInG: chunked"
	m["chunked-uppercase"] = "Transfer-Encoding: CHUNKED"

	// Searching for similar names
	m["cutoff"] = "Transfer-Encoding: chunk"
	m["lazy"] = "Transfer-Encoding: chunkedz"

	// \n tricks
	m["newline"] = "X: y\nTransfer-Encoding: chunked"
	m["double-newline"] = "Foo: bar\n\nTransfer-Encoding: chunked"
	m["carriagereturn"] = "X: y\rTransfer-Encoding: chunked"
	m["double-carriagereturn"] = "Foo: bar\r\rTransfer-Encoding: chunked"

	// Accents
	m["acute"] = "Transfer-Encoding: chunkéd"
	m["grave"] = "Trànsfer-Encoding: chunked"

	// Misc tricks
	m["connection-te"] = "Connection: Transfer-Encoding\r\nTransfer-Encoding: chunked"
	m["connection-cl"] = "Connection: Content-Length\r\nTransfer-Encoding: chunked"
	m["content-encoding"] = "Content-Encoding: chunked"

	// Multiple values of Transfer-Encoding
	other_encodings := [][]string{
		{"compress", "cmp"},
		{"deflate", "def"},
		{"gzip", "gz"},
		{"x-gzip", "xgz"},
		{"identity", "id"},
		{"null", "null"},
		{"z", "z"},
		{" ", "space"},
		{"chunked", "ch"},
	}
	for _, e := range other_encodings {
		// Multiple headers with different values
		k := fmt.Sprintf("multiple-ch_%s", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: chunked\r\nTransfer-Encoding: %s", e[0])
		k = fmt.Sprintf("multiple-%s_ch", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: %s\r\nTransfer-Encoding: chunked", e[0])

		// Multiple values separated by a comma
		k = fmt.Sprintf("comma-ch_%s", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: chunked, %s", e[0])
		k = fmt.Sprintf("comma-%s_ch", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: %s, chunked", e[0])

		// Multiple values separated by a comma with a tab instead of a space
		k = fmt.Sprintf("commatab-ch_%s", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: chunked,\t%s", e[0])
		k = fmt.Sprintf("commatab-%s_ch", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: %s,\tchunked", e[0])

		// Multiple values separated by a space
		k = fmt.Sprintf("spacesep-ch_%s", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: chunked %s", e[0])
		k = fmt.Sprintf("spacesep-%s_ch", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: %s chunked", e[0])

		// Wrap values in commas
		k = fmt.Sprintf("commawrap-ch_%s", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: chunked, %s, chunked", e[0])
		k = fmt.Sprintf("commawrap-%s_ch", e[1])
		m[k] = fmt.Sprintf("Transfer-Encoding: %s, chunked, %s", e[0], e[0])
	}

	return m
}
