package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/template"
)

// generatePoC returns a PoC request for verifying the desync at the given URL using the supplied method, smuggle
// type (CL.TE or TE.CL) and mutation
func generatePoC(conf Config, method string, uStr string, stype string, mutation string) ([]byte, error) {
	u, err := url.Parse(uStr)
	if err != nil {
		return nil, err
	}

	te, ok := conf.Mutations[mutation]
	if !ok {
		return nil, fmt.Errorf("mutations %s not found", mutation)
	}

	if stype == CLTE {
		return clte(method, u, te, conf.Headers), nil
	} else if stype == TECL {
		return tecl(method, u, te, conf.Headers), nil
	} else {
		return nil, fmt.Errorf("unrecognised smuggles type: %s", stype)
	}
}

// generateScript fills in the specified script template using the given information
func generateScript(conf Config, scriptFile string, method string, uStr string, mutation string) ([]byte, error) {
	u, err := url.Parse(uStr)
	if err != nil {
		return nil, err
	}

	te, ok := conf.Mutations[mutation]
	if !ok {
		return nil, fmt.Errorf("mutation %s not found", mutation)
	}

	// scriptParams is used with the text/template package to fill in the script file
	type scriptParams struct {
		Host     string
		Method   string
		Path     string
		Mutation string
	}
	te = strings.ReplaceAll(te, "\r", "\\r")
	te = strings.ReplaceAll(te, "\n", "\\n")
	path := "/"
	if u.Path != "" {
		path = u.Path
	}

	params := scriptParams{
		Host:     u.Host,
		Method:   method,
		Path:     path,
		Mutation: te,
	}

	t, err := template.ParseFiles(scriptFile)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err = t.Execute(&b, params); err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

// saveState saves the state in a concurrency-safe manner
func saveState(state *State, stateFile *os.File) error {
	state.BaseMux.RLock()
	state.ErrorsMux.RLock()
	state.ResultsMux.RLock()
	b, err := json.Marshal(*state)
	if err != nil {
		return err
	}
	state.BaseMux.RUnlock()
	state.ErrorsMux.RUnlock()
	state.ResultsMux.RUnlock()

	_, err = stateFile.Seek(0, 0)
	if err != nil {
		return err
	}

	_, err = stateFile.Write(b)
	if err != nil {
		return err
	}

	return nil
}
