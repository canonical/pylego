package main

import "C"
import (
	"encoding/json"
	"fmt"
)

type LegoArgs struct {
	Email  string `json:"email"`
	Server string `json:"server"`
	CSR    string `json:"csr"`
	Plugin string `json:"plugin"`
	Env    map[string]interface{}
}

//export RunLegoCommand
func RunLegoCommand(message *C.char) *C.char {
	goStrMessage := C.GoString(message)
	var CLIArgs LegoArgs
	if err := json.Unmarshal([]byte(goStrMessage), &CLIArgs); err != nil {
		fmt.Println("cli args failed validation", err.Error())
	}
	return_message_ptr := C.CString("--cert string--")
	return return_message_ptr
}

func main() {}
