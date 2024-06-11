package main

import (
	"C"
)
import (
	"encoding/json"
	"fmt"
	"unicode/utf16"
	"unsafe"
)

type LegoArgs struct {
	Email    string `json:"email"`
	Server   string `json:"server"`
	CSR_path string `json:"csr_path"`
	Plugin   string `json:"plugin"`
	Env      map[string]interface{}
}

//export RunLegoCommand
func RunLegoCommand(message *C.wchar_t) int {
	var goMessage []uint16
	for ptr := uintptr(unsafe.Pointer(message)); ; ptr += unsafe.Sizeof(C.wchar_t(0)) {
		wchar := *(*C.wchar_t)(unsafe.Pointer(ptr))
		if wchar == 0 {
			break
		}
		goMessage = append(goMessage, uint16(wchar))
	}
	jsonStr := string(utf16.Decode(goMessage))
	var CLIArgs LegoArgs
	if err := json.Unmarshal([]byte(jsonStr), &CLIArgs); err != nil {
		fmt.Println("cli args failed validation", err.Error())
	}
	fmt.Println(CLIArgs)
	return 0
}

func main() {}
