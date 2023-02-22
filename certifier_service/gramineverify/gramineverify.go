//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gramineverify

/*
#cgo CFLAGS: -I. -I../graminelib
#cgo LDFLAGS: -L/usr/lib/x86_64-linux-gnu -L../graminelib -lgramine -ldl -Wl,-rpath=../graminelib:/usr/lib/x86_64-linux-gnu:../../certifier_service/graminelib:../../../certifier_service/graminelib
#include "graminelib.h"

#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>

void myPrintFunction2() {
	printf("Hello from inline C\n");
}
*/
import "C"
import (
	"fmt"
	"unsafe"
	"encoding/binary"
)

func GramineVerifyEvidence(evidence []byte, endorsements []byte) ([]byte, []byte, error) {
	var assertion_size_bytes = make([]byte, 4)
	copy (assertion_size_bytes, evidence)

	assertion_size := binary.LittleEndian.Uint32(assertion_size_bytes)
	fmt.Printf("GramineVerifyEvidence assertion_size: %v\n", assertion_size)

	var assertion = make([]byte, assertion_size)
	assertion = evidence[4:assertion_size + 4]

	evidencePtr := C.CBytes(assertion)
	defer C.free(evidencePtr)

	var user_data_size_bytes = make([]byte, 4)
	user_data_size_bytes = evidence[4 + assertion_size:8 + assertion_size]
	user_data_size := binary.LittleEndian.Uint32(user_data_size_bytes)
	fmt.Printf("GramineVerifyEvidence user_data_size: %v\n", user_data_size)

	var user_data = make([]byte, user_data_size)
	user_data = evidence[8 + assertion_size:8 + assertion_size + user_data_size]

	endorsementsPtr := C.CBytes(endorsements)
	defer C.free(endorsementsPtr)

	measurementSize := C.ulong(32)
	measurementOut := C.malloc(measurementSize)
	defer C.free(unsafe.Pointer(measurementOut))

	ret := C.graminelib_verify_quote(C.ulong(assertion_size),
		(*C.uchar)(evidencePtr), (*C.ulong)(&measurementSize),
		(*C.uchar)(measurementOut))

	if ret != 0 {
		return nil, nil, fmt.Errorf("graminelib_verify_quote failed");
	}

	// Inline C
	C.myPrintFunction2()
	str := C.CString("Printing from C function")
	C.myPrintFunction(str)
	C.free(unsafe.Pointer(str))

	outMeasurement := C.GoBytes(unsafe.Pointer(measurementOut),
		C.int(measurementSize))

	fmt.Printf("GramineVerifyEvidence measurement received: %v\n", outMeasurement)

	fmt.Printf("GramineVerifyEvidence done\n")
	return user_data, outMeasurement, nil
}
