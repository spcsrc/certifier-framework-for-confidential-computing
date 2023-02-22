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
	var size_bytes = make([]byte, 4)
	copy (size_bytes, evidence)

	assertion_size := binary.LittleEndian.Uint32(size_bytes)
	fmt.Printf("GramineVerifyEvidence assertion_size: %v\n", assertion_size)

	var assertion = make([]byte, assertion_size)
	assertion = evidence[4:assertion_size + 4]

	evidencePtr := C.CBytes(assertion)
	defer C.free(evidencePtr)
	endorsementsPtr := C.CBytes(endorsements)
	defer C.free(endorsementsPtr)

	customClaimOutSize := C.ulong(4096)
	customClaimOut := C.malloc(customClaimOutSize)
	defer C.free(unsafe.Pointer(customClaimOut))
	measurementSize := C.ulong(256)
	measurementOut := C.malloc(measurementSize)
	defer C.free(unsafe.Pointer(measurementOut))

	ret := C.graminelib_verify_quote((*C.uchar)(evidencePtr),
		C.ulong(assertion_size))

	if ret != 0 {
		return nil, nil, fmt.Errorf("graminelib_verify_quote failed");
	}

	// Inline C
	C.myPrintFunction2()
	str := C.CString("Printing from C function")
	C.myPrintFunction(str)
	C.free(unsafe.Pointer(str))

	outCustomClaims := C.GoBytes(unsafe.Pointer(customClaimOut),
		C.int(customClaimOutSize))
	outMeasurement := C.GoBytes(unsafe.Pointer(measurementOut),
		C.int(measurementSize))

	fmt.Printf("GramineVerifyEvidence done\n")
	return outCustomClaims, outMeasurement, nil
}
