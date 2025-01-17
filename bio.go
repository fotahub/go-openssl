// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package openssl

// #include "shim.h"
import "C"

import (
	"errors"
	"io"
	"reflect"
	"sync"
	"unsafe"
	"net"

)

const (
	SSLRecordSize = 16 * 1024
)

func nonCopyGoBytes(ptr uintptr, length int) []byte {
	var slice []byte
	header := (*reflect.SliceHeader)(unsafe.Pointer(&slice))
	header.Cap = length
	header.Len = length
	header.Data = ptr
	return slice
}

func nonCopyCString(data *C.char, size C.int) []byte {
	return nonCopyGoBytes(uintptr(unsafe.Pointer(data)), int(size))
}

var writeBioMapping = newMapping()

type writeBio struct {
	data_mtx        sync.Mutex
	op_mtx          sync.Mutex
	buf             []byte
	release_buffers bool
	conn            net.Conn
}

func loadWritePtr(b *C.BIO) *writeBio {
	t := token(C.X_BIO_get_data(b))
	return (*writeBio)(writeBioMapping.Get(t))
}

func bioClearRetryFlags(b *C.BIO) {
	C.X_BIO_clear_flags(b, C.BIO_FLAGS_RWS|C.BIO_FLAGS_SHOULD_RETRY)
}

func bioSetRetryRead(b *C.BIO) {
	C.X_BIO_set_flags(b, C.BIO_FLAGS_READ|C.BIO_FLAGS_SHOULD_RETRY)
}

//export go_write_bio_write
func go_write_bio_write(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: writeBioWrite panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadWritePtr(b)
	if ptr == nil || data == nil || size < 0 {
		return -1
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	bioClearRetryFlags(b)
	ptr.buf = append(ptr.buf, nonCopyCString(data, size)...)
	return size
}

//export go_write_bio_ctrl
func go_write_bio_ctrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: writeBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_WPENDING:
		return writeBioPending(b)
	case C.BIO_CTRL_FLUSH:
		return writeBioFlush(b)
	case C.BIO_CTRL_DUP:
		return 1
	default:
		return 0
	}
}

func writeBioPending(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func writeBioFlush(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	n, err := ptr.WriteToConn()
	if err != nil {
		return 0
	}
	return C.long(n)
}

func (wb *writeBio) WriteToConn() (rv int64, err error) {
	wb.op_mtx.Lock()
	defer wb.op_mtx.Unlock()

	// write whatever data we currently have
	wb.data_mtx.Lock()
	data := wb.buf
	wb.data_mtx.Unlock()

	if len(data) == 0 {
		return 0, nil
	}
	n, err := wb.conn.Write(data)

	// subtract however much data we wrote from the buffer
	wb.data_mtx.Lock()
	wb.buf = wb.buf[:copy(wb.buf, wb.buf[n:])]
	if wb.release_buffers && len(wb.buf) == 0 {
		wb.buf = nil
	}
	wb.data_mtx.Unlock()

	return int64(n), err
}

func (wb *writeBio) Disconnect(b *C.BIO) {
	if loadWritePtr(b) == wb {
		writeBioMapping.Del(token(C.X_BIO_get_data(b)))
		C.X_BIO_set_data(b, nil)
	}
}

func (wb *writeBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_write_bio()
	token := writeBioMapping.Add(unsafe.Pointer(wb))
	C.X_BIO_set_data(rv, unsafe.Pointer(token))
	return rv
}

var readBioMapping = newMapping()

type readBio struct {
	data_mtx        sync.Mutex
	op_mtx          sync.Mutex
	buf             []byte
	eof             bool
	release_buffers bool
	conn            net.Conn
}

func loadReadPtr(b *C.BIO) *readBio {
	return (*readBio)(readBioMapping.Get(token(C.X_BIO_get_data(b))))
}

//export go_read_bio_read
func go_read_bio_read(b *C.BIO, data *C.char, size C.int) (rc C.int) {
	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: go_read_bio_read panic'd: %v", err)
			rc = -1
		}
	}()
	ptr := loadReadPtr(b)
	if ptr == nil || size < 0 {
		return -1
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	bioClearRetryFlags(b)
	if len(ptr.buf) == 0 {
		if ptr.eof {
			return 0
		}
		bioSetRetryRead(b)
		return -1
	}
	if size == 0 || data == nil {
		return C.int(len(ptr.buf))
	}
	n := copy(nonCopyCString(data, size), ptr.buf)
	ptr.buf = ptr.buf[:copy(ptr.buf, ptr.buf[n:])]
	if ptr.release_buffers && len(ptr.buf) == 0 {
		ptr.buf = nil
	}
	return C.int(n)
}

//export go_read_bio_ctrl
func go_read_bio_ctrl(b *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) (
	rc C.long) {

	defer func() {
		if err := recover(); err != nil {
			logger.Critf("openssl: readBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()
	switch cmd {
	case C.BIO_CTRL_PENDING:
		return readBioPending(b)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		return 1
	default:
		return 0
	}
}

func readBioPending(b *C.BIO) C.long {
	ptr := loadReadPtr(b)
	if ptr == nil {
		return 0
	}
	ptr.data_mtx.Lock()
	defer ptr.data_mtx.Unlock()
	return C.long(len(ptr.buf))
}

func (rb *readBio) ReadFromConnOnce() (n int, err error) {
	rb.op_mtx.Lock()
	defer rb.op_mtx.Unlock()

	// make sure we have a destination that fits at least one SSL record
	rb.data_mtx.Lock()
	if cap(rb.buf) < len(rb.buf)+SSLRecordSize {
		new_buf := make([]byte, len(rb.buf), len(rb.buf)+SSLRecordSize)
		copy(new_buf, rb.buf)
		rb.buf = new_buf
	}
	dst := rb.buf[len(rb.buf):cap(rb.buf)]
	dst_slice := rb.buf
	rb.data_mtx.Unlock()

	n, err = rb.conn.Read(dst)
	rb.data_mtx.Lock()
	defer rb.data_mtx.Unlock()
	if n > 0 {
		if len(dst_slice) != len(rb.buf) {
			// someone shrunk the buffer, so we read in too far ahead and we
			// need to slide backwards
			copy(rb.buf[len(rb.buf):len(rb.buf)+n], dst)
		}
		rb.buf = rb.buf[:len(rb.buf)+n]
	}
	return n, err
}

func (rb *readBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_read_bio()
	token := readBioMapping.Add(unsafe.Pointer(rb))
	C.X_BIO_set_data(rv, unsafe.Pointer(token))
	return rv
}

func (rb *readBio) Disconnect(b *C.BIO) {
	if loadReadPtr(b) == rb {
		readBioMapping.Del(token(C.X_BIO_get_data(b)))
		C.X_BIO_set_data(b, nil)
	}
}

func (rb *readBio) MarkEOF() {
	rb.data_mtx.Lock()
	defer rb.data_mtx.Unlock()
	rb.eof = true
}

type anyBio C.BIO

func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (b *anyBio) Read(buf []byte) (n int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n = int(C.X_BIO_read((*C.BIO)(b), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (b *anyBio) Write(buf []byte) (written int, err error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.X_BIO_write((*C.BIO)(b), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if n != len(buf) {
		return n, errors.New("BIO write failed")
	}
	return n, nil
}
