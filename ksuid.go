package ksuid

import (
	"bytes"
	"crypto/rand"
	"database/sql/driver"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sync"
	"time"
)

const (
	epochStamp             int64 = 1400000000
	timestampLengthInBytes       = 4
	payloadLengthInBytes         = 16
	byteLength                   = timestampLengthInBytes + payloadLengthInBytes
	stringEncodedLength          = 27

	minStringEncoded = "000000000000000000000000000"
	maxStringEncoded = "aWgEPTl1tmebfsQzFP4bxwgy80V"
)

type KSUID [byteLength]byte

var (
	rander     = rand.Reader
	randMutex  sync.Mutex
	randBuffer [payloadLengthInBytes]byte

	errSize        = fmt.Errorf("valid KSUIDs are %v bytes", byteLength)
	errStrSize     = fmt.Errorf("valid encoded KSUIDs are %v characters", stringEncodedLength)
	errStrValue    = fmt.Errorf("valid encoded KSUIDs are bounded by %s and %s", minStringEncoded, maxStringEncoded)
	errPayloadSize = fmt.Errorf("valid KSUID payloads are %v bytes", payloadLengthInBytes)

	Nil = KSUID{}
	Max = KSUID{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}
)

func (k KSUID) Append(b []byte) []byte {
	return fastAppendEncodeBase62(b, k[:])
}

func (k KSUID) String() string {
	return string(k.Append(make([]byte, 0, stringEncodedLength)))
}

func (k KSUID) Bytes() []byte {
	return k[:]
}

func (k KSUID) Time() time.Time {
	return correctedUTCTimestampToTime(k.Timestamp())
}

func (k KSUID) Timestamp() uint32 {
	return binary.BigEndian.Uint32(k[:timestampLengthInBytes])
}

func (k KSUID) Payload() []byte {
	return k[timestampLengthInBytes:]
}

func (k KSUID) IsNil() bool {
	return k == Nil
}

func (k KSUID) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

func (k KSUID) MarshalBinary() ([]byte, error) {
	return k.Bytes(), nil
}

func (k *KSUID) UnmarshalText(b []byte) error {
	id, err := Parse(string(b))
	if err != nil {
		return err
	}
	*k = id
	return nil
}

func (k *KSUID) UnmarshalBinary(b []byte) error {
	id, err := FromBytes(b)
	if err != nil {
		return err
	}
	*k = id
	return nil
}

func (k KSUID) Get() any {
	return k
}

func (k *KSUID) Set(s string) error {
	return k.UnmarshalText([]byte(s))
}

func (k KSUID) Value() (driver.Value, error) {
	if k.IsNil() {
		return nil, nil
	}
	return k.String(), nil
}

func (k *KSUID) Scan(src any) error {
	switch v := src.(type) {
	case nil:
		return k.scan(nil)
	case []byte:
		return k.scan(v)
	case string:
		return k.scan([]byte(v))
	default:
		return fmt.Errorf("scan: unable to scan type %T into KSUID", v)
	}
}

func (k *KSUID) scan(b []byte) error {
	switch len(b) {
	case 0:
		*k = Nil
		return nil
	case byteLength:
		return k.UnmarshalBinary(b)
	case stringEncodedLength:
		return k.UnmarshalText(b)
	default:
		return errSize
	}
}

func (k KSUID) Next() KSUID {
	t := k.Timestamp()
	v := add128(uint128Payload(k), makeUint128(0, 1))
	if v == makeUint128(0, 0) {
		t++
	}
	return v.ksuid(t)
}

func (k KSUID) Prev() KSUID {
	t := k.Timestamp()
	v := sub128(uint128Payload(k), makeUint128(0, 1))
	if v == makeUint128(math.MaxUint64, math.MaxUint64) {
		t--
	}
	return v.ksuid(t)
}

func New() KSUID {
	id, err := NewRandom()
	if err != nil {
		panic(fmt.Sprintf("Couldn't generate KSUID: %v", err))
	}
	return id
}

func NewRandom() (KSUID, error) {
	return NewRandomWithTime(time.Now())
}

func NewRandomWithTime(t time.Time) (KSUID, error) {
	randMutex.Lock()
	defer randMutex.Unlock()

	var id KSUID
	if _, err := io.ReadAtLeast(rander, randBuffer[:], len(randBuffer)); err != nil {
		return Nil, err
	}

	copy(id[timestampLengthInBytes:], randBuffer[:])
	binary.BigEndian.PutUint32(id[:timestampLengthInBytes], timeToCorrectedUTCTimestamp(t))
	return id, nil
}

func NewBytes() []byte {
	return New().Bytes()
}

func NewString() string {
	return New().String()
}

func FromParts(t time.Time, payload []byte) (KSUID, error) {
	if len(payload) != payloadLengthInBytes {
		return Nil, errPayloadSize
	}
	var id KSUID
	binary.BigEndian.PutUint32(id[:timestampLengthInBytes], timeToCorrectedUTCTimestamp(t))
	copy(id[timestampLengthInBytes:], payload)
	return id, nil
}

func FromPartsOrNil(t time.Time, payload []byte) KSUID {
	id, err := FromParts(t, payload)
	if err != nil {
		return Nil
	}
	return id
}

func FromBytes(b []byte) (KSUID, error) {
	if len(b) != byteLength {
		return Nil, errSize
	}
	var id KSUID
	copy(id[:], b)
	return id, nil
}

func FromBytesOrNil(b []byte) KSUID {
	id, err := FromBytes(b)
	if err != nil {
		return Nil
	}
	return id
}

func Parse(s string) (KSUID, error) {
	if len(s) != stringEncodedLength {
		return Nil, errStrSize
	}
	var src [stringEncodedLength]byte
	var dst [byteLength]byte
	copy(src[:], s)
	if err := fastDecodeBase62(dst[:], src[:]); err != nil {
		return Nil, errStrValue
	}
	return FromBytes(dst[:])
}

func ParseOrNil(s string) KSUID {
	id, err := Parse(s)
	if err != nil {
		return Nil
	}
	return id
}

func SetRand(r io.Reader) {
	if r == nil {
		rander = rand.Reader
	} else {
		rander = r
	}
}

func Compare(a, b KSUID) int {
	return bytes.Compare(a[:], b[:])
}

func Sort(ids []KSUID) {
	quickSort(ids, 0, len(ids)-1)
}

func IsSorted(ids []KSUID) bool {
	for i := 1; i < len(ids); i++ {
		if Compare(ids[i-1], ids[i]) > 0 {
			return false
		}
	}
	return true
}

func timeToCorrectedUTCTimestamp(t time.Time) uint32 {
	return uint32(t.Unix() - epochStamp)
}

func correctedUTCTimestampToTime(ts uint32) time.Time {
	return time.Unix(int64(ts)+epochStamp, 0)
}

func quickSort(a []KSUID, lo, hi int) {
	if lo < hi {
		pivot := a[hi]
		i := lo - 1
		for j := lo; j < hi; j++ {
			if Compare(a[j], pivot) < 0 {
				i++
				a[i], a[j] = a[j], a[i]
			}
		}
		i++
		a[i], a[hi] = a[hi], a[i]
		quickSort(a, lo, i-1)
		quickSort(a, i+1, hi)
	}
}
