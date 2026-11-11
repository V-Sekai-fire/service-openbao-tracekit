// Package bundle writes .tkb zip bundles (format v2, section 9) with a strict layout:
// stored entries, no data descriptor, no extra fields, no zip64, no archive comment.
// The writer is hand-rolled: archive/zip's Create sets a data descriptor and a
// modified-time extra field, which the verifier rejects as UNUSABLE BUNDLE.
package bundle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"regexp"
	"strings"
)

const (
	maxEntries    = 10000
	maxEntryBytes = 64 << 20
	maxTotalBytes = 512 << 20
)

// Fixed DOS timestamp (2026-10-10 05:49:22), so the same input always gives the same bytes.
const (
	dosTime = 5<<11 | 49<<5 | 22/2
	dosDate = (2026-1980)<<9 | 10<<5 | 10
)

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9._-]+)*$`)

// File is one bundle entry.
type File struct {
	Name string
	Data []byte
}

func u16(b *bytes.Buffer, v uint16) {
	var x [2]byte
	binary.LittleEndian.PutUint16(x[:], v)
	b.Write(x[:])
}

func u32(b *bytes.Buffer, v uint32) {
	var x [4]byte
	binary.LittleEndian.PutUint32(x[:], v)
	b.Write(x[:])
}

// Write returns the zip bytes for files, in the order given.
func Write(files []File) ([]byte, error) {
	if len(files) > maxEntries {
		return nil, fmt.Errorf("%d entries: more than %d", len(files), maxEntries)
	}
	seen := make(map[string]bool, len(files))
	total := 0
	for _, f := range files {
		if len(f.Name) > 0xFFFF || !nameRE.MatchString(f.Name) {
			return nil, fmt.Errorf("entry name %q is not allowed", f.Name)
		}
		for _, seg := range strings.Split(f.Name, "/") {
			if seg == "." || seg == ".." {
				return nil, fmt.Errorf("entry name %q has a %q segment", f.Name, seg)
			}
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("duplicate entry %q", f.Name)
		}
		seen[f.Name] = true
		if len(f.Data) > maxEntryBytes {
			return nil, fmt.Errorf("entry %q: %d bytes, more than %d", f.Name, len(f.Data), maxEntryBytes)
		}
		total += len(f.Data)
	}
	if total > maxTotalBytes {
		return nil, fmt.Errorf("%d bytes in total: more than %d", total, maxTotalBytes)
	}

	var buf bytes.Buffer
	offsets := make([]uint32, len(files))
	crcs := make([]uint32, len(files))
	for i, f := range files {
		offsets[i] = uint32(buf.Len())
		crcs[i] = crc32.ChecksumIEEE(f.Data)
		size := uint32(len(f.Data))
		u32(&buf, 0x04034b50) // local file header
		u16(&buf, 20)         // version needed
		u16(&buf, 0)          // flags: no encryption, no data descriptor
		u16(&buf, 0)          // method: stored
		u16(&buf, dosTime)
		u16(&buf, dosDate)
		u32(&buf, crcs[i])
		u32(&buf, size)
		u32(&buf, size)
		u16(&buf, uint16(len(f.Name)))
		u16(&buf, 0) // no extra field
		buf.WriteString(f.Name)
		buf.Write(f.Data)
	}

	cdStart := buf.Len()
	for i, f := range files {
		size := uint32(len(f.Data))
		u32(&buf, 0x02014b50) // central directory header
		u16(&buf, 20)         // version made by
		u16(&buf, 20)         // version needed
		u16(&buf, 0)
		u16(&buf, 0)
		u16(&buf, dosTime)
		u16(&buf, dosDate)
		u32(&buf, crcs[i])
		u32(&buf, size)
		u32(&buf, size)
		u16(&buf, uint16(len(f.Name)))
		u16(&buf, 0) // extra
		u16(&buf, 0) // comment
		u16(&buf, 0) // disk number
		u16(&buf, 0) // internal attributes
		u32(&buf, 0) // external attributes
		u32(&buf, offsets[i])
		buf.WriteString(f.Name)
	}
	cdSize := buf.Len() - cdStart

	u32(&buf, 0x06054b50) // end of central directory: the last 22 bytes
	u16(&buf, 0)
	u16(&buf, 0)
	u16(&buf, uint16(len(files)))
	u16(&buf, uint16(len(files)))
	u32(&buf, uint32(cdSize))
	u32(&buf, uint32(cdStart))
	u16(&buf, 0) // no archive comment
	return buf.Bytes(), nil
}
