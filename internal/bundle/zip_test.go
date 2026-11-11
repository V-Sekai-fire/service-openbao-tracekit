package bundle

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestWriteRoundTrip(t *testing.T) {
	in := []File{
		{Name: "manifest.json", Data: []byte(`{"format":"tracekit.bundle.v2"}`)},
		{Name: "runs/abc.jsonl", Data: []byte("line one\nline two\n")},
		{Name: "empty", Data: nil},
	}
	out, err := Write(in)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != len(in) {
		t.Fatalf("%d entries, want %d", len(zr.File), len(in))
	}
	for i, f := range zr.File {
		if f.Name != in[i].Name {
			t.Errorf("entry %d named %q, want %q", i, f.Name, in[i].Name)
		}
		if f.Flags != 0 {
			t.Errorf("%s: flags %#x, want 0 (no data descriptor)", f.Name, f.Flags)
		}
		if f.Method != zip.Store {
			t.Errorf("%s: method %d, want stored", f.Name, f.Method)
		}
		if len(f.Extra) != 0 {
			t.Errorf("%s: extra field of %d bytes", f.Name, len(f.Extra))
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("%s: %v (CRC?)", f.Name, err)
		}
		if !bytes.Equal(got, in[i].Data) {
			t.Errorf("%s: contents differ", f.Name)
		}
	}
}

func TestWriteLayoutIsStrict(t *testing.T) {
	out, err := Write([]File{{Name: "a", Data: []byte("x")}})
	if err != nil {
		t.Fatal(err)
	}
	eocd := out[len(out)-22:]
	if binary.LittleEndian.Uint32(eocd[0:4]) != 0x06054b50 {
		t.Fatal("the end-of-central-directory record is not the last 22 bytes")
	}
	cdSize := binary.LittleEndian.Uint32(eocd[12:16])
	cdStart := binary.LittleEndian.Uint32(eocd[16:20])
	if int(cdStart+cdSize) != len(out)-22 {
		t.Fatal("the central directory does not end where the record starts")
	}
	if binary.LittleEndian.Uint16(eocd[20:22]) != 0 {
		t.Fatal("an archive comment is present")
	}
}

func TestWriteIsDeterministic(t *testing.T) {
	in := []File{{Name: "a", Data: []byte("x")}, {Name: "b/c", Data: []byte("yz")}}
	a, err := Write(in)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Write(in)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("the same input gave different bytes")
	}
}

func TestWriteRefusesBadNames(t *testing.T) {
	for _, name := range []string{"../x", "a/../b", "a//b", "/abs", "a/.", "bad name", ""} {
		if _, err := Write([]File{{Name: name, Data: []byte("x")}}); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if _, err := Write([]File{{Name: "a", Data: nil}, {Name: "a", Data: nil}}); err == nil {
		t.Error("duplicate name accepted")
	}
}
