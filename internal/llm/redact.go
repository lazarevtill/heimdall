package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// maxUserJSONBytes caps a JSON user payload AFTER redaction. It is the same
// 32 KB the Tier-2 digest is held to when it is written, so a digest that
// honoured its own budget always fits. Over the cap, Analyze refuses the
// request outright: a JSON document cut at a byte offset is no longer a JSON
// document, and the model would be reasoning over a prefix that silently
// lost its closing rows and marker arrays.
const maxUserJSONBytes = 32 << 10

// redactJSON re-encodes the JSON document doc with every string in it —
// object keys and values alike — passed through redact on its DECODED text,
// one string at a time, in document order.
//
// This is why the analyst's digest is redacted here rather than as one
// serialized string. A pattern run over the whole document sees JSON
// syntax as ordinary text: the url-credentials pattern once matched from
// one row's "https://" to a LATER row's "@", deleting everything between
// and splicing two rows into one — still valid JSON, zero failures counted,
// and a real row_id left attached to another row's data. Per string, a
// match cannot cross a field boundary, and an escape (`\n`, ` `) is
// seen as the character it stands for.
//
// Everything else is reproduced exactly: numbers keep their literal text,
// structure and order are unchanged, and strings are re-encoded the way
// encoding/json writes them — so a document json.Marshal produced, with
// nothing to redact, comes back byte-identical.
//
// redact is contract.EvidenceOrWithheld in production (a seam, so a test
// can make it fail); every string it reports as failed is counted into the
// returned total. A doc that is not exactly one valid JSON value is an
// error, never a best-effort rewrite.
func redactJSON(doc []byte, redact func(string) (string, bool)) (out []byte, failures int, err error) {
	if !json.Valid(doc) {
		return nil, 0, errors.New("not a single valid JSON value")
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()

	// Per open container: is it an object, and how many tokens (keys and
	// values alike) it has emitted — all that is needed to place every ','
	// and ':' the tokenizer consumed.
	type frame struct {
		object bool
		n      int
	}
	var stack []frame
	var b bytes.Buffer
	b.Grow(len(doc))
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			b.WriteByte(byte(d))
			stack = stack[:len(stack)-1]
			continue
		}
		if len(stack) > 0 {
			top := &stack[len(stack)-1]
			switch {
			case top.object && top.n%2 == 1:
				b.WriteByte(':') // key -> value
			case top.n > 0:
				b.WriteByte(',') // previous element or member -> next
			}
			top.n++
		}
		switch v := tok.(type) {
		case json.Delim: // '{' or '['
			b.WriteByte(byte(v))
			stack = append(stack, frame{object: v == '{'})
		case string:
			r, failed := redact(v)
			if failed {
				failures++
			}
			enc, err := json.Marshal(r)
			if err != nil {
				return nil, 0, err
			}
			b.Write(enc)
		case json.Number:
			b.WriteString(v.String())
		case bool:
			b.WriteString(strconv.FormatBool(v))
		case nil:
			b.WriteString("null")
		default:
			return nil, 0, fmt.Errorf("unexpected JSON token %T", tok)
		}
	}
	return b.Bytes(), failures, nil
}
