//go:build ignore

// Writes test/golden-go.json: messages signed by entmoot's own Go code for cases the e2e
// node does not produce. Run from an entmoot checkout's src/ directory:
//
//	go run /path/to/entmoot-lite/test/gen/golden-go.go > /path/to/entmoot-lite/test/golden-go.json
//
//   - legacy: a version-0 message (no domain prefix, Pilot node id author, no member id)
//   - surrogate: a v2 message decoded from JSON whose topic holds a lone UTF-16 surrogate
//     escape; Go's decoder turns it into U+FFFD before canonical encoding.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"os"

	"entmoot/pkg/entmoot"
	"entmoot/pkg/entmoot/canonical"
)

func sign(m entmoot.Message, priv ed25519.PrivateKey) entmoot.Message {
	b, err := canonical.MessageSigningBytes(m)
	if err != nil {
		panic(err)
	}
	m.ID = entmoot.MessageID(sha256.Sum256(b))
	m.Signature = ed25519.Sign(priv, b)
	return m
}

func main() {
	priv := ed25519.NewKeyFromSeed(make([]byte, 32))
	pub := priv.Public().(ed25519.PublicKey)
	var group entmoot.GroupID
	group[0] = 1

	legacy := sign(entmoot.Message{
		GroupID:   group,
		Author:    entmoot.NodeInfo{PilotNodeID: 7, EntmootPubKey: pub},
		Timestamp: 1700000000000,
		Topics:    []string{"legacy/chat"},
		Content:   []byte("from the pilot era"),
	}, priv)

	member := entmoot.MemberID(sha256.Sum256(append([]byte("entmoot/member/v2\x00"), pub...)))
	var head entmoot.RosterEntryID
	head[0] = 2
	base := entmoot.Message{
		Version:    2,
		GroupID:    group,
		Author:     entmoot.NodeInfo{EntmootPubKey: pub, MemberID: &member},
		Timestamp:  1700000000001,
		Topics:     []string{"x"},
		RosterHead: &head,
	}
	raw, _ := json.Marshal(base)
	// replace the topic with a lone high surrogate escape, as a JS JSON.stringify would send it
	raw = []byte(replaceTopic(string(raw)))
	var decoded entmoot.Message
	if err := json.Unmarshal(raw, &decoded); err != nil {
		panic(err)
	}
	surrogate := sign(decoded, priv)

	out := map[string]any{"legacy": legacy, "surrogate": surrogate, "surrogate_sent_topic": `a\ud800b`}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}

func replaceTopic(s string) string {
	const from = `"topics":["x"]`
	const to = `"topics":["a\ud800b"]`
	for i := 0; i+len(from) <= len(s); i++ {
		if s[i:i+len(from)] == from {
			return s[:i] + to + s[i+len(from):]
		}
	}
	panic("topic not found")
}
