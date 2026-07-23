package dnsrr

import (
	"testing"

	"github.com/OmarTariq612/goech"
	"golang.org/x/net/dns/dnsmessage"

	"github.com/netd-tud/echtool/pkg/ech"
)

// sampleList builds a small, valid ECHConfigList for use in HTTPS RR fixtures.
func sampleList(t *testing.T, publicName string, configID uint8) goech.ECHConfigList {
	t.Helper()
	list, err := ech.Grease(publicName, ech.WithConfigID(configID))
	if err != nil {
		t.Fatalf("Grease: %v", err)
	}
	return list
}

// httpsAnswer packs a DNS response message with a single HTTPS answer built
// from params, mirroring what a resolver would return.
func httpsAnswer(t *testing.T, target string, params []dnsmessage.SVCParam) []byte {
	t.Helper()
	name := dnsmessage.MustNewName("example.com.")
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{Response: true},
		Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}},
		Answers: []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET},
			Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{
				Priority: 1,
				Target:   dnsmessage.MustNewName(target),
				Params:   params,
			}},
		}},
	}
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	return packed
}

// echParamFromAnswer parses packed as LookupECH does and returns the ech
// SvcParam of its first HTTPS answer.
func echParamFromAnswer(t *testing.T, packed []byte) ([]byte, bool) {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(packed); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("SkipAllQuestions: %v", err)
	}
	if _, err := p.AnswerHeader(); err != nil {
		t.Fatalf("AnswerHeader: %v", err)
	}
	https, err := p.HTTPSResource()
	if err != nil {
		t.Fatalf("HTTPSResource: %v", err)
	}
	return https.GetParam(dnsmessage.SVCParamECH)
}

func TestEchParamRootTarget(t *testing.T) {
	list := sampleList(t, "provider.example", 9)
	echBytes, err := list.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	packed := httpsAnswer(t, ".", []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamECH, Value: echBytes}})
	got, ok := echParamFromAnswer(t, packed)
	if !ok {
		t.Fatal("did not find the ech SvcParam")
	}
	parsed, err := goech.UnmarshalECHConfigList(got)
	if err != nil {
		t.Fatalf("UnmarshalECHConfigList: %v", err)
	}
	if !parsed.Equal(list) {
		t.Error("parsed ECHConfigList differs from the one embedded in the answer")
	}
}

func TestEchParamSkipsTargetLabelsAndOtherParams(t *testing.T) {
	list := sampleList(t, "provider.example", 3)
	echBytes, _ := list.MarshalBinary()

	params := []dnsmessage.SVCParam{
		{Key: dnsmessage.SVCParamALPN, Value: []byte{0x02, 'h', '2'}},
		{Key: dnsmessage.SVCParamECH, Value: echBytes},
	}
	packed := httpsAnswer(t, "svc.example.", params)

	got, ok := echParamFromAnswer(t, packed)
	if !ok {
		t.Fatal("did not find the ech SvcParam past the alpn param")
	}
	if string(got) != string(echBytes) {
		t.Error("returned the wrong SvcParam value")
	}
}

func TestEchParamAbsent(t *testing.T) {
	params := []dnsmessage.SVCParam{{Key: dnsmessage.SVCParamALPN, Value: []byte{0x02, 'h', '2'}}}
	packed := httpsAnswer(t, "svc.example.", params)
	if _, ok := echParamFromAnswer(t, packed); ok {
		t.Error("should report absence when no ech SvcParam is present")
	}
}

func TestListEquality(t *testing.T) {
	a := sampleList(t, "provider.example", 1)
	same := goech.ECHConfigList{a[0]}
	if !a.Equal(same) {
		t.Error("Equal should report equal lists as matching")
	}

	other := sampleList(t, "provider.example", 2) // different config id
	if a.Equal(other) {
		t.Error("Equal should report differing lists as not matching")
	}
}
