package query_context

import (
	"testing"

	"github.com/miekg/dns"
)

func TestCopyToClearsDestinationResponseState(t *testing.T) {
	sourceQuery := new(dns.Msg)
	sourceQuery.SetQuestion("source.example.", dns.TypeA)
	source := NewContext(sourceQuery)
	destinationQuery := new(dns.Msg)
	destinationQuery.SetQuestion("destination.example.", dns.TypeAAAA)
	destinationQuery.SetEdns0(1232, true)
	destination := NewContext(destinationQuery)
	response := new(dns.Msg)
	response.SetReply(destinationQuery)
	response.SetEdns0(1232, true)
	destination.SetResponse(response)
	destination.StoreValue(RegKey(), "old value")
	destination.SetMark(7)

	if got := source.CopyTo(destination); got != destination {
		t.Fatal("CopyTo did not return destination")
	}
	if destination.R() != nil || destination.RespOpt() != nil || destination.UpstreamOpt() != nil {
		t.Fatal("CopyTo retained the destination's old response or OPT state")
	}
	if destination.ClientOpt() != nil || destination.HasMark(7) || len(destination.kv) != 0 {
		t.Fatal("CopyTo retained the destination's old query state")
	}
	if destination.Id() != source.Id() || destination.QQuestion() != source.QQuestion() {
		t.Fatal("CopyTo did not copy query identity")
	}
}

func TestCopyToCopiesResponseAndMutableOptIndependently(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("copy.example.", dns.TypeA)
	q.SetEdns0(1232, true)
	source := NewContext(q)
	r := new(dns.Msg)
	r.SetReply(q)
	rr, err := dns.NewRR("copy.example. 300 IN A 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	r.Answer = []dns.RR{rr}
	r.SetEdns0(1232, false)
	source.SetResponse(r)
	destination := source.CopyTo(new(Context))
	destination.R().Answer[0].Header().Ttl = 9
	destination.RespOpt().SetUDPSize(512)
	if source.R().Answer[0].Header().Ttl != 300 || source.RespOpt().UDPSize() == 512 {
		t.Fatal("CopyTo shares mutable response or OPT state")
	}
	if destination.ClientOpt() != source.ClientOpt() || destination.UpstreamOpt() != source.UpstreamOpt() {
		t.Fatal("read-only OPT state should retain its existing sharing contract")
	}
}
