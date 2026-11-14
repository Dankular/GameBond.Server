package l2gw

// stackCounters reports the gVisor stack's receive-side drop and error counters that are nonzero, so a
// segment that never reaches a flow can be traced to the layer that refused it.
func (g *Gateway) stackCounters() map[string]uint64 {
	s := g.stack.Stats()
	out := map[string]uint64{}
	add := func(k string, v uint64) {
		if v != 0 {
			out[k] = v
		}
	}
	add("ip_invalid_dst", s.IP.InvalidDestinationAddressesReceived.Value())
	add("ip_invalid_src", s.IP.InvalidSourceAddressesReceived.Value())
	add("ip_malformed", s.IP.MalformedPacketsReceived.Value())
	add("ip_frag_errors", s.IP.MalformedFragmentsReceived.Value())
	add("tcp_checksum", s.TCP.ChecksumErrors.Value())
	add("tcp_invalid_segments", s.TCP.InvalidSegmentsReceived.Value())
	add("tcp_listen_overflow_syn", s.TCP.ListenOverflowSynDrop.Value())
	add("tcp_retransmits", s.TCP.Retransmits.Value())
	add("tcp_resets_received", s.TCP.ResetsReceived.Value())
	add("udp_checksum", s.UDP.ChecksumErrors.Value())
	add("udp_malformed", s.UDP.MalformedPacketsReceived.Value())
	add("udp_no_port", s.UDP.UnknownPortErrors.Value())
	add("udp_rcvbuf_errors", s.UDP.ReceiveBufferErrors.Value())
	add("nic_rx_drops", s.DroppedPackets.Value())
	return out
}
