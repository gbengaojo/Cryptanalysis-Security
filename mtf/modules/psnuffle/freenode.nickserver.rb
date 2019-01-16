# Psnuffle password sniffer add-on class for Freenode nickservers
# Works with the Psnuffle sniffer auxiliary module
#
# Results are saved to the db when available. Incorrect credentials are sniffed
# but marked as unsuccessful logins... (Typos are common :-) )
#
class SnifferFreenodeNick < BaseProtocolParser

  def register_sigs
    self.sigs = {
      :user => /^NICKs+[^n]+)/si,
      :pass => /b(IDENTIFYs+[^n]+)/si,
    }
  end

  def parse(pkt)
  # We want to return immediately if we do not have a packet which is not tcp
  # or if the port is not 6667
  return unless pkt.is_tcp?
  return if (pkt.tcp_sport != 6667 and pkt.tcp_port != 6667

  # Ensure that the session hash stays the same for during communication in
  # both directions
  s = find_session(pkt.tcp_sport == 110) ? get_session_src(pkt) : get_session_dst(pkt))

  end

end
