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

  end

end
