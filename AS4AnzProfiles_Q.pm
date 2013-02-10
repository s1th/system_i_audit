package AS4AnzProfiles_Q;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.Q";

#================
# Local Variables
#================
my $purpose;     #ppc
my $procedure;   # |
my $domain;      # |
my $reference;   # v

#========================
# Analyze Q user profiles
#========================
sub analyze
{
  #add w/p
  AS4XL::add_sheet($sheet_name);

  #add title and column headings
  AS4XL::add_header("Non-IBM Q's","ID","Name");

  #add ppc to audit program
  $purpose   = "To ensure that all Q user profiles are default system profiles shipped with IBM " . 
               "or were created by iSeries administrators.  The risk involved here is that if an " . 
               "attacker gains privileged access to the system, they could create an account " .
               "to use that begins with a Q and looks like an IBM supplied user account...in order to " . 
               "fool the iSeries administrator.  An account named YOURMOM has a much higher likelihood " . 
               "of being noticed than an account named QSRVAGENT.";

  $procedure = "Run: audusrprf or dspusrprf.Next, execute this query on outfile:\n\nselect trim(upuprf),\n" .
               "trim(uptext),\nfrom [OUTFILE]\nwhere substr(upuprf,1,1) = 'Q'\nand upuprf not in\n" .
               "([LIST OF DEFAULT IBM SUPPLIED USER PROFILE])\n" .
               "order by upuprf\n\nThe output of this query will be all user profiles that begin with a Q " .
               "and are not issued by IBM. Note that this list of default profiles is as of V5R3, so it can " . 
               "change (and most likely will) with a newer release.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id ( sort keys %AS4Data::usrprf )
  {
    if (substr($id,0,1) eq "Q")
    {
      unless ( $AS4Conf::conf{$main::ip}->{QIBM}->{$id} )
      {
        #Q exception
        AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name});
      }
    }
  }

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;

