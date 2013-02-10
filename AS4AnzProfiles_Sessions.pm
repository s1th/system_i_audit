package AS4AnzProfiles_Sessions;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.Sessions";

#================
# Local Variables
#================
my $purpose;     #ppc
my $procedure;   # |
my $domain;      # |
my $reference;   # v

#===============================
# Analyze user profile ownership
#===============================
sub analyze
{
  #add w/p
  AS4XL::add_sheet($sheet_name);

  #add title and column headings
  AS4XL::add_header("Limit Device Sessions","ID","Name","Status","LimDevSessions");

  #add ppc to audit program
  $purpose   = "To ensure that the number of sessions a user profile can have is appropriate. " . 
               "Only IT or a system profile should be able to have more than one device session. " . 
               "This helps prevent sharing user profiles.  Note that this can also be controlled " . 
               "by the QLMTDEVSSN system value.";

  $procedure = "Run: audusrprf or dspusrprf. Next, execute this query on outfile:\n\n" . 
               "select trim(upuprf),\n" . 
               "trim(uptext),\n" . 
               "trim(upstat),\n" . 
               "trim(upldvs)\n" . 
               "from [OUTFILE]\n" . 
               "order by upuprf\n\n" . 
               "The output of this query will be all user profiles with their name, status " . 
               "and limit device session setting.  If the values of upldvs is *SYSVAL then " . 
               "check the system value for the setting.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  my $qlmtdevssn = $AS4Data::sv{"QLMTDEVSSN"}->{current};
  for my $id ( sort keys %AS4Data::usrprf )
  {
    my $limdev = $AS4Data::usrprf{$id}->{lim_dev_sessions};
    if ($limdev eq "*SYSVAL")
    {
      if ($qlmtdevssn eq "0")
      {
        $limdev = "*NO";
      }
      else
      {
        $limdev = "*YES";
      }
    }

    #only output exceptions - not limited
    unless ($limdev eq "*YES") 
    {
      AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{status},$limdev);
    }
  } #end $id for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;