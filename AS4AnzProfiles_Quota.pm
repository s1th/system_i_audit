package AS4AnzProfiles_Quota;
require Exporter;

use strict;
use warnings;

use KMGconv;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.Quota";

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
  AS4XL::add_header("Disk Quotas","ID","Name","Status","MaxStorage","UsedStorage");

  #add ppc to audit program
  $purpose   = "To ensure that quota mangement is utilized. Quota management means " .
               "limiting users of the system to only a given amount of storage space.";

  $procedure = "Run: audusrprf or dspusrprf. Next, execute this query on outfile:\n\n" . 
               "select trim(upuprf),\n" . 
               "trim(uptext),\n" . 
               "trim(upstat),\n" . 
               "trim(upmxst),\n" . 
               "trim(upmxsu)\n" . 
               "from [OUTFILE]\n" . 
               "order by upuprf\n\n" . 
               "The output of this query will be all user profiles with their name, status, " . 
               "storage restrictions and storage used.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  my $kb = "kB";
  my $gb = "GB";

  for my $id (sort keys %AS4Data::usrprf)
  {
    my $maxst  = $AS4Data::usrprf{$id}->{max_storage};
    my $usedst = $AS4Data::usrprf{$id}->{storage_used};

    #get outstring for max
    if ($maxst eq "-1" ) 
    {
      $maxst = "NO LIMIT";
    }
    else 
    {
      $maxst = int(KMGconv::convert($kb,$gb,$maxst));
      $maxst .= " GB";
    }

    #get outstring for used
    unless ($usedst eq "0") 
    {
      $usedst = int(KMGconv::convert($kb,$gb,$usedst));
    }
    $usedst .= " GB";

    AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{status},$maxst,$usedst);

  } #end $id for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;