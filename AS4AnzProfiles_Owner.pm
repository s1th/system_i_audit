package AS4AnzProfiles_Owner;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.Owner";

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
  AS4XL::add_header("Owner NOT QSYS/QSECOFR","ID","Name","Owner","CreationDate");

  #add ppc to audit program
  $purpose   = "To ensure that all user profiles are owned by QSECOFR or QSYS. If a profile " .
               "is owned by a different profile there must be an administrative/business " .
               "purpose for it. The risk here is potential privilege escalation and an unreliable " .
               "audit trail.";

  $procedure = "Run: audobjd or dspobjd command with correct parameters. Next run the following query on outfile:\n\n" .
               "select trim(odobnm),\ntrim(odobtp),\ntrim(odobtx),\ntrim(odobow),\ntrim(odcdat)\nfrom audtlib/usrprf01\n" . 
               "where trim(odobow) not in ('QSECOFR')\norder by odobnm\n\nThe output of this query will be all user " . 
               "profiles that are owned by a user/group other than QSECOFR.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id ( sort keys %AS4Data::usrprf )
  {
    if ( $AS4Data::usrprf{$id}->{owner} ne "QSECOFR" && $AS4Data::usrprf{$id}->{owner} ne "QSYS" )
    {
      #owner does not equal QSECOFR, an exception
      AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{owner},$AS4Data::usrprf{$id}->{creation_date});
    }
  }

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;