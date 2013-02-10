package AS4AnzProfiles_Generic;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.Generic";

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
  AS4XL::add_header("Generic User Profiles","ID","Name","PassNone","Status");

  #add ppc to audit program
  $purpose   = "To ensure that all generic or system profiles are appropriate.  A generice profile is defined " . 
               "as a profile that is not 3 characters in length OR is not 3 characters followed by 0-99 in length." . 
               "For example, jcc, jcc01, jcc99, xyz, or xyz23 would be valid.  This follows the corporate standard " .
               "naming convention for user profiles.  Note that all Q profiles are also excluded since they are " . 
               "checked in a separate PPC.";

  $procedure = "Run: audusrprf or dspusrprf.  Then execute this query on outfile:\n\n" .
               "select trim(upuprf),\n" . 
               "trim(uptext),\n" . 
               "trim(uppwon)\n" . 
               "from [OUTFILE]\n" . 
               "where uppwon = '*NO'\n" . 
               "and length(trim(upuprf) != 3\n" . 
               "order by upuprf\n\n" . 
               "The output of this query will be all system/generic profiles that are able to " . 
               "sign onto the system.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id ( sort keys %AS4Data::usrprf )
  {
    unless ( lc($id) =~ /^[a-z][a-z][a-z]$/ || lc($id) =~ /^[a-z][a-z][a-z][0-9][0-9]$/ || $AS4Conf::conf{$main::ip}->{QIBM}->{$id} )
    {
     #a generic profile
     AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{pass_none},$AS4Data::usrprf{$id}->{status});
    }
  } #end $id for()
  
  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;