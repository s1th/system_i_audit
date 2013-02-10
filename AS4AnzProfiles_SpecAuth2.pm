package AS4AnzProfiles_SpecAuth2;
require Exporter;

use strict;
use warnings;
use MiscFunc;
use Date::Calc qw(:all);

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.SpecAuthCat";

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
  AS4XL::add_header("Users Categorized by Special Authorities","SpecialAuthority","ID","Name","JobTitle","AS400Status");


  #add ppc to audit program
  $purpose   = "To ensure that special authorities given to each user profile are appropriate.  This PPC looks " .
               "at the data categorized by special authority as opposed to user profile.  It is sometimes easier " .
               "to find errors looking at the data categorized this way.";

  $procedure = "This analysis is not easily done manually and is best left to scripting.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $spa (sort keys %AS4Data::spauth)
  {
    for my $id ( sort keys %{ $AS4Data::spauth{$spa} } )
    {
      #write
      AS4XL::write_row($spa,$id,$AS4Data::usrprf{$id}->{name},$AS4Data::hr{$id}->{job_title},$AS4Data::usrprf{$id}->{status});
    }
  } #end $spa for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;