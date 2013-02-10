package AS4AnzProfiles_Terms;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.Terms";

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
  AS4XL::add_header("Terminated Users","ID","Name","PassNone","Status","Term(s) Matched Against");

  #add ppc to audit program
  $purpose   = "To ensure that no terminated still has an active user profile on the AS400.  All terminated users " .
               "should ideally have their system profile deleted...however, if there is some unique circumstance, " .
               "and the ID can't be deleled it should at a minimum be disabled.";

  $procedure = "Run: audusrprf or dspusrprf.  Then execute this query on outfile:\n\n" .
               "select trim(upuprf),\n" .
               "trim(uptext),\n" .
               "trim(uppwon)\n" .
               "trim(upstat)\n" .
               "from [OUTFILE]\n\n" .
               "The output of this query will be all user profiles.  Compare this list with a recent list " .
               "of terminated users provided by HR.  Note any exceptions.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  #get terminations
  MiscFunc::get_terminations($AS4Conf::conf{$main::ip}->{TERMS}->{value});

  my $rv;   #return value
  my $rstr; #return string
  my $type; #type of match
  my $name; #user profile name - uptext
  for my $id ( sort keys %AS4Data::usrprf )
  {
    if ($AS4Data::usrprf{$id}->{name})
    {
      $name = $AS4Data::usrprf{$id}->{name};
    }
    else
    {
      $name = "";
    }

    $rv = MiscFunc::is_term($name,"AS4");
    print "called is_term --> $name\n";
    if ($rv)
    {
      #user id is a terminated user
      AS4XL::write_row($id,$name,$AS4Data::usrprf{$id}->{pass_none},$AS4Data::usrprf{$id}->{status},$rv);
    }
  } #end $id for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;