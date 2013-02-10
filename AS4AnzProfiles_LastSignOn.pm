package AS4AnzProfiles_LastSignOn;
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
our $sheet_name = "UP.LastSignOn";

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
  AS4XL::add_header("Last Sign-On > 90 Days","ID","Name","PassNone","Status","LastSignOn","DaysDormant");

  #add ppc to audit program
  $purpose   = "To ensure that all user profiles that have never signed-on or have not " .
               "signed-on for 90 days or more are appropriate.";

  $procedure = "Run: audusrprf or dspusrprf. Next, execute this query:\n\n" .
               "select trim(upuprf),\n" .
               "trim(uptext),\n" .
               "trim(uppwon),\n" .
               "trim(upstat),\n" .
               "trim(uppsod)\n" .
               "from [OUTFILE]\n" .
               "where uppwon = '*NO'\n" .
               "order by upuprf\n\n" .
               "The output of this query will be all user profiles that are able to sign " .
               "onto the system and the date of their last sign-on to the system.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id ( sort keys %AS4Data::usrprf )
  {
    my $lastsignon = $AS4Data::usrprf{$id}->{prev_sign_on};
    my $last_sign_on_prt = "";
    my $ninety_days_ago = MiscFunc::days_ago_90;
    my $date_in_days;
    my $creation_date_in_days;
    my $difference;
    my $difference_str;

    if ($lastsignon eq "")
    {
      #never signed on
      $date_in_days = -1;
      $last_sign_on_prt = "NEVER";

      #get difference between today and the creation date of the user profile
      my($month,$day,$year) = split /\//, $AS4Data::usrprf{$id}->{creation_date};
      if ($year eq "00")
      {
        #year 00 bombs it, so change it to 01 if it is encountered
        #it will still print as the correct date though
        $year = "01";
      }
      $creation_date_in_days = Date_to_Days($year,$month,$day);
      $difference = int($ninety_days_ago) - int($creation_date_in_days);
      $difference_str = "(created: $month/$day/$year)";
    }
    else
    {
      #last sign-on date is in the format: YYMMDD and 0 place
      #holders are utilized
      my $year  = substr($lastsignon,0,2);
      my $month = substr($lastsignon,2,2);
      my $day   = substr($lastsignon,4,2);
      $last_sign_on_prt = "$month/$day/$year";

      #see if this date is greater than 90 days ago
      if ($year eq "00")
      {
        #year 00 bombs it, so change it to 01 if it is encountered
        #it will still print as the correct date though
        $year = "01";
      }

      $date_in_days = Date_to_Days($year,$month,$day);
      $difference = int($ninety_days_ago) - int($date_in_days);
      $difference_str = "$difference";
    }

    if (int($date_in_days) < int($ninety_days_ago))
    {
      AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{pass_none},
                       $AS4Data::usrprf{$id}->{status},$last_sign_on_prt,$difference_str);
    }

  } #end $id for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;