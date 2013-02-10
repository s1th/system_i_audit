package AS4AnzProfiles_EmpStat;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.EmpStat";

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
  AS4XL::add_header("Employee Status Analysis","EmployeeStatus","ID","Name","JobTitle","AS400Status","LastLogon");

  #add ppc to audit program
  $purpose   = "To ensure that all AS400 accounts are " .
               "appropriate.  Basically only active employees should " .
               "have an enabled AS400 account.  These employees are indicated " .
               "by an 'A' status in the HRIS database.  Terminated " .
               "employees are indicated with a 'T'. These employees " .
               "should not have an AS400 account, or at a minimum it should " .
               "be disabled.  Employees on a leave of abscence are " .
               "indicated with a status of 'L'.  These AS400 accounts " .
               "should be disabled unless for some reason the employee " .
               "is performing some sort of business requirement remotely. " .
               "Employees that are released/laid off are indicated " .
               "with a status of 'R'.  These employees are basically " .
               "the same as a terminated employee and should not have " .
               "an AS400 account or at a minimum should have that account " .
               "in a disabled state.  The final status that a user " .
               "can have is one of 'UNKNOWN'.  This indicates that " .
               "the user has an AS400 account but does not show up in " .
               "the HRIS database.  All of these cases need to be researched " .
               "to determine why this account exists.";

  $procedure = "This analysis is too complex to do by hand (well you could " .
               "but it wouldn't be fun).  This is best handled by the script.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id ( sort keys %AS4Data::hr )
  {
    #skip Q user profiles - IBM supplied
    if (substr($id,0,1) eq "Q")
    {
      next;
    }

    my $stat = $AS4Data::hr{$id}->{status};
    unless ( $stat ) { $stat = "XXX"; }

    unless ( $stat eq "A" )
    {
      #last sign-on date is in the format: YYMMDD and 0 place
      #holders are utilized
      my $lastsignon = $AS4Data::usrprf{$id}->{prev_sign_on};
      my $year;
      my $month;
      my $day;
      my $last_sign_on_prt;

      if ($lastsignon)
      {
        $year  = substr($lastsignon,0,2);
        $month = substr($lastsignon,2,2);
        $day   = substr($lastsignon,4,2);
        $last_sign_on_prt = "$month/$day/$year";
      }
      else
      {
        $last_sign_on_prt = "Never";
      }

      AS4XL::write_row($AS4Data::hr{$id}->{status},$id,$AS4Data::hr{$id}->{full_name},
                       $AS4Data::hr{$id}->{job_title},$AS4Data::usrprf{$id}->{status},
                       $last_sign_on_prt);
    }
  } #end $id for()
  
  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;