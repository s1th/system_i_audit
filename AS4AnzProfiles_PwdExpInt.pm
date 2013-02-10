package AS4AnzProfiles_PwdExpInt;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.PwdExpInt";

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
  AS4XL::add_header("Password Expiration Interval","ID","Name","PassNone","Status","PwdExpInt");

  #add ppc to audit program
  $purpose   = "To ensure that all user profiles have a password expiration interval set to either " . 
               "0 (means use system value - which script checks) or 90.  A setting of -1 indicates " . 
               "*NOMAX (meaning password never expires).";

  $procedure = "Run: audusrprf or dspusrprf. Next, execute this query on outfile:\n\n" .
               "select trim(upuprf),\n" .
               "trim(uptext),\n" . 
               "trim(uppwei),\n" . 
               "trim(uppwon)\n" . 
               "from [OUTFILE]\n" . 
               "where uppwon = '*NO'\n" . 
               "and uppwei != 90\n" . 
               "order by upuprf\n\n" . 
               "The output of this query will be all user profiles that are able to sign " . 
               "onto the system and who have a password expiration interval setting not " . 
               "equal to 90 or set to *SYSVAL.  The QPWDEXPITV system value setting can then " . 
               "be checked for appropriateness (the script does this).";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  my $no = "*NO";
  my $pwdexi = "QPWDEXPITV";
  for my $id ( sort keys %AS4Data::usrprf )
  {
    if ($AS4Data::usrprf{$id}->{pass_exp_int} != 90)
    {
      #see if setting is *SYSVAL and check the QPWDEXPINTV sys val if it is
      if ($AS4Data::usrprf{$id}->{pass_exp_int} == 0)
      {
        #check system value
        unless ($AS4Data::sv{$pwdexi}->{current} == 90)
        {
          #write exception
          AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{pass_none},$AS4Data::usrprf{$id}->{status},$AS4Data::usrprf{$id}->{pass_exp_int});
        }
      }
      else
      {
        #exception
        AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{pass_none},$AS4Data::usrprf{$id}->{status},$AS4Data::usrprf{$id}->{pass_exp_int});
      } #end sv check if()
    } #end 90 if()
  } #end $id for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;