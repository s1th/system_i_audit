package AS4AnzProfiles_DftPwd;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.DftPwd";

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
  AS4XL::add_header("Default Passwords","ID","Name","PassNone","Status");

  #add ppc to audit program
  $purpose   = "To ensure that no user profiles have a password the same as their id name.";

  $procedure = "Run: audusrprf or dspusrprf. Next run: audanzdft or anzdftpwd action(*NONE). " .
               "Note, it is very important to specify the 'action(*NONE)' parameter...otherwise " .
               "all profiles found will automatically be disabled.  The output of this command " .
               "will go to the file qusrsys/qasecpwd.  Next, execute this query:\n\n" . 
               "select trim(dfusrp),\n" . 
               "trim(dfptxt),\n" . 
               "trim(upstat),\n" . 
               "trim(uppwex)\n" . 
               "from qusrsys/qasecpwd,[USRPRF OUTFILE]\n" . 
               "where dfusrp = upuprf\n" . 
               "order by dfusrp\n\n" . 
               "The output of this query will be all user profiles with a password the same as their " . 
               "id, their status and whether or not their password is set to expired.";


  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id ( sort keys %AS4Data::dftpwd )
  {
    AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{pass_none},$AS4Data::usrprf{$id}->{status});
  } #end $id for()
  
  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;