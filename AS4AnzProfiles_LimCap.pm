package AS4AnzProfiles_LimCap;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.LimCap";

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
  AS4XL::add_header("Limited Capabilities *NO","ID","Name","LimitedCap","PassNone","InitProg","CurLib","InitMenu","Status",
                    "GroupProf","SupGroups");

  #add ppc to audit program
  $purpose   = "To ensure users cannot alter their profiles, on a sign-in screen for example. " .
               "If a profile has Limited Capabilities of *NO and has access to a sign-in screen, " .
               "they can potentially escalate their priveleges by specifying their own initial " .
               "program and current library.  For example, an initial program of *NONE and a current " .
               "library of QSYS could be specified.  This gives the user access to a command line on " .
               "the iSeries and set their current library to QSYS. Object authority may still limit the " .
               "profile, however this access combined with the JDE group profile is very dangerous.";

  $procedure = "Run: audusrprf or dspusrprf. Next, execute this query on outfile:\n\n" . 
               "select trim(upuprf),\n" . 
               "trim(uptext),\n" . 
               "trim(upltcp),\n" . 
               "trim(upinpg),\n" .
               "trim(upcrlb),\n" . 
               "trim(upinmn),\n" . 
               "trim(upstat),\n" . 
               "trim(upgrpf),\n" . 
               "trim(upsupg)\n" . 
               "from [OUTFILE]\n" . 
               "where upltcp = '*NO'\n" . 
               "order by upuprf\n" . 
               "\n" . 
               "The output of this query will be all user profiles that have limited capabilities of *NO. " . 
               "Users who are a more significant risk are users who's initial program is J98INIT, has JDE " . 
               "as a group or supplemental group profile and has limited capabilities of *NO.  These users " . 
               "are users of production data who are supposed to be logged directly into the JDE environment..." . 
               "but could potentially alter their profiles to gain command line access to the iSeries.  " . 
               "From here these users would have sufficient object authority to do significant damage.  " . 
               "Because of this these users are highlighted in yellow.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  my $sgstr = "";
  for my $id ( sort keys %AS4Data::usrprf )
  {
    if ($AS4Data::usrprf{$id}->{limited_cap} eq "*NO")
    {
     $sgstr = "";

     for my $grp ( @{ $AS4Data::usrprf{$id}->{sup_group} } )
     {
       $sgstr .= "$grp\n";
     }

     AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{limited_cap},$AS4Data::usrprf{$id}->{pass_none},
                      $AS4Data::usrprf{$id}->{init_prog},$AS4Data::usrprf{$id}->{cur_lib},$AS4Data::usrprf{$id}->{init_menu},
                      $AS4Data::usrprf{$id}->{status},$AS4Data::usrprf{$id}->{group},$sgstr);

     #exception highlighting
     my $init_p;
     my $group;
     if ($AS4Data::usrprf{$id}->{init_prog})
     {
       $init_p = $AS4Data::usrprf{$id}->{init_prog};
     }
     else
     {
       $init_p = "";
     }

     if ($AD4Data::usrprf{$id}->{group})
     {
       $group = $AS4Data::usrprf{$id}->{group};
     }
     else
     {
       $group = "";
     }

     if ( ( $init_p =~ /.*J98INIT.*/g) || ( $group =~ /JDE/) || ($sgstr =~ /JDE/g) )
     {
       AS4XL::highlight(AS4XL::get_row(),'yellow')
     }
    }
  } #end $id for()

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;