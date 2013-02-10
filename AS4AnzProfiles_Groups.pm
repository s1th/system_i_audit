package AS4AnzProfiles_Groups;
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
our $sheet_name = "GRP.Groups";

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
  AS4XL::add_header("Group/Supplemental Groups","ID","Name","GroupProf","SupGroups","PassNone","Status");


  #add ppc to audit program
  $purpose   = "To ensure that all user profiles have been assigned appropriate group profiles " . 
               "(whether granted through the group profile field or the supplemental groups field).";

  $procedure = "Run: audusrprf or dspusrprf Next execute this query:\n\n" . 
               "select trim(upuprf),\n" . 
               "trim(uptext),\n" . 
               "trim(upgrpf),\n" .
               "trim(upsupg),\n" .
               "trim(uppwon),\n" .
               "trim(upstat),\n" .
               "from [OUTFILE]\n" .
               "order by upuprf\n\n" .
               "The output of this query will be all user profiles and their associated group profiles. " .
               "This output should be reviewed for appropriateness (script highlights some potential " .
               "issues).";

  $domain    = "Groups";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $id (sort keys %AS4Data::usrprf)
  {
    #get a print string of supplemental groups
    my $sg;
    my $exstr;
    
    unless ( $AS4Data::usrprf{$id}->{sup_group} )
    {
      print "$id profile in AS4AnzProfiles_Groups.pm --> No supplemental groups found, is this true?\n";
      print "Skipping this profile for now...do some research!\n";
      next;
    }

    my $size = @{ $AS4Data::usrprf{$id}->{sup_group} };
    for my $grp (sort @{ $AS4Data::usrprf{$id}->{sup_group} })
    {
      if ($size == 1)
      {
        $sg .= "$grp";
      }
      else
      {
        $sg .= "$grp\n";
      }
    }

    #create string for exception match analysis
    $exstr = $sg . " " . $AS4Data::usrprf{$id}->{group};

    #write
    AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{group},$sg,$AS4Data::usrprf{$id}->{pass_none},$AS4Data::usrprf{$id}->{status});

    #exception analysis
    if (($exstr =~ /GRPIS/) && ($exstr =~ /JDE/) && ($exstr =~ /GRPODBC/))
    {
      AS4XL::highlight(AS4XL::get_row(),'red');
    }
    elsif ( ($exstr =~ /GRPIS/) && ($exstr =~ /JDE/) )
    {
      #IS and JDE
      AS4XL::highlight(AS4XL::get_row(),'yellow');
    }
    elsif ($exstr =~ /GRPODBC/)
    {
      #ODBC
      AS4XL::highlight(AS4XL::get_row(),'blue');
    }
    elsif ($exstr =~ /Q.*/)
    {
      #IBM supplied group profile
      AS4XL::highlight(AS4XL::get_row(),'green');
    }
  } #end $id for()
  
  #enter legend
  AS4XL::add_legend("yellow|GRPIS and JDE groups",
                    "red|GRPIS, JDE and GRPODBC groups",
                    "blue|GRPODBC group",
                    "green|Qxxx IBM group");

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;