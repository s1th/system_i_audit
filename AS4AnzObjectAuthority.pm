package AS4AnzObjectAuthority;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "OA.All";

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
  AS4XL::add_header("Object Authority Audit","Object","User/Group","Object Authority","Group","Owner","Primary Group","Library","Type",
                    "Obj Oper","Obj Mgmt","Obj Exec","Read","Add","Update","Delete","Execute","Obj Alter",
                    "Obj Ref","Aut List Mgmt");

  #add ppc to audit program
  $purpose   = "To ensure that the object authorities for key objects on the system are appropriate.  The list " .
               "of objects is varied and includes stock IBM supplied iSeries commands, custom admin commands, " .
               "key JD Edwards files, etc.  This list needs to be reviewed in more detail to determine if " .
               "the authorities are set appropriately.";

  $procedure = "The script performs this process.  This is not possible to replicate manually unless you have " .
               "a lot of time on your hands.  It basically involves running the audobjaut or dspobjaut command " .
               "for each object that you want to audit.  Best to let the script handle this.";

  $domain    = "Object Authority";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $obj ( sort keys %AS4Data::objaut )
  {
    for my $id ( sort keys %{ $AS4Data::objaut{$obj} } )
    {
      #write details
      AS4XL::write_row($obj,
                       $id,
                       $AS4Data::objaut{$obj}->{$id}->{obj_auth},
                       $AS4Data::objaut{$obj}->{$id}->{group},
                       $AS4Data::objaut{$obj}->{$id}->{obj_owner},
                       $AS4Data::objaut{$obj}->{$id}->{primary_grp},
                       $AS4Data::objaut{$obj}->{$id}->{lib},
                       $AS4Data::objaut{$obj}->{$id}->{obj_type},
                       $AS4Data::objaut{$obj}->{$id}->{op_auth},
                       $AS4Data::objaut{$obj}->{$id}->{mgt_auth},
                       $AS4Data::objaut{$obj}->{$id}->{exs_auth},
                       $AS4Data::objaut{$obj}->{$id}->{read_auth},
                       $AS4Data::objaut{$obj}->{$id}->{add_auth},
                       $AS4Data::objaut{$obj}->{$id}->{upd_auth},
                       $AS4Data::objaut{$obj}->{$id}->{del_auth},
                       $AS4Data::objaut{$obj}->{$id}->{exec_auth},
                       $AS4Data::objaut{$obj}->{$id}->{alt_auth},
                       $AS4Data::objaut{$obj}->{$id}->{ref_auth},
                       $AS4Data::objaut{$obj}->{$id}->{amgt_auth}
                       );

      #highlight any that don't have *PUBLIC --> *EXCLUDE
      if ($id eq "*PUBLIC")
      {
        unless ( $AS4Data::objaut{$obj}->{$id}->{obj_auth} eq "*EXCLUDE" )
        {
          AS4XL::highlight(AS4XL::get_row(),'yellow');
        }
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