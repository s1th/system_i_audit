package AS4AnzProfiles_AttnKey;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.AttnKey";

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
  AS4XL::add_header("Attn Key Programs","ID","Name","Status","PassNone","AttnKeyProgram","AttnKeyLibrary");

  #add ppc to audit program
  $purpose   = "To ensure that user profile attention key programs are appropriate.  The attention " . 
               "key program is called when a user presses the F1 key.  Thus this should be the IBM help " . 
               "assistance program (*ASSIST - QEZMAIN).  Any other value should be confirmed as appropriate.";

  $procedure = "Run: audusrprf or dspusrprf. Next, execute this query on outfile:\n\n" . 
               "select trim(upuprf),\n" . 
               "trim(uptext),\n" . 
               "trim(upstat),\n" . 
               "trim(uppwon),\n" . 
               "trim(upatpg),\n" . 
               "trim(upatpl)\n" . 
               "from [OUTFILE]\n" . 
               "where trim(upatpg) != '*NONE'\n" . 
               "order by upuprf\n\n" . 
               "The output of this query will be all user profiles with their name, status, " . 
               "sign-on ability and the attention key program and library.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  my $sv = "QATNPGM";
  my $sv_setting = "QEZMAIN   QSYS";
  for my $id ( sort keys %AS4Data::usrprf )
  {
    my $attnpg  = $AS4Data::usrprf{$id}->{attn_prog};
    if ($attnpg eq "*SYSVAL")
    {
      #specified at the system value level
      if ( ($AS4Data::sv{$sv}->{current} ne $sv_setting ) && ( $AS4Data::sv{$sv}->{current} ne "*NONE") )
      {
        #system value is something other than the assist program (or nothing)
        $attnpg = $AS4Data::sv{$sv}->{current};
      }
      else 
      {
        next;
      }
    }
    elsif ( ($attnpg eq $sv_setting) || ($attnpg eq "*NONE") )
    {
      #set appropriately at user profile level
      next;
    }

    AS4XL::write_row($id,$AS4Data::usrprf{$id}->{name},$AS4Data::usrprf{$id}->{status},$AS4Data::usrprf{$id}->{pass_none},$attnpg,$AS4Data::usrprf{$id}->{attn_prog_lib});

  } #end $id for()
  
  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;