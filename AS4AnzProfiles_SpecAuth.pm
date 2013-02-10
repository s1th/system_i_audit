package AS4AnzProfiles_SpecAuth;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name);

#=================
# Global Variables
#=================
our $sheet_name = "UP.SpecAuth";

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
  AS4XL::add_header("Special Authorities","ID","Name","PassNone","Status","UserClass","*ALLOBJ","*SECADM","*JOBCTL","*SPLCTL","*SAVSYS","*SERVICE","*AUDIT","*IOSYSCFG");

  #add ppc to audit program
  $purpose   = "To ensure that all special authorities granted to user profiles are appropriate. " .
               "Special authorities can be granted through a profile's user class or through the " .
               "special authorities field.";

  $procedure = "Run: audusrprf or dspusrprf. Next,execute this query:\n\nselect trim(upuprf),\n" .
               "trim(uptext),\ntrim(uppwon),\ntrim(upstat),\ntrim(upuscl),\ntrim(upspau)\n" .
               "from [OUTFILE]\norder by upuprf\n\nThe output of this query is all user profiles " .
               "and the special authorities granted to them, either through their user class or " .
               "special authorities. Additionally it shows whether the profile can sign-on ,its " .
               "user class, and its status.  This report also provides exception analysis.  Profiles " .
               "highlighted in green represent those profiles that have *ALLOBJ authority. Profiles " .
               "highlighted in yellow are those that are a mismatch between the authorities granted " .
               "through the user class and the special authorities granted to them. Those profiles " .
               "that are both a mismatch and have *ALLOBJ authority are highlighted in red.  The as4sec.pl " .
               "script does the exception analysis and enumeration of all special authorities (whether " .
               "given through user class or special authorities) behind the scenes.";

  $domain    = "User Profiles";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  my $allobj   = "ALLOBJ";     #special authority of *ALLOBJ
  my $secadm   = "SECADM";     #special authority of *SECADM
  my $jobctl   = "JOBCTL";     #special authority of *JOBCTL
  my $splctl   = "SPLCTL";     #special authority of *SPLCTL
  my $savsys   = "SAVSYS";     #special authority of *SAVSYS
  my $service  = "SERVICE";    #special authority of *SERVICE
  my $audit    = "AUDIT";      #special authority of *AUDIT
  my $iosyscfg = "IOSYSCFG";   #special authority of *IOSYSCFG
  my %specauth;                #hash to store special authorities analysis
  my %mismatch;                #hash for mismatch analysis between user class and special authorities

  for my $id (sort keys %AS4Data::usrprf)
  {
    my $userclass;
    if ($AS4Data::usrprf{$id}->{user_class})
    {
      $userclass = $AS4Data::usrprf{$id}->{user_class};
    }
    else
    {
      $userclass = "NULL";
    }

    #analyze user class - users can have only one user class
    if ($userclass eq "*SECOFR")
    {
      #has all special authorities
      $specauth{$id}->{$allobj}   = "X";
      $specauth{$id}->{$secadm}   = "X";
      $specauth{$id}->{$jobctl}   = "X";
      $specauth{$id}->{$splctl}   = "X";
      $specauth{$id}->{$savsys}   = "X";
      $specauth{$id}->{$service}  = "X";
      $specauth{$id}->{$audit}    = "X";
      $specauth{$id}->{$iosyscfg} = "X";
    }
    elsif ($userclass eq "*SECADM")
    {
      $specauth{$id}->{$secadm} = "X";
    }
    elsif ($userclass eq "*SYSOPR")
    {
      $specauth{$id}->{$jobctl} = "X";
      $specauth{$id}->{$savsys} = "X";
    }
    elsif ($userclass eq "*PGMR")
    {
      #no special authorities granted
    }
    elsif ($userclass eq "*USER")
    {
      #no special authorities granted
    }
    else
    {
      unless ($userclass eq "NULL")
      {
        print "user class error in AS4AnzProfiles_SpecAuth::analyze(): $userclass unknown!\n";
      }
    }

    #analyze special authorities to see if more have been granted
    for my $spa ( @{ $AS4Data::usrprf{$id}->{spec_auth} } )
    {
      if ($spa eq "*ALLOBJ")
      {
        $specauth{$id}->{$allobj} = "X";
      }
      elsif ($spa eq "*SECADM")
      {
        $specauth{$id}->{$secadm} = "X";
      }
      elsif ($spa eq "*JOBCTL")
      {
        $specauth{$id}->{$jobctl} = "X";
      }
      elsif ($spa eq "*SPLCTL")
      {
        $specauth{$id}->{$splctl} = "X";
      }
      elsif ($spa eq "*SAVSYS")
      {
        $specauth{$id}->{$savsys} = "X";
      }
      elsif ($spa eq "*SERVICE")
      {
        $specauth{$id}->{$service} = "X";
      }
      elsif ($spa eq "*AUDIT")
      {
        $specauth{$id}->{$audit} = "X";
      }
      elsif ($spa eq "*IOSYSCFG")
      {
        $specauth{$id}->{$iosyscfg} = "X";
      }
      elsif ($spa eq "*NONE")
      {
        #no special authorities granted to user profile
      }
      else
      {
        unless ($userclass eq "NULL")
        {
          print "Error in AS4AnzProfiles_SpecAuth::analyze() at spa for(): $spa unknown!\n";
        }
      }
    } #end spa for()

    #mismatch analysis - a mismatch is when a user has additional special
    #authorities than are granted through their user class.
    if ($userclass eq "*SECOFR")
    {
      #has all special authorities, so no potential for mismatch
    }
    elsif ($userclass eq "*SECADM")
    {
      #mismatch = *ALLOBJ,*JOBCTL,*SPLCTL,*SAVSYS,*SERVICE,*AUDIT,*IOSYSCFG
      for my $spa ( @{ $AS4Data::usrprf{$id}->{spec_auth} } )
      {
        if (($spa eq "*ALLOBJ") || ($spa eq "*JOBCTL")  || ($spa eq "*SPLCTL") ||
            ($spa eq "*SAVSYS") || ($spa eq "*SERVICE") || ($spa eq "*AUDIT")  ||
            ($spa eq "*IOSYSCFG"))
        {
         $mismatch{$id} = 1;
        }
      } #end $spa for()
    }
    elsif ($userclass eq "*PGMR")
    {
      #mismatch = *ALLOBJ,*SECADM,*JOBCTL,*SPLCTL,*SAVSYS,*SERVICE,*AUDIT,*IOSYSCFG
      for my $spa ( @{ $AS4Data::usrprf{$id}->{spec_auth} } )
      {
        if (($spa eq "*ALLOBJ") || ($spa eq "*SECADM")  || ($spa eq "*JOBCTL") ||
            ($spa eq "*SPLCTL") || ($spa eq "*SAVSYS")  || ($spa eq "*SERVICE")||
            ($spa eq "*AUDIT")  || ($spa eq "*IOSYSCFG"))
        {
         $mismatch{$id} = 1;
        }
      } #end $spa for()
    }
    elsif ($userclass eq "*SYSOPR")
    {
      #mismatch = *ALLOBJ,*SECADM,*SPLCTL,*SERVICE,*AUDIT,*IOSYSCFG
      for my $spa ( @{ $AS4Data::usrprf{$id}->{spec_auth} } )
      {
        if (($spa eq "*ALLOBJ") || ($spa eq "*SECADM") || ($spa eq "*SPLCTL") ||
            ($spa eq "*SERVICE")|| ($spa eq "*AUDIT")  || ($spa eq "*IOSYSCFG"))
        {
         $mismatch{$id} = 1;
        }
      } #end $spa for()
    }
    elsif ($userclass eq "*USER")
    {
      #mismatch = *ALLOBJ,*SECADM,*JOBCTL,*SPLCTL,*SAVSYS,*SERVICE,*AUDIT,*IOSYSCFG
      for my $spa ( @{ $AS4Data::usrprf{$id}->{spec_auth} } )
      {
        if (($spa eq "*ALLOBJ") || ($spa eq "*SECADM")  || ($spa eq "*JOBCTL") ||
            ($spa eq "*SPLCTL") || ($spa eq "*SAVSYS")  || ($spa eq "*SERVICE")||
            ($spa eq "*AUDIT")  || ($spa eq "*IOSYSCFG"))
        {
         $mismatch{$id} = 1;
        }
      } #end $spa for()
    }
    else
    {
      unless ($userclass eq "NULL")
      {
        print "Error in special_authorities_ppc mismatch analysis - user class $userclass unknown!\n";
      }
    }
  } #end $id for()

  #output details
  for my $id (sort keys %specauth)
  {
    #user's info
    my $uname     = $AS4Data::usrprf{$id}->{name};
    my $upassnone = $AS4Data::usrprf{$id}->{pass_none};
    my $ustat     = $AS4Data::usrprf{$id}->{status};
    my $uclass    = $AS4Data::usrprf{$id}->{user_class};
    my $uallobj;
    my $usecadm;
    my $ujobctl;
    my $usplctl;
    my $usavsys;
    my $uservice;
    my $uaudit;
    my $uiosyscfg;

    #*ALLOBJ
    if ( exists $specauth{$id}->{$allobj} )
    {
      $uallobj = $specauth{$id}->{$allobj};
    }
    else
    {
      $uallobj = " ";
    }

    #*SECADM
    if ( exists $specauth{$id}->{$secadm} )
    {
      $usecadm = $specauth{$id}->{$secadm};
    }
    else
    {
      $usecadm = " ";
    }

    #*JOBCTL
    if ( exists $specauth{$id}->{$jobctl} )
    {
      $ujobctl = $specauth{$id}->{$jobctl};
    }
    else
    {
      $ujobctl = " ";
    }

    #*SPLCTL
    if ( exists $specauth{$id}->{$splctl} )
    {
      $usplctl = $specauth{$id}->{$splctl};
    }
    else
    {
      $usplctl = " ";
    }

    #*SAVSYS
    if ( exists $specauth{$id}->{$savsys} )
    {
      $usavsys = $specauth{$id}->{$savsys};
    }
    else
    {
      $usavsys = " ";
    }

    #*SERVICE
    if ( exists $specauth{$id}->{$service} )
    {
      $uservice = $specauth{$id}->{$service};
    }
    else
    {
      $uservice = " ";
    }

    #*AUDIT
    if ( exists $specauth{$id}->{$audit} )
    {
      $uaudit = $specauth{$id}->{$audit};
    }
    else
    {
      $uaudit = " ";
    }

    #*IOSYSCFG
    if ( exists $specauth{$id}->{$iosyscfg} )
    {
      $uiosyscfg = $specauth{$id}->{$iosyscfg};
    }
    else
    {
      $uiosyscfg = " ";
    }

    #write detail
    AS4XL::write_row($id,$uname,$upassnone,$ustat,$uclass,$uallobj,$usecadm,$ujobctl,$usplctl,$usavsys,$uservice,$uaudit,$uiosyscfg);

    #exception analysis
    #*ALLOBJ authority
    if ($uallobj eq "X")
    {
      AS4XL::highlight(AS4XL::get_row(),'green');
    }

    #mismatch
    if ( $mismatch{$id} )
    {
      AS4XL::highlight(AS4XL::get_row(),'yellow');
    }

    #*ALLOBJ and mismatch
    if ( ( $mismatch{$id} ) && ( $uallobj eq "X" ) )
    {
      AS4XL::highlight(AS4XL::get_row(),'red');
    }
  } #end $id for()


  #enter key
  AS4XL::add_legend("green|User has *ALLOBJ",
                    "yellow|User is a mismatch",
                    "red|Mismatch and *ALLOBJ");

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;