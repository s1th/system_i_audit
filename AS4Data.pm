package AS4Data;
require Exporter;

use strict;
use warnings;
use Array::Compare;
use IAD::MiscFunc;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw(%sv %usrprf %grp %spauth %dftpwd %objaut %hr online_connect online_get_user_profile_data online_get_system_values
            online_disconnect offline_get_user_profile_data offline_get_system_values);

#=================
# Global Variables
#=================
our %sv;       #system values hash
our %usrprf;   #user profile data hash
our %grp;      #groups hash
our %spauth;   #special authorities hash
our %dftpwd;   #analysis of default passwords hash
our %objaut;   #object authority hash
our %hr;       #hr database information hash

#================
# Local Variables
#================
my @cs;        #system values current settings array
my @rs;        #system values recommended settings array
my $recset;    #system values recommended settings string

#=====================
# Connect to AS400 sub
#=====================
sub online_connect
{
  print "Connecting...","\n";
  $main::conn->Open("Provider=IBMDA400;Data Source=$main::ip;User Id=$main::id;Password=$main::pass");
  my $err = Win32::OLE->LastError();

  if ($err)
  {
    return (0,"There was an error connecting to " . $main::ip . " -->\n\n" . Win32::OLE->LastError() . "\n");
  }
  else
  {
    return 1;
  }
  print "Successful!\n";
}

#==================================
# Get user profile data from server
#==================================
sub online_get_user_profile_data
{
  #create users_info file
  my $command = $AS4Conf::conf{$main::ip}->{AS400}->{dspusrprf_command};
  unless ($command)
  {
    $command = $AS4Conf::conf{default}->{AS400}->{dspusrprf_command};
  }

  my $lib = $AS4Conf::conf{$main::ip}->{AS400}->{library};
  unless ($lib)
  {
    $lib = $AS4Conf::conf{default}->{AS400}->{library};
  }

  #run command
  $main::cmd->{ActiveConnection} = $main::conn;

  $main::cmd->{CommandText} = "{{$command}}";
  $main::cmd->Execute or return (0,"Error in AS4Data::online_get_user_profile_data -->\n***Cannot execute the | $command | command!***\n");

  #query data
  $main::cmd->{CommandText} = "select * from $lib.users_info order by upuprf";

  $main::rs = $main::cmd->Execute or return (0,"Error in AS4Data::online_get_user_profile_data -->\n***Cannot execute the | select * from $lib.users_info order by upuprf | command!***\n");

  #store the user profile data
  open USRPRF, ">$main::datad\\as4.user.profile.data.txt"
       or return (0,"Error in AS4Data::online_get_user_profile_data -->\n***Can't open the as4.user.profile.data.txt file: $!***\n");

  #dump data to log file
  while (! $main::rs->{EOF})
  {
    #store necessary data for ppc checks
    my $id = $main::rs->Fields("UPUPRF")->{Value};
    $usrprf{$id}->{name}         = $main::rs->Fields("UPTEXT")->{Value};
    $usrprf{$id}->{limited_cap}  = $main::rs->Fields("UPLTCP")->{Value};
    $usrprf{$id}->{init_prog}    = $main::rs->Fields("UPINPG")->{Value};
    $usrprf{$id}->{cur_lib}      = $main::rs->Fields("UPCRLB")->{Value};
    $usrprf{$id}->{init_menu}    = $main::rs->Fields("UPINMN")->{Value};
    $usrprf{$id}->{status}       = $main::rs->Fields("UPSTAT")->{Value};
    $usrprf{$id}->{group}        = $main::rs->Fields("UPGRPF")->{Value};

    #get an array of the user's supplemental groups
    my @sg = split(/\s+/,IAD::MiscFunc::trim($main::rs->Fields("UPSUPG")->{Value}));
    $usrprf{$id}->{sup_group}    = [ @sg ];

    $usrprf{$id}->{pass_none}    = $main::rs->Fields("UPPWON")->{Value};
    $usrprf{$id}->{pass_exp_int} = $main::rs->Fields("UPPWEI")->{Value};
    $usrprf{$id}->{user_class}   = $main::rs->Fields("UPUSCL")->{Value};

    #get an array of the user's special authorities
    my @sa = split(/\s+/,IAD::MiscFunc::trim($main::rs->Fields("UPSPAU")->{Value}));
    $usrprf{$id}->{spec_auth} = [ @sa ];

    $usrprf{$id}->{prev_sign_on}     = $main::rs->Fields("UPPSOD")->{Value};
    $usrprf{$id}->{pass_exp}         = $main::rs->Fields("UPPWEX")->{Value};
    $usrprf{$id}->{so_att_not_valid} = $main::rs->Fields("UPNVSA")->{Value};
    $usrprf{$id}->{lim_dev_sessions} = $main::rs->Fields("UPLDVS")->{Value};
    $usrprf{$id}->{max_storage}      = $main::rs->Fields("UPMXST")->{Value};
    $usrprf{$id}->{storage_used}     = $main::rs->Fields("UPMXSU")->{Value};
    $usrprf{$id}->{attn_prog}        = $main::rs->Fields("UPATPG")->{Value};
    $usrprf{$id}->{attn_prog_lib}    = $main::rs->Fields("UPATPL")->{Value};

    #store groups analysis
    $grp{$main::rs->Fields("UPGRPF")->{Value}}->{$id} = 1;
    for my $sgrp ( @sg )
    {
      $grp{$sgrp}->{$id} = 1;
    }

    #store special authorities analysis
    $spauth{$main::rs->Fields("UPUSCL")->{Value}}->{$id} = 1;
    for my $spa ( @sa )
    {
      $spauth{$spa}->{$id} = 1;
    }

    #log data
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPUPRF")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPTEXT")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPLTCP")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPINPG")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPINPL")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPCRLB")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPINMN")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPINML")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPSTAT")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPGRPF")->{Value}) . "|";
    print USRPRF "@sg" . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPPWON")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPPWEI")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPUSCL")->{Value}) . "|";
    print USRPRF "@sa" . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPLDVS")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPGRAU")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPATPG")->{Value}) . "|";
    print USRPRF IAD::MiscFunc::trim($main::rs->Fields("UPATPL")->{Value}) . "|";
    print USRPRF $main::rs->Fields("UPUPLK")->{Value} . "|";
    print USRPRF $main::rs->Fields("UPUPDM")->{Value} . "|";
    print USRPRF $main::rs->Fields("UPENPW")->{Value} . "|";
    print USRPRF $main::rs->Fields("UPENPH")->{Value} . "|";
    print USRPRF $main::rs->Fields("UPENLM")->{Value} . "|";
    print USRPRF $main::rs->Fields("UPLPWM")->{Value} . "\n";

    #next record
    $main::rs->MoveNext();
  }
  close USRPRF;

  return 1;
}

#==============================================
# Get user profile data offline, from text file
#==============================================
sub offline_get_user_profile_data
{
  open USRPRF, $main::ddir .  "\\as4.user.profile.data.txt"
       or return (0,"Error in AS4Data::offline_get_user_profile_data -->\n***Can't open the as4.user.profile.data.txt file in the $main::ddir directory: $!***\n");

  open LOG, ">" . $main::datad . "\\as4.user.profile.data.txt"
       or return (0,"Error in AS4Data::offline_get_user_profile_data -->\n***Can't open the as4.user.profile.data.txt LOG file in the $main::datad directory: $!***\n");

  while (<USRPRF>)
  {
    #print to log file
    print LOG "$_";

    chomp;
    my($updcen,$upddat,$updtim,$upsyst,$upuprf,$upuscl,$updsin,$uppwcc,$uppwcd,$uppwct,
       $uppwei,$uppwex,$uppwon,$uppsoc,$uppsod,$uppsot,$upnvsa,$upldvs,$upspau,$upmxst,
       $upmxsu,$upprlt,$upinpg,$upinpl,$upjbds,$upjbdl,$upownr,$upgrpf,$upgrau,$upgrpi,
       $upaccd,$upmgqu,$upmgql,$upotqu,$upotql,$uptext,$upspen,$upcrlb,$upinmn,$upinml,
       $upltcp,$updlvy,$upsvrt,$upprdv,$upatpg,$upatpl,$upusop,$upuplk,$upupdm,$upstat,
       $upkbdb,$upastl,$uplang,$upcntr,$upccsi,$upsrt,$upsrtl,$upobja,$upaudl,$upgaty,
       $upsupg,$upuid,$upgid,$upsetj,$upchid,$upenpw,$upenph,$upenlm,$uplpwm) = split /\|/, $_;

    #store necessary data for ppc checks
    $usrprf{$upuprf}->{name}         = $uptext;
    $usrprf{$upuprf}->{limited_cap}  = $upltcp;
    $usrprf{$upuprf}->{init_prog}    = $upinpg;
    $usrprf{$upuprf}->{cur_lib}      = $upcrlb;
    $usrprf{$upuprf}->{init_menu}    = $upinmn;
    $usrprf{$upuprf}->{status}       = $upstat;
    $usrprf{$upuprf}->{group}        = $upgrpf;

    #get an array of the user's supplemental groups
    my @sg = split(/\s+/,$upsupg);
    $usrprf{$upuprf}->{sup_group}    = [ @sg ];

    $usrprf{$upuprf}->{pass_none}    = $uppwon;
    $usrprf{$upuprf}->{pass_exp_int} = $uppwei;
    $usrprf{$upuprf}->{user_class}   = $upuscl;

    #get an array of the user's special authorities
    my @sa = split(/\s+/,$upspau);
    $usrprf{$upuprf}->{spec_auth} = [ @sa ];

    $usrprf{$upuprf}->{prev_sign_on}     = $uppsod;
    $usrprf{$upuprf}->{pass_exp}         = $uppwex;
    $usrprf{$upuprf}->{so_att_not_valid} = $upnvsa;
    $usrprf{$upuprf}->{lim_dev_sessions} = $upldvs;
    $usrprf{$upuprf}->{max_storage}      = $upmxst;
    $usrprf{$upuprf}->{storage_used}     = $upmxsu;
    $usrprf{$upuprf}->{attn_prog}        = $upatpg;
    $usrprf{$upuprf}->{attn_prog_lib}    = $upatpl;

    #store groups analysis
    $grp{$upgrpf}->{$upuprf} = 1;
    for my $sgrp ( @sg )
    {
      $grp{$sgrp}->{$upuprf} = 1;
    }

    #store special authorities analysis
    $spauth{$upuscl}->{$upuprf} = 1;
    for my $spa ( @sa )
    {
      $spauth{$spa}->{$upuprf} = 1;
    }

  }
  close USRPRF;
  close LOG;

  return 1;
}

#=========================
# Get System Values online
# (uses a java program)
#=========================
sub online_get_system_values
{
  #retrieve and create system values file
  my $return = system("java as4sysval $main::ip $main::id $main::pass $main::datad");
  unless ($return == 0)
  {
    return (0,"Error in AS4Data::online_get_system_values -->\n***Java program returned with an abnormal return number ($return)***\n");
  }

  #system values retrieve
  my $svfile = $main::datad . "\\as4.system.values.txt";

  open SV, "$svfile"
       or return(0,"Error in AS4Data::online_get_system_values -->\n***Can't open the System Values file $svfile: $!***\n");

  while (<SV>)
  {
    chomp;
    my($name,$curset,$desc) = split /\|/;

    #determine if we got a string or array of strings
    if (substr($curset,0,1) eq "[")
    {
      #current
      $curset =~ s/[[]//;
      $curset =~ s/[]]//;
      @cs = split (/\s+/,$curset);
      @cs = sort @cs;

      #recommended
      $recset = $AS4Conf::conf{$main::ip}->{SV}->{$name}->{value};
      $recset =~ s/[[]//;
      $recset =~ s/[]]//;
      @rs = split (/\s+/,$recset);
      @rs = sort @rs;

      #store information away for use in later PPCs
      $sv{$name}->{current} = [ @cs ];
      $sv{$name}->{recommended} = [ @rs ];
      $sv{$name}->{description} = $desc;
      $sv{$name}->{array} = 1;

      #compare arrays for exceptions
      my $comp = Array::Compare->new;
      $comp->Sep('|');
      $comp->WhiteSpace(0);
      $comp->Case(0);
      my $result = $comp->compare(\@cs, \@rs) || 0;

      if ($result == 0)
      {
        $sv{$name}->{exception} = 1;
      }
      else
      {
        $sv{$name}->{exception} = 0;
      }
    }
    else
    {
      #just a normal string
      #clean up whitespace and leading zeros
      $curset =~ s/^\s+//;
      $curset =~ s/\s+$//;
      unless (length($curset) == 1) { $curset =~ s/^0+// };

      $recset = $AS4Conf::conf{$main::ip}->{SV}->{$name}->{value};
      $recset =~ s/^\s+//;
      $recset =~ s/\s+$//;
      unless (length($recset) == 1) { $recset =~ s/^0+// };

      #save
      $sv{$name}->{current} = $curset;
      $sv{$name}->{recommended} = $recset;
      $sv{$name}->{description} = $desc;
      $sv{$name}->{array} = 0;
      if ($curset eq $recset)
      {
        $sv{$name}->{exception} = 0;
      }
      else
      {
        $sv{$name}->{exception} = 1;
      }
    } #end [ if()
  } #end while()

  return 1;
}

#==========================
# Get System Values offline
#==========================
sub offline_get_system_values
{
  #system values retrieve
  my $svfile = $main::ddir . "\\as4.system.values.txt";
  open SV, "$svfile"
       or return (0,"Fatal error in AS4Data::offline_get_system_values --> \n\n***Error opening system values file: $!***\n");
  open LOG, ">" . $main::datad . "\\as4.system.values.txt"
       or return (0,"Fatal error in AS4Data::offline_get_system_values --> \n\n***Error opening LOG file for system values file: $!***\n");
  while (<SV>)
  {
    #copy to log file
    print LOG "$_";

    chomp;
    my($name,$curset,$desc) = split /\|/;

    #determine if we got a string or array of strings
    if (substr($curset,0,1) eq "[")
    {
      #current
      $curset =~ s/[[]//;
      $curset =~ s/[]]//;
      @cs = split (/\s+/,$curset);
      @cs = sort @cs;
      @rs = @AS4Conf::conf{$main::ip}->{SV}->{$name}->{value};

      #recommended
      $recset = $AS4Conf::conf{$main::ip}->{SV}->{$name}->{value};
      $recset =~ s/[[]//;
      $recset =~ s/[]]//;
      @rs = split (/\s+/,$recset);
      @rs = sort @rs;

      #store information away for use in later PPCs
      $sv{$name}->{current} = [ @cs ];
      $sv{$name}->{recommended} = [ @rs ];
      $sv{$name}->{description} = $desc;
      $sv{$name}->{array} = 1;

      #compare arrays for exceptions
      my $comp = Array::Compare->new;
      $comp->Sep('|');
      $comp->WhiteSpace(0);
      $comp->Case(0);
      my $result = $comp->compare(\@cs, \@rs) || 0;

      if ($result == 0)
      {
        $sv{$name}->{exception} = 1;
      }
      else
      {
        $sv{$name}->{exception} = 0;
      }
    }
    else
    {
      #just a normal string
      #clean up whitespace and leading zeros
      $curset =~ s/^\s+//;
      $curset =~ s/\s+$//;
      unless (length($curset) == 1) { $curset =~ s/^0+// };
      $recset = $AS4Conf::conf{$main::ip}->{SV}->{$name}->{value};
      $recset =~ s/^\s+//;
      $recset =~ s/\s+$//;
      unless (length($recset) == 1) { $recset =~ s/^0+// };

      #save
      $sv{$name}->{current} = $curset;
      $sv{$name}->{recommended} = $recset;
      $sv{$name}->{description} = $desc;
      $sv{$name}->{array} = 0;
      if ($curset eq $recset)
      {
        $sv{$name}->{exception} = 0;
      }
      else
      {
        $sv{$name}->{exception} = 1;
      }
    } #end [ if()
  } #end while()
  close SV;
  close LOG;

  return 1;
}

#=====================================
# Get usrprf object information online
#=====================================
sub online_get_usrprf_obj_data
{
  #create users_info file
  my $command = $AS4Conf::conf{$main::ip}->{AS400}->{dspobjd_command};
  unless ($command)
  {
    $command = $AS4Conf::conf{default}->{AS400}->{dspobjd_command};
  }

  my $lib = $AS4Conf::conf{$main::ip}->{AS400}->{library};
  unless ($lib)
  {
    $lib = $AS4Conf::conf{default}->{AS400}->{library};
  }

  #set active connection
  $main::cmd->{ActiveConnection} = $main::conn;

  $main::cmd->{CommandText} = "{{$command}}";
  $main::cmd->Execute or return (0,"Error in AS4Data::online_get_usrprf_obj_data -->\n***Cannot execute the | $command | command!***\n");

  #query data
  $main::cmd->{CommandText} = "select odobnm,odobow,odcdat from $lib.usrprf01 order by odobnm";

  $main::rs = $main::cmd->Execute or return (0,"Error in AS4Data::online_get_usrprf_obj_data -->\n***Cannot execute the | select * from $lib.usrprf01 order by odobnm | command!***\n");

  #store the user profile data
  open USRPRF, ">$main::datad\\as4.usrprf.obj.data.txt"
       or return (0,"Error in AS4Data::online_get_usrprf_obj_data -->\n***Can't open the as4.usrprf.obj.data.txt file: $!***\n");

  my $cdate;
  my $mon="";
  my $day="";
  my $yr="";
  my $date="";
  my $id;
  my $owner;
  while (! $main::rs->{EOF})
  {
    $id = $main::rs->Fields("ODOBNM")->{Value};
    $owner =  $main::rs->Fields("ODOBOW")->{Value};
    $cdate = $main::rs->Fields("ODCDAT")->{Value};

    #correct date format
    if ( $usrprf{$id} )
    {
      #exists - get date in good format
      if (length($cdate) == 6)
      {
       $mon = substr($cdate,0,2);
       $day = substr($cdate,2,2);
       $yr  = substr($cdate,4,2);
       $date = "$mon/$day/$yr";
      }
      elsif (length($cdate) == 5)
      {
       $mon = substr($cdate,0,1);
       $day = substr($cdate,1,2);
       $yr  = substr($cdate,3,2);
       $date = "$mon/$day/$yr";
      }
      else
      {
       #fuck it
       $date = $cdate;
      }

      #dump data to log file
      print USRPRF IAD::MiscFunc::trim($id),"|";
      print USRPRF IAD::MiscFunc::trim($owner),"|";
      print USRPRF IAD::MiscFunc::trim($date),"\n";

      #store in usrprf hash
      $usrprf{$id}->{owner}         = $owner;
      $usrprf{$id}->{creation_date} = $date;
    }
    else
    {
      return (0,"Error in AS4Data::online_get_usrprf_obj_data() -->\n***User Profile found in usrprf01 that's not in users_info, mysterious!: $id***\n");
    }

    $main::rs->MoveNext();
  }
  close USRPRF;

  return 1;
}

#=======================================
# Get usrprf01 object information online
#=======================================
sub offline_get_usrprf_obj_data
{
  open USRPRF, $main::ddir . "\\as4.usrprf.obj.data.txt"
       or return (0,"Error in AS4Data::offline_get_usrprf_obj_data -->\n***Can't open the as4.usrprf.obj.data.txt file: $!***\n");
  open LOG, ">" . $main::datad . "\\as4.usrprf.obj.data.txt"
       or return (0,"Error in AS4Data::offline_get_usrprf_obj_data -->\n***Can't open the as4.usrprf.obj.data.txt LOG file: $!***\n");
  while (<USRPRF>)
  {
    #print to log
    print LOG "$_";

    chomp;
    my($id,$owner,$date) = split/\|/;

    #store in usrprf hash
    $usrprf{$id}->{owner}         = $owner;
    $usrprf{$id}->{creation_date} = $date;
  }
  close USRPRF;
  close LOG;

  return 1;
}

#=================================
# Analyze default passwords online
#=================================
sub online_analyze_dft_pwd
{
  #refresh the qasecpwd file
  my $command = $AS4Conf::conf{$main::ip}->{AS400}->{anzdftpwd_command};
  unless ($command)
  {
    $command = $AS4Conf::conf{default}->{AS400}->{anzdftpwd_command};
  }

  my $lib = $AS4Conf::conf{$main::ip}->{AS400}->{anzdftpwd_lib};
  unless ($lib)
  {
    $lib = $AS4Conf::conf{default}->{AS400}->{anzdftpwd_lib};
  }

  #set active connection
  $main::cmd->{ActiveConnection} = $main::conn;

  $main::cmd->{CommandText} = "{{$command}}";
  $main::cmd->Execute or return (0,"Error in AS4Data::online_analyze_dft_pwd -->\n***Cannot execute the | $command | command!***\n");

  #query data
  $main::cmd->{CommandText} = "select * from $lib.qasecpwd";

  $main::rs = $main::cmd->Execute or return (1,"Possible Error in AS4Data::online_analyze_dft_pwd -->\n***Cannot execute the 'select * from $lib.qasecpwd' query or zero rows returned -- THIS IS PROBABLY OK!!!***\n");

  #store the user profile data
  open DFTPWD, ">$main::datad\\as4.analyze.dft.pwd.txt"
       or return (0,"Error in AS4Data::online_analyze_dft_pwd -->\n***Can't open the as4.anzlyze.dft.pwd.txt file: $!***\n");
  my $user;

  while (! $main::rs->{EOF})
  {
    #store
    $user = $main::rs->Fields("DFUSRP")->{Value};
    $dftpwd{$user}->{pwd_exp_before} = $main::rs->Fields("DFPEXB")->{Value};
    $dftpwd{$user}->{pwd_exp_after}  = $main::rs->Fields("DFPEXA")->{Value};
    $dftpwd{$user}->{status_before}  = $main::rs->Fields("DFSTAB")->{Value};
    $dftpwd{$user}->{status_after}   = $main::rs->Fields("DFSTAA")->{Value};
    $dftpwd{$user}->{name}           = $main::rs->Fields("DFPTXT")->{Value};

    #log
    print DFTPWD IAD::MiscFunc::trim($user) . "|";
    print DFTPWD IAD::MiscFunc::trim($main::rs->Fields("DFPTXT")->{Value}) . "|";
    print DFTPWD IAD::MiscFunc::trim($main::rs->Fields("DFPEXB")->{Value}) . "|";
    print DFTPWD IAD::MiscFunc::trim($main::rs->Fields("DFPEXA")->{Value}) . "|";
    print DFTPWD IAD::MiscFunc::trim($main::rs->Fields("DFSTAB")->{Value}) . "|";
    print DFTPWD IAD::MiscFunc::trim($main::rs->Fields("DFSTAA")->{Value}) . "\n";

    $main::rs->MoveNext();
  }

  return 1;
}

#==================================
# Analyze default passwords offline
#==================================
sub offline_analyze_dft_pwd
{
  open DFTPWD, $main::ddir . "\\as4.analyze.dft.pwd.txt"
       or return (1,"Possible error in AS4Data::offline_analyze_dft_pwd -->\n***Can't open the as4.analyze.dft.pwd.txt file, but it may not exist which could be ok: $!***\n");
  open LOG, ">" . $main::datad . "\\as4.analyze.dft.pwd.txt"
       or return (0,"Error in AS4Data::offline_analyze_dft_pwd -->\n***Can't open the as4.anzlyze.dft.pwd.txt LOG file: $!***\n");

  while (<DFTPWD>)
  {
    #print to log file
    print LOG "$_";

    chomp;
    my($user,$pwd_exp_before,$status_after,$pwd_exp_after,$name) = split/\|/;
    $dftpwd{$user}->{pwd_exp_before} = $pwd_exp_before;
    $dftpwd{$user}->{status_after}   = $status_after;
    $dftpwd{$user}->{pwd_exp_after}  = $pwd_exp_after;
    $dftpwd{$user}->{name}           = $name;
  }
  close DFTPWD;
  close LOG;

  return 1;
}

#============================
# Get object authority online
#============================
sub online_get_objaut
{
  #get objects to audit
  my %objs;
  my @objs;
  @objs = keys %{ $AS4Conf::conf{$main::ip}->{OBJAUT} };
  if (@objs)
  {
    #ip address existed, store object and type
    for my $obj (@objs)
    {
      $objs{$obj} = $AS4Conf::conf{$main::ip}->{OBJAUT}->{$obj};
    }
  }
  else
  {
    #use default objects
    @objs = keys %{ $AS4Conf::conf{default}->{OBJAUT} };
    for my $obj (@objs)
    {
      $objs{$obj} = $AS4Conf::conf{default}->{OBJAUT}->{$obj};
    }
  }
  @objs = ();

  #get our library
  my $lib = $AS4Conf::conf{$main::ip}->{AS400}->{library};
  unless ($lib)
  {
    $lib = $AS4Conf::conf{default}->{AS400}->{library};
  }

  #get object authority command
  my $cmd;
  $cmd = $AS4Conf::conf{$main::ip}->{AS400}->{objaut_command};
  unless ($cmd)
  {
    #use default
    $cmd = $AS4Conf::conf{default}->{AS400}->{objaut_command};
  }


  #create file with object authority
  my $cmdstr;
  $main::cmd->{ActiveConnection} = $main::conn;

  #first delete objaut__ file if it exists, note this may trigger an error
  $cmdstr = "DLTF " . $lib . "/OBJAUT__";
  $main::cmd->{CommandText} = "{{$cmdstr}}";
  $main::cmd->Execute or warn "Cannot delete the OBJAUT__ file, probably doesn't exist, continuing...\n";

  for my $obj (sort keys %objs)
  {
    $cmdstr = $cmd . " OBJ(" . $obj . ") OBJTYPE(" . $objs{$obj} . ") OUTPUT(*OUTFILE) OUTFILE(" . $lib . "/OBJAUT__) ";                   #43 chars
    $cmdstr .= "REPADD(*FIRST *ADD)";

    #execute command for this object
    $main::cmd->{CommandText} = "{{$cmdstr}}";
    $main::cmd->Execute or return (0,"Error in AS4Data::online_get_objaut -->\n***Cannot execute the | $cmdstr | command!***\n");
  }

  #query data in file, write log, and store data
  my $objname;
  my $usrprfname;
  open OBJAUT, ">$main::datad\\as4.objaut.data.txt"
       or return(0,"Error in AS4Data::online_get_objaut -->\n***Can't open the log file: $!***\n");
  $main::cmd->{CommandText} = "select * from $lib.objaut__ order by oaname";
  $main::rs = $main::cmd->Execute or return (0,"Error in AS4Data::online_get_objaut -->\n***Cannot execute the 'select * from $lib.objaut__ order by oaname' query!***\n");

  while (! $main::rs->{EOF})
  {
    #dump contents to log file
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OANAME")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAUSR")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAOBJA")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAOPR")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAOMGT")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAEXS")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAREAD")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAADD")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAUPD")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OADLT")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAAMGT")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAANAM")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OALIB")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OATYPE")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAOWN")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAPGRP")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAGRPN")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAEXEC")->{Value}) . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAALT")->{Value})  . "|";
    print OBJAUT IAD::MiscFunc::trim($main::rs->Fields("OAREF")->{Value})  . "\n";


    #store
    $objname    = $main::rs->Fields("OANAME")->{Value};
    $usrprfname = $main::rs->Fields("OAUSR")->{Value};
    $objaut{$objname}->{$usrprfname}->{obj_auth}    = $main::rs->Fields("OAOBJA")->{Value};
    $objaut{$objname}->{$usrprfname}->{op_auth}     = $main::rs->Fields("OAOPR")->{Value};
    $objaut{$objname}->{$usrprfname}->{mgt_auth}    = $main::rs->Fields("OAOMGT")->{Value};
    $objaut{$objname}->{$usrprfname}->{exs_auth}    = $main::rs->Fields("OAEXS")->{Value};
    $objaut{$objname}->{$usrprfname}->{read_auth}   = $main::rs->Fields("OAREAD")->{Value};
    $objaut{$objname}->{$usrprfname}->{add_auth}    = $main::rs->Fields("OAADD")->{Value};
    $objaut{$objname}->{$usrprfname}->{upd_auth}    = $main::rs->Fields("OAUPD")->{Value};
    $objaut{$objname}->{$usrprfname}->{del_auth}    = $main::rs->Fields("OADLT")->{Value};
    $objaut{$objname}->{$usrprfname}->{amgt_auth}   = $main::rs->Fields("OAAMGT")->{Value};
    $objaut{$objname}->{$usrprfname}->{anam_list}   = $main::rs->Fields("OAANAM")->{Value};
    $objaut{$objname}->{$usrprfname}->{lib}         = $main::rs->Fields("OALIB")->{Value};
    $objaut{$objname}->{$usrprfname}->{obj_type}    = $main::rs->Fields("OATYPE")->{Value};
    $objaut{$objname}->{$usrprfname}->{obj_owner}   = $main::rs->Fields("OAOWN")->{Value};
    $objaut{$objname}->{$usrprfname}->{primary_grp} = $main::rs->Fields("OAPGRP")->{Value};
    $objaut{$objname}->{$usrprfname}->{group}       = $main::rs->Fields("OAGRPN")->{Value};
    $objaut{$objname}->{$usrprfname}->{exec_auth}   = $main::rs->Fields("OAEXEC")->{Value};
    $objaut{$objname}->{$usrprfname}->{alt_auth}    = $main::rs->Fields("OAALT")->{Value};
    $objaut{$objname}->{$usrprfname}->{ref_auth}    = $main::rs->Fields("OAREF")->{Value};

    #move to next record
    $main::rs->MoveNext();
  }
  close OBJAUT;

  return 1;
}

#=============================
# Get object authority offline
#=============================
sub offline_get_objaut
{
  open OBJAUT, "$main::ddir\\as4.objaut.data.txt"
       or return(0,"Error in AS4Data::offline_get_objaut -->\n***Can't open the data file: $!***\n");
  open LOG, ">" . $main::datad . "\\as4.objaut.data.txt"
       or return(0,"Error in AS4Data::offline_get_objaut -->\n***Can't open the data LOG file: $!***\n");

  while (<OBJAUT>)
  {
    #print to log file
    print LOG "$_";

    chomp;
    my($oadcen,$oaddat,$oadtim,$oausr,$oaobja,$oaopr,$oaomgt,$oaexs,$oaread,$oaadd,$oaupd,$oadlt,$oaamgt,$oaanam,
       $oaname,$oalib,$oatype,$oaown,$oasyst,$oapgrp,$oagrpn,$oaexec,$oaalt,$oaref,$oares1,$oaaspl,$oaaspc) = split /\|/;

    $objaut{$oaname}->{$oausr}->{obj_auth}    = $oaobja;
    $objaut{$oaname}->{$oausr}->{op_auth}     = $oaopr;
    $objaut{$oaname}->{$oausr}->{mgt_auth}    = $oaomgt;
    $objaut{$oaname}->{$oausr}->{exs_auth}    = $oaexs;
    $objaut{$oaname}->{$oausr}->{read_auth}   = $oaread;
    $objaut{$oaname}->{$oausr}->{add_auth}    = $oaadd;
    $objaut{$oaname}->{$oausr}->{upd_auth}    = $oaupd;
    $objaut{$oaname}->{$oausr}->{del_auth}    = $oadlt;
    $objaut{$oaname}->{$oausr}->{amgt_auth}   = $oaamgt;
    $objaut{$oaname}->{$oausr}->{anam_list}   = $oaanam;
    $objaut{$oaname}->{$oausr}->{lib}         = $oalib;
    $objaut{$oaname}->{$oausr}->{obj_type}    = $oatype;
    $objaut{$oaname}->{$oausr}->{obj_owner}   = $oaown;
    $objaut{$oaname}->{$oausr}->{primary_grp} = $oapgrp;
    $objaut{$oaname}->{$oausr}->{group}       = $oagrpn;
    $objaut{$oaname}->{$oausr}->{exec_auth}   = $oaexec;
    $objaut{$oaname}->{$oausr}->{alt_auth}    = $oaalt;
    $objaut{$oaname}->{$oausr}->{ref_auth}    = $oaref;
  }
  close OBJAUT;
  close LOG;

  return 1;
}

#========================
# Get hr file information
#========================
sub get_hr_info
{
  open HR, $AS4Conf::conf{$main::ip}->{HR}->{value}
       or return(0,"Error in AS4Data::get_hr_info -->\n***Can't open the data file: $!***\n");
  open LOG, ">" . $main::datad . "\\as4.hr.info.txt"
       or return(0,"Error in AS4Data::get_hr_info -->\n***Can't open the data LOG file: $!***\n");

  while (<HR>)
  {
    #skip comments and blanks
    if ( $_ =~ /^#.*/ || $_ =~ /^(\s)*$/ )
    {
      next;
    }

    #print to log file
    print LOG "$_";

    chomp;
    my($as4_id,$full_name,$job_title,$dept,$work_location,$company,$status) = split /\|/;
    $as4_id = uc($as4_id);

    $hr{$as4_id}->{full_name}     = $full_name;
    $hr{$as4_id}->{job_title}     = $job_title;
    $hr{$as4_id}->{department}    = $dept;
    $hr{$as4_id}->{work_location} = $work_location;
    $hr{$as4_id}->{company}       = $company;
    $hr{$as4_id}->{status}        = $status;
  }
  close HR;
  close LOG;

  return 1;
}

#=======================
# Disconnect from server
#=======================
sub online_disconnect
{
  $main::rs->Close;
  $main::conn->Close;

  return 1;
}

#=============
# Return Value
#=============
1;