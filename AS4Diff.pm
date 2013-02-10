package AS4Diff;
require Exporter;

use strict;
use warnings;
use Algorithm::Diff 'traverse_sequences';
use Text::Tabs;
use File::Basename;
use IAD::XL;
use IAD::MiscFunc;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw(diff);

#=================
# Global Variables
#=================

#================
# Local Variables
#================
my @snap1;       #files for first snapshot directory
my @snap2;       #files for second snapshot directory
my @a;           #hold contents of snap1 file
my @b;           #hold contents of snap2 file
my $onlya = "onlyA";
my $onlyb = "onlyB";
my $type;        #hold type of log file being processed (accounts, policies, dormant, groups, or vpn)
my $preD;        #snapshot 1 date
my $preD_str;    #string of snap1 date for titles
my $postD;       #snapshot 2 date
my $postD_str;   #string of snap2 date for titles
my %dftpwd;      #hold changes to any default passworded accounts
my %objaut;      #hold changes to key objects
my %sv;          #hold changes to system values
my %usrprf;      #hold changes for user profiles
my %owners;      #hold changes made to owners of user profiles
my $xl_filename; #file to save end results to

#==========================================
# Diff two runs of the as4.pl script to
# track changes
#==========================================
sub diff
{
  my($snap_dir_1,$snap_dir_2) = @_;

  #get files and store in arrays
  @snap1 = glob ("$snap_dir_1\\data\\*.txt");
  @snap2 = glob ("$snap_dir_2\\data\\*.txt");
  @snap1 = sort @snap1;
  @snap2 = sort @snap2;

  #get the PRE and POST dates from the directories passed
  my($name,$path) = fileparse($snap_dir_1)
     or die "Can't perform the fileparse() operation on $snap_dir_1: $!\n";
  my($ts,$ip) = split /_/, $name;
  my(undef,$mon,$day,$yr,$hr,$min,$sec) = split /\./, $ts;
  $preD = "$mon.$day.$yr.$hr.$min.$sec";
  $preD_str = "$mon/$day/$yr";

  ($name,$path) = fileparse($snap_dir_2)
     or die "Can't perform the fileparse() operation on $snap_dir_2: $!\n";
  ($ts,$ip) = split /_/, $name;
  (undef,$mon,$day,$yr,$hr,$min,$sec) = split /\./, $ts;
  $postD = "$mon.$day.$yr.$hr.$min.$sec";
  $postD_str = "$mon/$day/$yr";
  $xl_filename = "$main::cwdd\\AS4." . $main::ip . "_diff_${preD}_to_${postD}.xls";

  #loop over each file and process
  for (my $i = 0; $i < 5; $i++)
  {
    #determine which log file type it is and set $type equal to it
    my($name,$path) = fileparse($snap1[$i])
       or die "Can't perform the fileparse() operation on $snap1[$i]: $!\n";
    (undef,$type,undef,undef) = split /\./, $name;

    #read files into arrays
    open S1, $snap1[$i] or die "Can't open $snap1[$i] file for snapshot 1: $!\n";
    open S2, $snap2[$i] or die "Can't open $snap2[$i] file for snapshot 2: $!\n";

    @a = <S1>;
    @b = <S2>;
    @a = sort @a;
    @b = sort @b;
    close S1;
    close S2;

    #chomp chomp
    preprocess(\@a);
    preprocess(\@b);

    #compare the arrays, store results in a %chgXxx hash
    traverse_sequences
    (
	    \@a,    # first sequence
	    \@b,    # second sequence
	    {
		    MATCH     => \&match,     # callback on identical lines
		    DISCARD_A => \&only_a,    # callback on A-only
		    DISCARD_B => \&only_b,    # callback on B-only
	    }
    );
  } #end files for()

  #----------
  # CALLBACKS
  #----------
  sub preprocess
  {
    #chomp chomp
	  my $arrayRef = shift;
	  chomp(@$arrayRef);
	  @$arrayRef = expand(@$arrayRef);
  }

  sub match
  {
    #do nothing with matches
  }

  sub only_a
  {
    #line in snap1 that isn't in snap2
    my ($s1,$s2) = @_;

    #analyze...parse...store
    logparse($a[$s1],$onlya);
  }

  sub only_b
  {
    #line in snap2 that isn't in snap1
    my ($s1,$s2) = @_;

    #analyze...parse...store
    logparse($b[$s2],$onlyb);
  }

  sub logparse
  {
    my($log_line,$callback) = @_;
    chomp $log_line;

    #parse out log line based on what log file we're processing
    if ($type eq "analyze")
    {
      #log file: as4.analyze.dft.pwd.txt
      #format: AS400_ID|PWD_Exp_Before|Status_After|PWD_Exp_After|Name
      my($id,$name,$pwd_exp_before,$pwd_exp_after,$status_before,$status_after) = split /\|/, $log_line;

      $dftpwd{$id}->{$callback}->{name}           = $name;
      $dftpwd{$id}->{$callback}->{pwd_exp_before} = $pwd_exp_before;
      $dftpwd{$id}->{$callback}->{pwd_exp_after}  = $pwd_exp_after;
      $dftpwd{$id}->{$callback}->{status_before}  = $status_before;
      $dftpwd{$id}->{$callback}->{status_after}   = $status_after;
    }
    elsif ($type eq "objaut")
    {
      #log file: as4.objaut.data.txt
      #format: Object_Name|User_Profile_Name|Object_Authority|Operational_Authority|Management_Authority|
      #        Existence_Authority|Read_Authority|Add_Authority|Update_Authority|Delete_Authority|Auth_List_Mgmt_Authority|
      #        Auth_List_Object|Library|Object_Type|Object_Owner|Primary_Group|Group|Execute_Authority|Alter_Authority|
      #        Reference_Authority
      my($object_name,$usr_profile_name,$obj_auth,$op_auth,$mgt_auth,$exs_auth,$read_auth,$add_auth,
         $upd_auth,$del_auth,$amgt_auth,$anam_list,$lib,$obj_type,$obj_owner,$primary_grp,$group,
         $exec_auth,$alt_auth,$ref_auth) = split /\|/, $log_line;

      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{obj_auth}    = $obj_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{op_auth}     = $op_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{mgt_auth}    = $mgt_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{exs_auth}    = $exs_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{read_auth}   = $read_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{add_auth}    = $add_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{upd_auth}    = $upd_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{del_auth}    = $del_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{amgt_auth}   = $amgt_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{anam_list}   = $anam_list;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{lib}         = $lib;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{obj_type}    = $obj_type;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{obj_owner}   = $obj_owner;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{primary_grp} = $primary_grp;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{group}       = $group;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{exec_auth}   = $exec_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{alt_auth}    = $alt_auth;
      $objaut{$object_name}->{$usr_profile_name}->{$callback}->{ref_auth}    = $ref_auth;
    }
    elsif ($type eq "system")
    {
      #log file: as4.system.values.txt
      #format: System_Value_Name|System_Value_Setting|System_Value_Desc
      my($sv_name,$sv_value,$sv_desc) = split /\|/, $log_line;

      $sv{$sv_name}->{$callback}->{value} = $sv_value;
      $sv{$sv_name}->{$callback}->{desc}  = $sv_desc;
    }
    elsif ($type eq "user")
    {
      #log file: as4.user.profile.data.txt
      #format: User_Profile_Name|Text_Description|Limited_Capabilities|Initial_Program|
      #        Initial_Program_Library|Current_Library|Initial_Menu|Initial_Menu_Library|
      #        Status|Group_Profile|Supplemental_Groups|Password_Of_*NONE|Password_Exp_Interval|
      #        User_Class|Special_Authorities|Limit_Device_Sessions|Groups_Authority|Attention_Program
      #        Attention_Program_Lib|User_Profile_Locked|User_Profile_Damaged|Password_Present_For_Level_0|
      #        Password_Present_For_Level_2|NetServer_Password_Present|Local_Password_Management
      my($id,$name,$limited_cap,$init_prog,$init_prog_lib,$cur_lib,$init_menu,$init_menu_lib,
         $status,$group,$sup_group,$pass_none,$pass_exp_int,$user_class,$spec_auth,$lim_dev_sessions,
         $group_auth,$attn_prog,$attn_prog_lib,$locked,$damaged,$pwd_lvl_0,$pwd_lvl_2,$ns_pwd,
         $loc_pwd_mgmt) = split /\|/, $log_line;

      $usrprf{$id}->{$callback}->{name}             = $name;
      $usrprf{$id}->{$callback}->{limited_cap}      = $limited_cap;
      $usrprf{$id}->{$callback}->{init_prog}        = $init_prog;
      $usrprf{$id}->{$callback}->{init_prog_lib}    = $init_prog_lib;
      $usrprf{$id}->{$callback}->{cur_lib}          = $cur_lib;
      $usrprf{$id}->{$callback}->{init_menu}        = $init_menu;
      $usrprf{$id}->{$callback}->{init_menu_lib}    = $init_menu_lib;
      $usrprf{$id}->{$callback}->{status}           = $status;
      $usrprf{$id}->{$callback}->{group}            = $group;
      $usrprf{$id}->{$callback}->{sup_group}        = $sup_group;
      $usrprf{$id}->{$callback}->{pass_none}        = $pass_none;
      $usrprf{$id}->{$callback}->{pass_exp_int}     = $pass_exp_int;
      $usrprf{$id}->{$callback}->{user_class}       = $user_class;
      $usrprf{$id}->{$callback}->{spec_auth}        = $spec_auth;
      $usrprf{$id}->{$callback}->{lim_dev_sessions} = $lim_dev_sessions;
      $usrprf{$id}->{$callback}->{group_auth}       = $group_auth;
      $usrprf{$id}->{$callback}->{attn_prog}        = $attn_prog;
      $usrprf{$id}->{$callback}->{attn_prog_lib}    = $attn_prog_lib;
      $usrprf{$id}->{$callback}->{locked}           = $locked;
      $usrprf{$id}->{$callback}->{damaged}          = $damaged;
      $usrprf{$id}->{$callback}->{pwd_lvl_0}        = $pwd_lvl_0;
      $usrprf{$id}->{$callback}->{pwd_lvl_2}        = $pwd_lvl_2;
      $usrprf{$id}->{$callback}->{ns_pwd}           = $ns_pwd;
      $usrprf{$id}->{$callback}->{loc_pwd_mgmt}     = $loc_pwd_mgmt;

    }
    elsif ($type eq "usrprf")
    {
      #log file: as4.usrprf.obj.data.txt
      #format: ID|Owner|Creation_Date
      my($id,$owner,$creation_date) = split /\|/, $log_line;

      $owners{$id}->{$callback}->{owner} = $owner;
      $owners{$id}->{$callback}->{creation_date} = $creation_date;

    }
    else
    {
      die "unknown type in logparse(): passed line $log_line and callback $callback","\n";
    }
  } #end logparse()

  #-------------------------
  # Output - Account Changes
  #-------------------------
  IAD::XL::init_xl("User Profile Changes");
  IAD::XL::add_header("Profile Chgs [$preD_str to $postD_str]","User ID","Previous","Current","Type");
  my $before  = 0;
  my $after   = 0;
  my $change_type;
  my $previous_str = "";
  my $current_str = "";

  #before temp vars
  my $b_name             = "";
  my $b_limited_cap      = "";
  my $b_init_prog        = "";
  my $b_init_prog_lib    = "";
  my $b_cur_lib          = "";
  my $b_init_menu        = "";
  my $b_init_menu_lib    = "";
  my $b_status           = "";
  my $b_group            = "";
  my $b_sup_group        = "";
  my $b_pass_none        = "";
  my $b_pass_exp_int     = "";
  my $b_user_class       = "";
  my $b_spec_auth        = "";
  my $b_lim_dev_sessions = "";
  my $b_group_auth       = "";
  my $b_attn_prog        = "";
  my $b_attn_prog_lib    = "";
  my $b_locked           = "";
  my $b_damaged          = "";
  my $b_pwd_lvl_0        = "";
  my $b_pwd_lvl_2        = "";
  my $b_ns_pwd           = "";
  my $b_loc_pwd_mgmt     = "";

  #after temp vars
  my $a_name             = "";
  my $a_limited_cap      = "";
  my $a_init_prog        = "";
  my $a_init_prog_lib    = "";
  my $a_cur_lib          = "";
  my $a_init_menu        = "";
  my $a_init_menu_lib    = "";
  my $a_status           = "";
  my $a_group            = "";
  my $a_sup_group        = "";
  my $a_pass_none        = "";
  my $a_pass_exp_int     = "";
  my $a_user_class       = "";
  my $a_spec_auth        = "";
  my $a_lim_dev_sessions = "";
  my $a_group_auth       = "";
  my $a_attn_prog        = "";
  my $a_attn_prog_lib    = "";
  my $a_locked           = "";
  my $a_damaged          = "";
  my $a_pwd_lvl_0        = "";
  my $a_pwd_lvl_2        = "";
  my $a_ns_pwd           = "";
  my $a_loc_pwd_mgmt     = "";

  for my $id (sort keys %usrprf)
  {
    for my $cb (sort keys %{ $usrprf{$id} })
    {
      if ($cb eq $onlya)
      {
        $before = 1;
        $b_name             = $usrprf{$id}->{$cb}->{name};
        $b_limited_cap      = $usrprf{$id}->{$cb}->{limited_cap};
        $b_init_prog        = $usrprf{$id}->{$cb}->{init_prog};
        $b_init_prog_lib    = $usrprf{$id}->{$cb}->{init_prog_lib};
        $b_cur_lib          = $usrprf{$id}->{$cb}->{cur_lib};
        $b_init_menu        = $usrprf{$id}->{$cb}->{init_menu};
        $b_init_menu_lib    = $usrprf{$id}->{$cb}->{init_menu_lib};
        $b_status           = $usrprf{$id}->{$cb}->{status};
        $b_group            = $usrprf{$id}->{$cb}->{group};
        $b_sup_group        = $usrprf{$id}->{$cb}->{sup_group};
        $b_pass_none        = $usrprf{$id}->{$cb}->{pass_none};
        $b_pass_exp_int     = $usrprf{$id}->{$cb}->{pass_exp_int};
        $b_user_class       = $usrprf{$id}->{$cb}->{user_class};
        $b_spec_auth        = $usrprf{$id}->{$cb}->{spec_auth};
        $b_lim_dev_sessions = $usrprf{$id}->{$cb}->{lim_dev_sessions};
        $b_group_auth       = $usrprf{$id}->{$cb}->{group_auth};
        $b_attn_prog        = $usrprf{$id}->{$cb}->{attn_prog};
        $b_attn_prog_lib    = $usrprf{$id}->{$cb}->{attn_prog_lib};
        $b_locked           = $usrprf{$id}->{$cb}->{locked};
        $b_damaged          = $usrprf{$id}->{$cb}->{damaged};
        $b_pwd_lvl_0        = $usrprf{$id}->{$cb}->{pwd_lvl_0};
        $b_pwd_lvl_2        = $usrprf{$id}->{$cb}->{pwd_lvl_2};
        $b_ns_pwd           = $usrprf{$id}->{$cb}->{ns_pwd};
        $b_loc_pwd_mgmt     = $usrprf{$id}->{$cb}->{loc_pwd_mgmt}
      }

      if ($cb eq $onlyb)
      {
        $after  = 1;
        $a_name             = $usrprf{$id}->{$cb}->{name};
        $a_limited_cap      = $usrprf{$id}->{$cb}->{limited_cap};
        $a_init_prog        = $usrprf{$id}->{$cb}->{init_prog};
        $a_init_prog_lib    = $usrprf{$id}->{$cb}->{init_prog_lib};
        $a_cur_lib          = $usrprf{$id}->{$cb}->{cur_lib};
        $a_init_menu        = $usrprf{$id}->{$cb}->{init_menu};
        $a_init_menu_lib    = $usrprf{$id}->{$cb}->{init_menu_lib};
        $a_status           = $usrprf{$id}->{$cb}->{status};
        $a_group            = $usrprf{$id}->{$cb}->{group};
        $a_sup_group        = $usrprf{$id}->{$cb}->{sup_group};
        $a_pass_none        = $usrprf{$id}->{$cb}->{pass_none};
        $a_pass_exp_int     = $usrprf{$id}->{$cb}->{pass_exp_int};
        $a_user_class       = $usrprf{$id}->{$cb}->{user_class};
        $a_spec_auth        = $usrprf{$id}->{$cb}->{spec_auth};
        $a_lim_dev_sessions = $usrprf{$id}->{$cb}->{lim_dev_sessions};
        $a_group_auth       = $usrprf{$id}->{$cb}->{group_auth};
        $a_attn_prog        = $usrprf{$id}->{$cb}->{attn_prog};
        $a_attn_prog_lib    = $usrprf{$id}->{$cb}->{attn_prog_lib};
        $a_locked           = $usrprf{$id}->{$cb}->{locked};
        $a_damaged          = $usrprf{$id}->{$cb}->{damaged};
        $a_pwd_lvl_0        = $usrprf{$id}->{$cb}->{pwd_lvl_0};
        $a_pwd_lvl_2        = $usrprf{$id}->{$cb}->{pwd_lvl_2};
        $a_ns_pwd           = $usrprf{$id}->{$cb}->{ns_pwd};
        $a_loc_pwd_mgmt     = $usrprf{$id}->{$cb}->{loc_pwd_mgmt}
      }
    } #end cb for()

    #determine change type
    if ($before && $after)
    {
      $change_type = "Change";
    }
    elsif ($before && ! $after)
    {
      $change_type = "Removal";
    }
    elsif (! $before && $after)
    {
      $change_type = "Addition";
    }

    #determine what changed
    #Name (UPTEXT)
    unless ($b_name eq $a_name)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Name (UPTEXT): $b_name\n";
        $current_str  .= "Name (UPTEXT): $a_name\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Name (UPTEXT): $b_name\n";
      }
      elsif ( $change_type eq "Addition")
      {
        $current_str  .= "Name (UPTEXT): $a_name\n";
      }
    }

    #Limited Capabilities (UPLTCP)
    unless ($b_limited_cap eq $a_limited_cap)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Limited Cap (UPLTCP): $b_limited_cap\n";
        $current_str  .= "Limited Cap (UPLTCP): $a_limited_cap\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Limited Cap (UPLTCP): $b_limited_cap\n";
      }
      elsif ( $change_type eq "Addition")
      {
        $current_str  .= "Limited Cap (UPLTCP): $a_limited_cap\n";
      }
    }

    #Initial Program (UPINPG)
    unless ($b_init_prog eq $a_init_prog)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Init Program (UPINPG): $b_init_prog\n";
        $current_str  .= "Init Program (UPINPG): $a_init_prog\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Init Program (UPINPG): $b_init_prog\n";
      }
      elsif ( $change_type eq "Addition")
      {
        $current_str  .= "Init Program (UPINPG): $a_init_prog\n";
      }
    }

    #Initial Program Library (UPINPL)
    unless ($b_init_prog_lib eq $a_init_prog_lib)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Init Prog Lib (UPINPL): $b_init_prog_lib\n";
        $current_str  .= "Init Prog Lib (UPINPL): $a_init_prog_lib\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Init Prog Lib (UPINPL): $b_init_prog_lib\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Init Prog Lib (UPINPL): $a_init_prog_lib\n";
      }
    }

    #Current Library (UPCRLB)
    unless ($b_cur_lib eq $a_cur_lib)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Current Lib (UPCRLB): $b_cur_lib\n";
        $current_str  .= "Current Lib (UPCRLB): $a_cur_lib\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Current Lib (UPCRLB): $b_cur_lib\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Current Lib (UPCRLB): $a_cur_lib\n";
      }
    }

    #Initial Menu (UPINMN)
    unless ($b_init_menu eq $a_init_menu)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Init Menu (UPINMN): $b_init_menu\n";
        $current_str  .= "Init Menu (UPINMN): $a_init_menu\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Init Menu (UPINMN): $b_init_menu\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Init Menu (UPINMN): $a_init_menu\n";
      }
    }

    #Initial Menu Library (UPINML)
    unless ($b_init_menu_lib eq $a_init_menu_lib)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Init Menu Lib (UPINML): $b_init_menu_lib\n";
        $current_str  .= "Init Menu Lib (UPINML): $a_init_menu_lib\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Init Menu Lib (UPINML): $b_init_menu_lib\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Init Menu Lib: $a_init_menu_lib\n";
      }
    }

    #Status (UPSTAT)
    unless ($b_status eq $a_status)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Status (UPSTAT): $b_status\n";
        $current_str  .= "Status (UPSTAT): $a_status\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Status (UPSTAT): $b_status\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Status (UPSTAT): $a_status\n";
      }
    }
    
    #Group (UPGRPF)
    unless ($b_group eq $a_group)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Group (UPGRPF): $b_group\n";
        $current_str  .= "Group (UPGRPF): $a_group\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Group (UPGRPF): $b_group\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Group (UPGRPF): $a_group\n";
      }
    }

    #Supplemental Groups (UPSUPG)
    unless ($b_sup_group eq $a_sup_group)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Supplemental Groups (UPSUPG): $b_sup_group\n";
        $current_str  .= "Supplemental Groups (UPSUPG): $a_sup_group\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Supplemental Groups (UPSUPG): $b_sup_group\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Supplemental Groups (UPSUPG): $a_sup_group\n";
      }
    }
    
    #Password of *NONE (UPPWON)
    unless ($b_pass_none eq $a_pass_none)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Pass of *NONE (UPPWON): $b_pass_none\n";
        $current_str  .= "Pass of *NONE (UPPWON): $a_pass_none\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Pass of *NONE (UPPWON): $b_pass_none\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Pass of *NONE (UPPWON): $a_pass_none\n";
      }
    }
    
    #Password Expiration Interval (UPPWEI)
    unless ($b_pass_exp_int eq $a_pass_exp_int)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Pass Exp Interval (UPPWEI): $b_pass_exp_int\n";
        $current_str  .= "Pass Exp Interval (UPPWEI): $a_pass_exp_int\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Pass Exp Interval (UPPWEI): $b_pass_exp_int\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Pass Exp Interval (UPPWEI): $a_pass_exp_int\n";
      }
    }
    
    #User Class (UPUSCL)
    unless ($b_user_class eq $a_user_class)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "User Class (UPUSCL): $b_user_class\n";
        $current_str  .= "User Class (UPUSCL): $a_user_class\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "User Class (UPUSCL): $b_user_class\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "User Class (UPUSCL): $a_user_class\n";
      }
    }

    #Special Authorities (UPSPAU)
    unless ($b_spec_auth eq $a_spec_auth)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Special Authorities (UPSPAU): $b_spec_auth\n";
        $current_str  .= "Special Authorities (UPSPAU): $a_spec_auth\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Special Authorities (UPSPAU): $b_spec_auth\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Special Authorities (UPSPAU): $a_spec_auth\n";
      }
    }

    #Limit Device Sessions (UPLDVS)
    unless ($b_lim_dev_sessions eq $a_lim_dev_sessions)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Limit Dev Sessions (UPLDVS): $b_lim_dev_sessions\n";
        $current_str  .= "Limit Dev Sessions (UPLDVS): $a_lim_dev_sessions\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Limit Dev Sessions (UPLDVS): $b_lim_dev_sessions\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Limit Dev Sessions (UPLDVS): $a_lim_dev_sessions\n";
      }
    }
    
    #Group Authority (UPGRAU)
    unless ($b_group_auth eq $a_group_auth)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Group Authority (UPGRAU): $b_group_auth\n";
        $current_str  .= "Group Authority (UPGRAU): $a_group_auth\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Group Authority (UPGRAU): $b_group_auth\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Group Authority (UPGRAU): $a_group_auth\n";
      }
    }
    
    #Attention Key Program (UPATPG)
    unless ($b_attn_prog eq $a_attn_prog)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Attn Key Prog (UPATPG): $b_attn_prog\n";
        $current_str  .= "Attn Key Prog (UPATPG): $a_attn_prog\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Attn Key Prog (UPATPG): $b_attn_prog\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Attn Key Prog (UPATPG): $a_attn_prog\n";
      }
    }
    
    #Attention Key Program Library (UPATPL)
    unless ($b_attn_prog_lib eq $a_attn_prog_lib)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Attn Key Prog Lib (UPATPL): $b_attn_prog_lib\n";
        $current_str  .= "Attn Key Prog Lib (UPATPL): $a_attn_prog_lib\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Attn Key Prog Lib (UPATPL): $b_attn_prog_lib\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Attn Key Prog Lib (UPATPL): $a_attn_prog_lib\n";
      }
    }

    #User Profile Locked (UPUPLK)
    unless ($b_locked eq $a_locked)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Locked (UPUPLK): $b_locked\n";
        $current_str  .= "Locked (UPUPLK): $a_locked\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Locked (UPUPLK): $b_locked\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Locked (UPUPLK): $a_locked\n";
      }
    }

    #User Profile Damaged (UPUPDM)
    unless ($b_damaged eq $a_damaged)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Damaged (UPUPDM): $b_damaged\n";
        $current_str  .= "Damaged (UPUPDM): $a_damaged\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Damaged (UPUPDM): $b_damaged\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Damaged (UPUPDM): $a_damaged\n";
      }
    }

    #Password Present for Level 0 (UPENPW)
    unless ($b_pwd_lvl_0 eq $a_pwd_lvl_0)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Pwd Present for Lvl 0 (UPENPW): $b_pwd_lvl_0\n";
        $current_str  .= "Pwd Present for Lvl 0 (UPENPW): $a_pwd_lvl_0\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Pwd Present for Lvl 0 (UPENPW): $b_pwd_lvl_0\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Pwd Present for Lvl 0 (UPENPW): $a_pwd_lvl_0\n";
      }
    }
    
    #Password Present for Level 2 (UPENPH)
    unless ($b_pwd_lvl_2 eq $a_pwd_lvl_2)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Pwd Present for Lvl 2 (UPENPH): $b_pwd_lvl_2\n";
        $current_str  .= "Pwd Present for Lvl 2 (UPENPH): $a_pwd_lvl_2\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Pwd Present for Lvl 2 (UPENPH): $b_pwd_lvl_2\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Pwd Present for Lvl 2 (UPENPH): $a_pwd_lvl_2\n";
      }
    }
    
    #NetServer Password Present (UPENLM)
    unless ($b_ns_pwd eq $a_ns_pwd)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "NetServer Pwd (UPENLM): $b_ns_pwd\n";
        $current_str  .= "NetServer Pwd (UPENLM): $a_ns_pwd\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "NetServer Pwd (UPENLM): $b_ns_pwd\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "NetServer Pwd (UPENLM): $a_ns_pwd\n";
      }
    }
    
    #Local Password Management (UPLPWM)
    unless ($b_loc_pwd_mgmt eq $a_loc_pwd_mgmt)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Local Pwd Mgmt (UPLPWM): $b_loc_pwd_mgmt\n";
        $current_str  .= "Local Pwd Mgmt (UPLPWM): $a_loc_pwd_mgmt\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Local Pwd Mgmt (UPLPWM): $b_loc_pwd_mgmt\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Local Pwd Mgmt (UPLPWM): $a_loc_pwd_mgmt\n";
      }
    }

    #write row
    IAD::XL::write_row($id,$previous_str,$current_str,$change_type);

    #release memory
    $before = 0;
    $after  = 0;
    $previous_str = "";
    $current_str  = "";
    $change_type  = "";
    
    #before temps
    $b_name             = "";
    $b_limited_cap      = "";
    $b_init_prog        = "";
    $b_init_prog_lib    = "";
    $b_cur_lib          = "";
    $b_init_menu        = "";
    $b_init_menu_lib    = "";
    $b_status           = "";
    $b_group            = "";
    $b_sup_group        = "";
    $b_pass_none        = "";
    $b_pass_exp_int     = "";
    $b_user_class       = "";
    $b_spec_auth        = "";
    $b_lim_dev_sessions = "";
    $b_group_auth       = "";
    $b_attn_prog        = "";
    $b_attn_prog_lib    = "";
    $b_locked           = "";
    $b_damaged          = "";
    $b_pwd_lvl_0        = "";
    $b_pwd_lvl_2        = "";
    $b_ns_pwd           = "";
    $b_loc_pwd_mgmt     = "";
    
    #after temps
    $a_name             = "";
    $a_limited_cap      = "";
    $a_init_prog        = "";
    $a_init_prog_lib    = "";
    $a_cur_lib          = "";
    $a_init_menu        = "";
    $a_init_menu_lib    = "";
    $a_status           = "";
    $a_group            = "";
    $a_sup_group        = "";
    $a_pass_none        = "";
    $a_pass_exp_int     = "";
    $a_user_class       = "";
    $a_spec_auth        = "";
    $a_lim_dev_sessions = "";
    $a_group_auth       = "";
    $a_attn_prog        = "";
    $a_attn_prog_lib    = "";
    $a_locked           = "";
    $a_damaged          = "";
    $a_pwd_lvl_0        = "";
    $a_pwd_lvl_2        = "";
    $a_ns_pwd           = "";
    $a_loc_pwd_mgmt     = "";

  } #end id for()

  #----------------------------------
  # Output - Object Authority Changes
  #----------------------------------
  IAD::XL::add_sheet("Object Authority Changes");
  IAD::XL::add_header("Obj Auth Chgs [$preD_str to $postD_str]","Object","User/Group","Previous","Current","Type");
  $before = 0;
  $after  = 0;
  $change_type  = "";
  $previous_str = "";
  $current_str  = "";

  #before temp vars
  my $b_obj_auth = "";
  my $b_op_auth = "";
  my $b_mgt_auth = "";
  my $b_exs_auth = "";
  my $b_read_auth = "";
  my $b_add_auth = "";
  my $b_upd_auth = "";
  my $b_del_auth = "";
  my $b_amgt_auth = "";
  my $b_anam_list = "";
  my $b_lib = "";
  my $b_obj_type = "";
  my $b_obj_owner = "";
  my $b_primary_grp = "";
  $b_group = "";
  my $b_exec_auth = "";
  my $b_alt_auth = "";
  my $b_ref_auth = "";

  #after temp vars
  my $a_obj_auth = "";
  my $a_op_auth = "";
  my $a_mgt_auth = "";
  my $a_exs_auth = "";
  my $a_read_auth = "";
  my $a_add_auth = "";
  my $a_upd_auth = "";
  my $a_del_auth = "";
  my $a_amgt_auth = "";
  my $a_anam_list = "";
  my $a_lib = "";
  my $a_obj_type = "";
  my $a_obj_owner = "";
  my $a_primary_grp = "";
  $a_group = "";
  my $a_exec_auth = "";
  my $a_alt_auth = "";
  my $a_ref_auth = "";

  for my $obj (sort keys %objaut)
  {
    for my $id (sort keys %{ $objaut{$obj} })
    {
      for my $cb (sort keys %{ $objaut{$obj}->{$id} })
      {
        if ($cb eq $onlya)
        {
          $before = 1;
          $b_obj_auth    = $objaut{$obj}->{$id}->{$cb}->{obj_auth};
          $b_op_auth     = $objaut{$obj}->{$id}->{$cb}->{op_auth};
          $b_mgt_auth    = $objaut{$obj}->{$id}->{$cb}->{mgt_auth};
          $b_exs_auth    = $objaut{$obj}->{$id}->{$cb}->{exs_auth};
          $b_read_auth   = $objaut{$obj}->{$id}->{$cb}->{read_auth};
          $b_add_auth    = $objaut{$obj}->{$id}->{$cb}->{add_auth};
          $b_upd_auth    = $objaut{$obj}->{$id}->{$cb}->{upd_auth};
          $b_del_auth    = $objaut{$obj}->{$id}->{$cb}->{del_auth};
          $b_amgt_auth   = $objaut{$obj}->{$id}->{$cb}->{amgt_auth};
          $b_anam_list   = $objaut{$obj}->{$id}->{$cb}->{anam_list};
          $b_lib         = $objaut{$obj}->{$id}->{$cb}->{lib};
          $b_obj_type    = $objaut{$obj}->{$id}->{$cb}->{obj_type};
          $b_obj_owner   = $objaut{$obj}->{$id}->{$cb}->{obj_owner};
          $b_primary_grp = $objaut{$obj}->{$id}->{$cb}->{primary_grp};
          $b_group       = $objaut{$obj}->{$id}->{$cb}->{group};
          $b_exec_auth   = $objaut{$obj}->{$id}->{$cb}->{exec_auth};
          $b_alt_auth    = $objaut{$obj}->{$id}->{$cb}->{alt_auth};
          $b_ref_auth    = $objaut{$obj}->{$id}->{$cb}->{ref_auth};
        }

        if ($cb eq $onlyb)
        {
          $after  = 1;
          $a_obj_auth    = $objaut{$obj}->{$id}->{$cb}->{obj_auth};
          $a_op_auth     = $objaut{$obj}->{$id}->{$cb}->{op_auth};
          $a_mgt_auth    = $objaut{$obj}->{$id}->{$cb}->{mgt_auth};
          $a_exs_auth    = $objaut{$obj}->{$id}->{$cb}->{exs_auth};
          $a_read_auth   = $objaut{$obj}->{$id}->{$cb}->{read_auth};
          $a_add_auth    = $objaut{$obj}->{$id}->{$cb}->{add_auth};
          $a_upd_auth    = $objaut{$obj}->{$id}->{$cb}->{upd_auth};
          $a_del_auth    = $objaut{$obj}->{$id}->{$cb}->{del_auth};
          $a_amgt_auth   = $objaut{$obj}->{$id}->{$cb}->{amgt_auth};
          $a_anam_list   = $objaut{$obj}->{$id}->{$cb}->{anam_list};
          $a_lib         = $objaut{$obj}->{$id}->{$cb}->{lib};
          $a_obj_type    = $objaut{$obj}->{$id}->{$cb}->{obj_type};
          $a_obj_owner   = $objaut{$obj}->{$id}->{$cb}->{obj_owner};
          $a_primary_grp = $objaut{$obj}->{$id}->{$cb}->{primary_grp};
          $a_group       = $objaut{$obj}->{$id}->{$cb}->{group};
          $a_exec_auth   = $objaut{$obj}->{$id}->{$cb}->{exec_auth};
          $a_alt_auth    = $objaut{$obj}->{$id}->{$cb}->{alt_auth};
          $a_ref_auth    = $objaut{$obj}->{$id}->{$cb}->{ref_auth};
        }
      } #end cb for()

      #determine change type
      if ($before && $after)
      {
        $change_type = "Change";
      }
      elsif ($before && ! $after)
      {
        $change_type = "Removal";
      }
      elsif (! $before && $after)
      {
        $change_type = "Addition";
      }

      #determine what changed
      #Object Authority (OAOBJA)
      unless ($b_obj_auth eq $a_obj_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Obj Authority (OAOBJA): $b_obj_auth\n";
          $current_str  .= "Obj Authority (OAOBJA): $a_obj_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Obj Authority (OAOBJA): $b_obj_auth\n";
        }
        elsif ( $change_type eq "Addition")
        {
          $current_str  .= "Obj Authority (OAOBJA): $a_obj_auth\n";
        }
      }

      #Operation Authority (OAOPR)
      unless ($b_op_auth eq $a_op_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Obj Oper (OAOPR): $b_op_auth\n";
          $current_str  .= "Obj Oper (OAOPR): $a_op_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Obj Oper (OAOPR): $b_op_auth\n";
        }
        elsif ( $change_type eq "Addition")
        {
          $current_str  .= "Obj Oper (OAOPR): $a_op_auth\n";
        }
      }

      #Management Authority (OAOMGT)
      unless ($b_mgt_auth eq $a_mgt_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Obj Mgmt (OAOMGT): $b_mgt_auth\n";
          $current_str  .= "Obj Mgmt (OAOMGT): $a_mgt_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Obj Mgmt (OAOMGT): $b_mgt_auth\n";
        }
        elsif ( $change_type eq "Addition")
        {
          $current_str  .= "Obj Mgmt (OAOMGT): $a_mgt_auth\n";
        }
      }

      #Existence Authority (OAEXS)
      unless ($b_exs_auth eq $a_exs_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Obj Existence Auth (OAEXS): $b_exs_auth\n";
          $current_str  .= "Obj Existence Auth (OAEXS): $a_exs_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Obj Existence Auth (OAEXS): $b_exs_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Obj Existence Auth (OAEXS): $a_exs_auth\n";
        }
      }

      #Read Authority (OAREAD)
      unless ($b_read_auth eq $a_read_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Read Auth (OAREAD): $b_read_auth\n";
          $current_str  .= "Read Auth (OAREAD): $a_read_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Read Auth (OAREAD): $b_read_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Read Auth (OAREAD): $a_read_auth\n";
        }
      }

      #Add Authority (OAADD)
      unless ($b_add_auth eq $a_add_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Add Auth (OAADD): $b_add_auth\n";
          $current_str  .= "Add Auth (OAADD): $a_add_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Add Auth (OAADD): $b_add_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Add Auth (OAADD): $a_add_auth\n";
        }
      }

      #Update Authority (OAUPD)
      unless ($b_upd_auth eq $a_upd_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Update Auth (OAUPD): $b_upd_auth\n";
          $current_str  .= "Update Auth (OAUPD): $a_upd_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Update Auth (OAUPD): $b_upd_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Update Auth (OAUPD): $a_upd_auth\n";
        }
      }

      #Delete Authority (OADLT)
      unless ($b_del_auth eq $a_del_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Delete Auth (OADLT): $b_del_auth\n";
          $current_str  .= "Delete Auth (OADLT): $a_del_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Delete Auth (OADLT): $b_del_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Delete Auth (OADLT): $a_del_auth\n";
        }
      }

      #Auth. List Mgt Authority (OAAMGT)
      unless ($b_amgt_auth eq $a_amgt_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Aut List Mgmt Auth (OAAMGT): $b_amgt_auth\n";
          $current_str  .= "Aut List Mgmt Auth (OAAMGT): $a_amgt_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Aut List Mgmt Auth (OAAMGT): $b_amgt_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Aut List Mgmt Auth (OAAMGT): $a_amgt_auth\n";
        }
      }

      #Authorization List on Object (OAANAM)
      unless ($b_anam_list eq $a_anam_list)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Auth List on Obj (OAANAM): $b_anam_list\n";
          $current_str  .= "Auth List on Obj (OAANAM): $a_anam_list\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Auth List on Obj (OAANAM): $b_anam_list\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Auth List on Obj (OAANAM): $a_anam_list\n";
        }
      }

      #Library (OALIB)
      unless ($b_lib eq $a_lib)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Library (OALIB): $b_lib\n";
          $current_str  .= "Library (OALIB): $a_lib\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Library (OALIB): $b_lib\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Library (OALIB): $a_lib\n";
        }
      }

      #Type Of Object (OATYPE)
      unless ($b_obj_type eq $a_obj_type)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Object Type (OATYPE): $b_obj_type\n";
          $current_str  .= "Object Type (OATYPE): $a_obj_type\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Object Type (OATYPE): $b_obj_type\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Object Type (OATYPE): $a_obj_type\n";
        }
      }

      #Object Owner (OAOWN)
      unless ($b_obj_owner eq $a_obj_owner)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Obj Owner (OAOWN): $b_obj_owner\n";
          $current_str  .= "Obj Owner (OAOWN): $a_obj_owner\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Obj Owner (OAOWN): $b_obj_owner\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Obj Owner (OAOWN): $a_obj_owner\n";
        }
      }

      #Primary Group (OAPGRP)
      unless ($b_primary_grp eq $a_primary_grp)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Primary Group (OAPGRP): $b_primary_grp\n";
          $current_str  .= "Primary Group (OAPGRP): $a_primary_grp\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Primary Group (OAPGRP): $b_primary_grp\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Primary Group (OAPGRP): $a_primary_grp\n";
        }
      }

      #Group (OAGRPN)
      unless ($b_group eq $a_group)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Group (OAGRPN): $b_group\n";
          $current_str  .= "Group (OAGRPN): $a_group\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Group (OAGRPN): $b_group\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Group (OAGRPN): $a_group\n";
        }
      }

      #Execute Authority (OAEXEC)
      unless ($b_exec_auth eq $a_exec_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Execute Authority (OAEXEC): $b_exec_auth\n";
          $current_str  .= "Execute Authority (OAEXEC): $a_exec_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Execute Authority (OAEXEC): $b_exec_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Execute Authority (OAEXEC): $a_exec_auth\n";
        }
      }

      #Alter Authority (OAALT)
      unless ($b_alt_auth eq $a_alt_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Alter Authority (OAALT): $b_alt_auth\n";
          $current_str  .= "Alter Authority (OAALT): $a_alt_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Alter Authority (OAALT): $b_alt_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Alter Authority (OAALT): $a_alt_auth\n";
        }
      }

      #Reference Authority (OAREF)
      unless ($b_ref_auth eq $a_ref_auth)
      {
        if ( $change_type eq "Change" )
        {
          $previous_str .= "Reference Authority (OAREF): $b_ref_auth\n";
          $current_str  .= "Reference Authority (OAREF): $a_ref_auth\n";
        }
        elsif ( $change_type eq "Removal" )
        {
          $previous_str .= "Reference Authority (OAREF): $b_ref_auth\n";
        }
        elsif ( $change_type eq "Addition" )
        {
          $current_str  .= "Reference Authority (OAREF): $a_ref_auth\n";
        }
      }

      #write row
      IAD::XL::write_row($obj,$id,$previous_str,$current_str,$change_type);

      #release memory
      $before = 0;
      $after  = 0;
      $change_type = "";
      $previous_str = "";
      $current_str = "";

      #before temp vars
      $b_obj_auth = "";
      $b_op_auth = "";
      $b_mgt_auth = "";
      $b_exs_auth = "";
      $b_read_auth = "";
      $b_add_auth = "";
      $b_upd_auth = "";
      $b_del_auth = "";
      $b_amgt_auth = "";
      $b_anam_list = "";
      $b_lib = "";
      $b_obj_type = "";
      $b_obj_owner = "";
      $b_primary_grp = "";
      $b_group = "";
      $b_exec_auth = "";
      $b_alt_auth = "";
      $b_ref_auth = "";

      #after temp vars
      $a_obj_auth = "";
      $a_op_auth = "";
      $a_mgt_auth = "";
      $a_exs_auth = "";
      $a_read_auth = "";
      $a_add_auth = "";
      $a_upd_auth = "";
      $a_del_auth = "";
      $a_amgt_auth = "";
      $a_anam_list = "";
      $a_lib = "";
      $a_obj_type = "";
      $a_obj_owner = "";
      $a_primary_grp = "";
      $a_group = "";
      $a_exec_auth = "";
      $a_alt_auth = "";
      $a_ref_auth = "";

    } #end $id for()
  } #end $obj for()

  #----------------------------------
  # Output - Default Password Changes
  #----------------------------------
  IAD::XL::add_sheet("Default Password Changes");
  IAD::XL::add_header("Default Pwd Chgs [$preD_str to $postD_str]","AccountID","Previous","Current","Type");
  $before = 0;
  $after  = 0;
  $change_type  = "";

  #before temp vars
  my $b_pwd_exp_before = "";
  my $b_pwd_exp_after  = "";
  $b_name              = "";
  my $b_status_before  = "";
  my $b_status_after   = "";

  #after temp vars
  my $a_pwd_exp_before = "";
  my $a_pwd_exp_after  = "";
  $a_name              = "";
  my $a_status_before  = "";
  my $a_status_after   = "";

  for my $id (sort keys %dftpwd)
  {
    for my $cb (sort keys %{ $dftpwd{$id} })
    {
      if ($cb eq $onlya)
      {
        $before = 1;
        $b_pwd_exp_before = $dftpwd{$id}->{$cb}->{pwd_exp_before};
        $b_pwd_exp_after  = $dftpwd{$id}->{$cb}->{pwd_exp_after};
        $b_name           = $dftpwd{$id}->{$cb}->{name};
        $b_status_before  = $dftpwd{$id}->{$cb}->{status_before};
        $b_status_after   = $dftpwd{$id}->{$cb}->{status_after};
      }

      if ($cb eq $onlyb)
      {
        $after  = 1;
        $a_pwd_exp_before = $dftpwd{$id}->{$cb}->{pwd_exp_before};
        $a_pwd_exp_after  = $dftpwd{$id}->{$cb}->{pwd_exp_after};
        $a_name = $dftpwd{$id}->{$cb}->{name};
        $a_status_before = $dftpwd{$id}->{$cb}->{status_before};
        $a_status_after = $dftpwd{$id}->{$cb}->{status_after};
      }
    } #end cb for()

    #determine change type
    if ($before && $after)
    {
      $change_type = "Change";
    }
    elsif ($before && ! $after)
    {
      $change_type = "Removal";
    }
    elsif (! $before && $after)
    {
      $change_type = "Addition";
    }

    #determine what changed
    #Text Description (DFPTXT)
    unless ($b_name eq $a_name)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Name (DFPTXT): $b_name\n";
        $current_str  .= "Name (DFPTXT): $a_name\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Name (DFPTXT): $b_name\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Name (DFPTXT): $a_name\n";
      }
    }

    #PWDEXP Before Action (DFPEXB)
    unless ($b_pwd_exp_before eq $a_pwd_exp_before)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "PWDEXP Before Action (DFPEXB): $b_pwd_exp_before\n";
        $current_str  .= "PWDEXP Before Action (DFPEXB): $a_pwd_exp_before\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "PWDEXP Before Action (DFPEXB): $b_pwd_exp_before\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "PWDEXP Before Action (DFPEXB): $a_pwd_exp_before\n";
      }
    }

    #PWDEXP After Action (DFPEXA)
    unless ($b_pwd_exp_after eq $a_pwd_exp_after)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "PWDEXP After Action (DFPEXA): $b_pwd_exp_after\n";
        $current_str  .= "PWDEXP After Action (DFPEXA): $a_pwd_exp_after\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "PWDEXP After Action (DFPEXA): $b_pwd_exp_after\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "PWDEXP After Action (DFPEXA): $a_pwd_exp_after\n";
      }
    }

    #Status Before Action (DFSTAB)
    unless ($b_status_before eq $a_status_before)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Status Before Action (DFSTAB): $b_status_before\n";
        $current_str  .= "Status Before Action (DFSTAB): $a_status_before\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Status Before Action (DFSTAB): $b_status_before\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Status Before Action (DFSTAB): $a_status_before\n";
      }
    }

    #Status After Action (DFSTAA)
    unless ($b_status_after eq $a_status_after)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Status After Action (DFSTAA): $b_status_after\n";
        $current_str  .= "Status After Action (DFSTAA): $a_status_after\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Status After Action (DFSTAA): $b_status_after\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Status After Action (DFSTAA): $a_status_after\n";
      }
    }

    #write row
    IAD::XL::write_row($id,$previous_str,$current_str,$change_type);

    #release memory
    $before = 0;
    $after  = 0;
    $change_type = "";

    #before temp vars
    $b_pwd_exp_before = "";
    $b_pwd_exp_after  = "";
    $b_name           = "";
    $b_status_after   = "";

    #after temp vars
    $a_pwd_exp_before = "";
    $a_pwd_exp_after  = "";
    $a_name           = "";
    $a_status_after   = "";

  } #end $id for()

  #------------------------------
  # Output - System Value Changes
  #------------------------------
  IAD::XL::add_sheet("System Value Changes");
  IAD::XL::add_header("Sys Val Chgs [$preD_str to $postD_str]","SysVal","Previous","Current","Type");
  $before = 0;
  $after  = 0;
  $change_type  = "";
  $previous_str = "";
  $current_str = "";

  #before temp vars
  my $b_sv_val  = "";
  my $b_sv_desc = "";
  
  #after temp vars
  my $a_sv_val  = "";
  my $a_sv_desc = "";

  for my $sv_name (sort keys %sv)
  {
    for my $cb (sort keys %{ $sv{$sv_name} })
    {
      if ($cb eq $onlya)
      {
        $before = 1;
        $b_sv_val  = $sv{$sv_name}->{$cb}->{value};
        $b_sv_desc = $sv{$sv_name}->{$cb}->{desc};
      }

      if ($cb eq $onlyb)
      {
        $after  = 1;
        $a_sv_val  = $sv{$sv_name}->{$cb}->{value};
        $a_sv_desc = $sv{$sv_name}->{$cb}->{desc};
      }
    } #end cb for()

    #determine change type
    if ($before && $after)
    {
      $change_type = "Change";
    }
    elsif ($before && ! $after)
    {
      $change_type = "Removal";
    }
    elsif (! $before && $after)
    {
      $change_type = "Addition";
    }

    #determine what changed
    #System Value Setting
    unless ($b_sv_val eq $a_sv_val)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Setting: $b_sv_val\n";
        $current_str  .= "Setting: $a_sv_val\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Setting: $b_sv_val\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Setting: $a_sv_val\n";
      }
    }
    
    #System Value Description
    unless ($b_sv_desc eq $a_sv_desc)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Description: $b_sv_desc\n";
        $current_str  .= "Description: $a_sv_val\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Description: $b_sv_desc\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Description: $a_sv_desc\n";
      }
    }

    #write row
    IAD::XL::write_row($sv_name,$previous_str,$current_str,$change_type);

    #release memory
    $before = 0;
    $after  = 0;
    $change_type = "";
    $previous_str = "";
    $current_str = "";

    #before temp vars
    $b_sv_val  = "";
    $b_sv_desc = "";

    #after temp vars
    $a_sv_val  = "";
    $a_sv_desc = "";
  } #end $sv_name for()

  #----------------------------------
  # Output - Group Membership Changes
  #----------------------------------
  IAD::XL::add_sheet("User Profile Ownership Changes");
  IAD::XL::add_header("Profile Owner Chgs [$preD_str to $postD_str]","ID","Previous","Current","Type");
  $before = 0;
  $after  = 0;
  $change_type  = "";
  $previous_str = "";
  $current_str = "";

  #before temp vars
  my $b_owner = "";
  my $b_creation_date = "";

  #after temp vars
  my $a_owner = "";
  my $a_creation_date = "";

  for my $id (sort keys %owners)
  {
    for my $cb (sort keys %{ $owners{$id} })
    {
      if ($cb eq $onlya)
      {
        $before = 1;
        $b_owner = $owners{$id}->{$cb}->{owner};
        $b_creation_date = $owners{$id}->{$cb}->{creation_date};
      }

      if ($cb eq $onlyb)
      {
        $after  = 1;
        $a_owner = $owners{$id}->{$cb}->{owner};
        $a_creation_date = $owners{$id}->{$cb}->{creation_date};
      }
    } #end cb for()

    #determine change type
    if ($before && $after)
    {
      $change_type = "Change";
    }
    elsif ($before && ! $after)
    {
      $change_type = "Removal";
    }
    elsif (! $before && $after)
    {
      $change_type = "Addition";
    }

    #determine what changed
    #Owner
    unless ($b_owner eq $a_owner)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Owner: $b_owner\n";
        $current_str  .= "Owner: $a_owner\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Owner: $b_owner\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Owner: $a_owner\n";
      }
    }

    #Creation Date
    unless ($b_creation_date eq $a_creation_date)
    {
      if ( $change_type eq "Change" )
      {
        $previous_str .= "Creation Date: $b_creation_date\n";
        $current_str  .= "Creation Date: $a_creation_date\n";
      }
      elsif ( $change_type eq "Removal" )
      {
        $previous_str .= "Creation Date: $b_creation_date\n";
      }
      elsif ( $change_type eq "Addition" )
      {
        $current_str  .= "Creation Date: $a_creation_date\n";
      }
    }

    #write row
    IAD::XL::write_row($id,$previous_str,$current_str,$change_type);

    #release memory
    $before = 0;
    $after  = 0;
    $change_type = "";
    $previous_str = "";
    $current_str = "";
    
    #before temp vars
    $b_owner = "";
    $b_creation_date = "";

    #after temp vars
    $a_owner = "";
    $a_creation_date = "";

  } #end $id for()

  #----------
  # Finish Up
  #----------
  IAD::XL::end_formatting;
  IAD::XL::exit_xl($xl_filename);
  print "\n";
  print "Saved diff file to: $xl_filename\n";

} #end diff()

#=============
# Return value
#=============
return 1;