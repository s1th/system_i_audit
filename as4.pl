#================================
# .:: AS400 Audit Script ::.
#
# Type as4.pl -h to see the help
#================================
use strict;
use warnings;

#modules
use AS4AnzObjectAuthority;
use AS4AnzProfiles_AttnKey;
use AS4AnzProfiles_DftPwd;
use AS4AnzProfiles_Generic;
use AS4AnzProfiles_Groups;
use AS4AnzProfiles_Groups2;
use AS4AnzProfiles_LastSignOn;
use AS4AnzProfiles_LimCap;
use AS4AnzProfiles_Owner;
use AS4AnzProfiles_PwdExpInt;
use AS4AnzProfiles_Q;
use AS4AnzProfiles_Quota;
use AS4AnzProfiles_Sessions;
use AS4AnzProfiles_SpecAuth;
use AS4AnzProfiles_SpecAuth2;
use AS4AnzProfiles_EmpStat;
use AS4AnzSystemValues;
use AS4Conf;
use AS4Data;
use AS4Diff;
use Cwd;
use Date::Calc qw(:all);
use Getopt::Long;
use Win32::OLE;
use Win32::Service;
use AS4XL;

#export global variables
our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($conn $cmd $rs $rpt $ip $id $pass $bdir $adir $ddir $ts $logd $datad $rptd $cwdd $ninety_days_ago);

#=================
# Global Variables
#=================
our $conn = Win32::OLE->new('ADODB.Connection');  #connection object
our $cmd  = Win32::OLE->new('ADODB.Command');     #command object
our $rs   = Win32::OLE->new('ADODB.Recordset');   #record set object
our $rpt;                                         #report type to process
our $ip;                                          #ip address of server
our $id;                                          #user id to log into server
our $pass;                                        #password to log into server
our $snap1;                                       #before directory - used for diff
our $snap2;                                       #after directory  - used for diff
our $ddir;                                        #data directory
our $ts;                                          #time stamp
our $logd;                                        #log directory
our $chgd;                                        #changes log file directory
our $datad;                                       #data log file directory
our $rptd;                                        #report output directory
our $cwdd;                                        #current working directory - store top lvl as4 dir here
our $ninety_days_ago;                             #90 days ago - use for some last sign-on checks, etc.

#================
# Local Variables
#================
my %opts;     #command line options
my $filename; #xl filename to save report to
my %status;   #use for checkpoint killing

#===============================
# Process Command Line Arguments
#===============================
my $cl_result = GetOptions (\%opts,'s=s','u=s','p=s','run=s','kill-chkpt','h');

#print usage if no parameters passed
my @keys = keys %opts;
unless (@keys)
{
  usage();
}

#print usage if -h (help) parameter is passed
if ($opts{'h'})
{
  usage();
}

#report type error check
unless ($opts{'run'} && ($opts{'run'} eq "report" || $opts{'run'} eq "diff") )
{
  print "Please specify a run type (either 'report' or 'diff')...this is required.","\n";
  print "\n";
  print "For help: cmd> as4.pl -h","\n";
  exit;
}

#make sure an ip address is passed regardless of report
unless ($opts{'s'})
{
  print "Please specify the IP address of the server you're analyzing...\n";
  print "Even if you're doing a 'diff' report.  Type 'as4.pl -h'\n";
  print "for more info.\n";
  exit;
}

#normal report run error checks
if ($opts{'run'} eq "report")
{
  #normal run, check that a server, username and password was passed
  unless ( $opts{'s'} && $opts{'u'} && $opts{'p'} )
  {
    print "For a normal report run you must specify an ip address ","\n";
    print "of the server (-s), username (-u) and password (-p).","\n";
    print "For example:\n";
    print "  as4.pl -s 192.168.2.22 -u xyz -p mypass --run report","\n","\n";;
    print "Please try again...or for more help enter: as4.pl -h","\n";
    exit;
  }
}

#save options passed in global vars
$ip   = $opts{'s'};
$rpt  = $opts{'run'};
$id   = $opts{'u'};
$pass = $opts{'p'};

#========================
# Preliminary Setup Stuff
#========================
#get timestamp
my($sec,$min,$hr,$day,$mon,$yr,$wkday,$dayofyr,$isdst) = localtime(time);
$mon += 1;
$yr += 1900;
$ts = "$mon" . "." . "$day" . "." . "$yr" . "." . "$hr" . "." . "$min" . "." . "$sec";
my $as4str = "as4." . $ts . "_" . $ip;

#get current working directory
$cwdd = getcwd();
$cwdd =~ s/\//\\/g;   #fix up for windows horseshit
#fix trailing slash issue
if ( substr($cwdd,-1,1) eq "\\")
{
  substr($cwdd,-1,1) = '';
}

$cwdd = $cwdd . "\\" . $as4str;
$datad = $cwdd . "\\data";
$logd = $cwdd . "\\log";
$rptd = $cwdd . "\\rpt";
mkdir($cwdd);
mkdir($datad);
mkdir($logd);
mkdir($rptd);

#get 90 days ago
my($nago_yr,$nago_mon,$nago_day) = Add_Delta_Days($yr,$mon,$day,-90);
my $new_nago_yr = substr($nago_yr,2,2);
$ninety_days_ago = Date_to_Days($new_nago_yr,$nago_mon,$nago_day);

#======================================================
# Open log file to track all errors, fatal or otherwise
#======================================================
my $logf = "$logd\\" . $ts . "_" . $ip . "_" . "log.txt";
open LOG, ">$logf"
     or die "Can't open the log file: $!\n";

#==================
# MAIN - Audit Work
#==================
my($rv,$err);   #return value for functions and error string if there's an error

#kill checkpoint if requested
if ($opts{'kill-chkpt'})
{
  kill_checkpoint();
}

#get configuration information
($rv,$err) = AS4Conf::get_conf;
unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
else         { print LOG "*** AS4Conf::get_conf() call successful ***\n"; }

#do processing based on report type
if ($rpt eq "report")
{
  #a normal report

  #---Data Retrieval---#
  #establish connection to server
  ($rv,$err) = AS4Data::online_connect;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::online_connect() call successful ***\n"; }

  #retrieve system values
  ($rv,$err) = AS4Data::online_get_system_values;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::online_get_system_values() call successful ***\n"; }

  #retrieve user profile data
  ($rv,$err) = AS4Data::online_get_user_profile_data;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::online_get_user_profile_data() call successful ***\n"; }

  #retrieve additional user profile data - this MUST be called after the AS4Data::online_get_user_profile_data()
  ($rv,$err) = AS4Data::online_get_usrprf_obj_data;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::online_get_usrprf_obj_data() call successful ***\n"; }

  #analyze default passwords
  ($rv,$err) = AS4Data::online_analyze_dft_pwd;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::online_analyze_dft_pwd() call successful ***\n"; }

  #get object authority data
  ($rv,$err) = AS4Data::online_get_objaut;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::online_get_objaut() call successful ***\n"; }

  #get hr information
  #($rv,$err) = AS4Data::get_hr_info;
  #unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  #else         { print LOG "*** AS4Data::get_hr_data() call successful ***\n"; }

  #disconnect from server
  ($rv,$err) = AS4Data::online_disconnect;
  unless ($rv) { print "Error occurred, check $logf\n\n"; print LOG "XXX\n$err\nXXX"; exit; }
  else         { print LOG "*** AS4Data::disconnect() call successful ***\n"; }

  #---Analysis and XL work---#
  AS4XL::init_xl;

  #system values analysis
  AS4AnzSystemValues::analyze;

  #user profile analysis
  AS4AnzProfiles_Q::analyze;
  AS4AnzProfiles_Owner::analyze;
  AS4AnzProfiles_LimCap::analyze;
  AS4AnzProfiles_Generic::analyze;
  AS4AnzProfiles_PwdExpInt::analyze;
  AS4AnzProfiles_SpecAuth::analyze;
  AS4AnzProfiles_SpecAuth2::analyze;
  AS4AnzProfiles_LastSignOn::analyze;
  AS4AnzProfiles_DftPwd::analyze;
  AS4AnzProfiles_Sessions::analyze;
  AS4AnzProfiles_Quota::analyze;
  AS4AnzProfiles_AttnKey::analyze;
  #AS4AnzProfiles_EmpStat::analyze;

  #groups analysis
  AS4AnzProfiles_Groups::analyze;
  AS4AnzProfiles_Groups2::analyze;

  #object authority analysis
  AS4AnzObjectAuthority::analyze;

  AS4XL::end_formatting;
  $filename = $rptd . "\\as4.rpt." . $ts . "_" . $ip . ".xls";
  AS4XL::exit_xl($filename);
}
elsif ($rpt eq "diff")
{
  print "Enter the PRE run directory: ";
  chomp($snap1 = <STDIN>);
  print "\n";
  print "Enter the POST run directory: ";
  chomp($snap2 = <STDIN>);
  print "\n";

  AS4Diff::diff($snap1,$snap2);


}
else
{
  print "Error occurred, check $logf\n";
  print LOG "Error in processing report type: $rpt\n";
  exit;
}

#restart checkpoint if it was killed
if ($opts{'kill-chkpt'})
{
  restart_checkpoint();
}



#===========================================
# Checkpoint Kill - stop checkpoint services
#===========================================
sub kill_checkpoint
{
  Win32::Service::GetStatus('','SR_Service',\%status);
  if ($status{CurrentState} == 1)
  {
    print "'Check Point SecuRemote' service is not running...schweet!\n";
  }
  else
  {
    Win32::Service::StopService('','SR_Service') ||
       die "I can't stop the 'Check Point SecuRemote' service...do you have Administrator rights? If not, then get them (one way or the other).\n";
    print "'Check Point SecuRemote' service stopped...\n";
  }

  Win32::Service::GetStatus('','SR_WatchDog',\%status);
  if ($status{CurrentState} == 1)
  {
    print "'Check Point WatchDog' service is not running...schweet!\n";
  }
  else
  {
    Win32::Service::StopService('','SR_WatchDog') ||
       die "I can't stop the 'Check Point WatchDog' service...do you have Administrator rights? If not, then get them (one way or the other).\n";
    print "'Check Point WatchDog' service stopped...\n";
  }
}

#=============================
# Restart check point services
#=============================
sub restart_checkpoint
{
  Win32::Service::StartService('','SR_Service');
  Win32::Service::StartService('','SR_WatchDog');
  print "'Check Point SecuRemote' service restarted...\n";
  print "'Check Point WatchDog' service restarted...\n";
}

#======
# Usage
#======
sub usage
{
  print "as4.pl [-s IP] [-u username] [-p password]","\n";
  print "       [--run [report|diff]] [--kill-chkpt] [-h]","\n";
  print "\n";
  print "-s            IP Address of AS400 server to be analyzed.","\n";
  print "              This is a required parameter, even if doing a ","\n";
  print "              diff report as it is used in some file naming ","\n";
  print "              conventions.","\n";
  print "\n";
  print "-u            Username to use to log into the AS400.","\n";
  print "\n";
  print "-p            Password to use to log into the AS400.","\n";
  print "\n";
  print "--run         The type of run the script should perform.","\n";
  print "              This is ALWAYS a required parameter, and is either ","\n";
  print "              'report' for a normal report run or a 'diff' for a ","\n";
  print "              diff of two previous runs.","\n";
  print "\n";
  print "--kill-chkpt  Specify this option to have the script kill ","\n";
  print "              the checkpoint services.  Generally this ","\n";
  print "              should not be required, but may be at SMWE.","\n";
  print "\n";
  print "-h            Print this help.","\n";
  print "\n";
  print "Example Sessions:","\n";
  print "|-----------------------------------------------------------|","\n";
  print "| cmd> as4.pl -s 192.168.1.24 -u xyz -p mypwd --run report  |","\n";
  print "|-----------------------------------------------------------|","\n";
  print "  *This will perform a normal audit of the server at 192.168.1.24.","\n";
  print "   It will log in with the username and password specified with -u ","\n";
  print "   and -p.  Note that this will use the network to run commands ","\n";
  print "   on the server and extract the necessary data to perform the ","\n";
  print "   audit.","\n";
  print "\n";
  print "|------------------------------------------------------|","\n";
  print "| cmd> as4.pl -s 182.43.45.66 --run diff               |","\n";
  print "|                                                      |","\n";
  print "| Enter the PRE run directory: c:\\pre\\run\\directory    |","\n";
  print "|                                                      |","\n";
  print "| Enter the POST run directory: c:\\post\\run\\directory  |","\n";
  print "|------------------------------------------------------|","\n";
  print "  *This will perform a diff of two previous runs log files. ","\n";
  print "   All that required is to specify the path the previous runs ","\n";
  print "   top-level directory (i.e. the as4.1.1.2007.6.6.6 directory).","\n";
  print "\n";
  exit;
} #end usage()
