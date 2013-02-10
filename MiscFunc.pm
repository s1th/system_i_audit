package MiscFunc;
require Exporter;

use strict;
use warnings;
use Cwd;
use Date::Calc qw(:all);
use Text::Levenshtein qw(fastdistance);

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw();

#=================
# Global Variables
#=================

#================
# Local Variables
#================



#================
# Get a timestamp
#================
sub get_timestamp
{
  my($sec,$min,$hr,$day,$mon,$yr,$wkday,$dayofyr,$isdst) = localtime(time);
  $mon += 1;
  $yr += 1900;
  my $ts = "$mon" . "." . "$day" . "." . "$yr" . "." . "$hr" . "." . "$min" . "." . "$sec";
  return $ts;
}

#==============================
# Get current working directory
#==============================
sub get_cwd
{
  my $cwdd = getcwd();
  $cwdd =~ s/\//\\/g;   #fix up for windows horseshit
  #fix trailing slash issue
  if ( substr($cwdd,-1,1) eq "\\")
  {
    substr($cwdd,-1,1) = '';
  }

  return $cwdd;
}

#================
# Get 90 days ago
#================
sub days_ago_90
{
  my($sec,$min,$hr,$day,$mon,$yr,$wkday,$dayofyr,$isdst) = localtime(time);
  $mon += 1;
  $yr += 1900;
  my($nago_yr,$nago_mon,$nago_day) = Add_Delta_Days($yr,$mon,$day,-90);
  my $new_nago_yr = substr($nago_yr,2,2);
  my $ninety_days_ago = Date_to_Days($new_nago_yr,$nago_mon,$nago_day);
  return $ninety_days_ago;
}

#==============================================================
# Trim leading and trailing whitespace characters from a string
#==============================================================
sub trim
{
	my($str) = @_;
	$str =~ s/^\s+//;
	$str =~ s/\s+$//;
	return $str;
}

#===================================
# Trim leading whitespace characters
#===================================
sub ltrim
{
	my($str) = @_;
	$str =~ s/^\s+//;
	return $str;
}

#====================================
# Trim trailing whitespace characters
#====================================
sub rtrim
{
	my($str) = @_;
	$str =~ s/\s+$//;
	return $str;
}


#=============
# Return value
#=============
return 1;