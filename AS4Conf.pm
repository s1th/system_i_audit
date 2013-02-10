#======================================================
#               .: AS4Conf Module :.
#
# This module parses the 'as4.conf' configuration file
# and stores the configuration details in the '%conf'
# hash.  This configuration file must be stored
# in the same location as the script, or you will
# get an error that it can't find the file.
#======================================================
package AS4Conf;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw(%conf);

#=================
# Global Variables
#=================
our %conf;  #hold all configuration information

#================
# Local Variables
#================
my $line;  #hold each line of configuratio file
my @cs;    #array to hold system values with multiple values

#==================================
# Open and parse configuration file
#==================================
sub get_conf
{
  open CONF, "as4.conf"
       or return(0,"Fatal error in AS4Conf::get_conf -->\n\n***Can't open the as4.conf configuration file: $!***\n");

  while (<CONF>)
  {
    chomp;
    $line = $_;

    #skip comments and blanks
    if ( $line =~ /^#.*/ || $line =~ /^(\s)*$/ )
    {
      next;
    }

    my($p1,$p2,$p3,$p4) = split /\|/, $line;
    if ($p1 eq "AS400")
    {
      #AS400 configuration settings
      # ip_address --> AS400 --> configuration_area = configuration_setting
      $conf{$p3}->{$p1}->{$p2} = $p4;
    }
    elsif ($p1 eq "OBJAUT")
    {
      #object authority section
      # ip_address --> OBJAUT --> object = object_type
      $conf{$p2}->{$p1}->{$p3} = $p4;
    }
    elsif ($p1 eq "SV")
    {
      #recommended system values section
      # ip_address --> SV --> system_value --> {value} = recommended_setting
      $conf{$p2}->{$p1}->{$p3}->{value} = $p4;
    }
    elsif ($p1 eq "QIBM")
    {
      #IBM suppied user profiles
      # ip_address --> QIBM --> q_user_profile = 1
      $conf{$p2}->{$p1}->{$p3} = 1;
    }
    elsif ($p1 eq "HR")
    {
      #HR file produced by the hr_shuffle.pl script
      $conf{$p2}->{$p1}->{value} = $p3;
    }
    elsif ($p1 eq "CLLINK")
    {
      #CL commands website link
      $conf{$p1} = $p2;
    }
  } #<CONF>

  return 1;
} #end get_conf()

#===========================================
# Debug sub for error checking - dumps %conf
#===========================================
sub debug
{
  #print %conf to STDOUT
  print "===== Dump of %conf hash =====","\n";
  for my $k1 (sort keys %conf)
  {
    for my $k2 (sort keys %{ $conf{$k1} })
    {
      for my $k3 (sort keys %{ $conf{$k1}->{$k2} })
      {
        print "$k1 --> $k2 --> $k3 --> ";
        if ($k2 eq "SV")
        {
          for my $k4 (sort keys %{ $conf{$k1}->{$k2}->{$k3} })
          {
            print " $k4 --> $conf{$k1}->{$k2}->{$k3}->{$k4}","\n";
          }
        }
        else
        {
          print " $conf{$k1}->{$k2}->{$k3}\n";
        }
      }
    }
  }
} #end debug()

#=============
# Return value
#=============
1;
