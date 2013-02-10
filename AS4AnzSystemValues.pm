package AS4AnzSystemValues;
require Exporter;

use strict;
use warnings;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($sheet_name analyze);

#=================
# Global Variables
#=================
our $sheet_name = "SV.All";

#================
# Local Variables
#================
my $cur;         #string for current setting
my $rec;         #string for recommended setting
my @cs;          #array for current settings
my @rs;          #array for recommended settings
my $cstr;        #hold current settings string
my $rstr;        #hold recommended settings string
my $desc;        #hold description for system value
my $exception;   #flag for exceptions
my @row;         #hold row data for writing to W/P
my $purpose;     #ppc
my $procedure;   # |
my $domain;      # |
my $reference;   # v

#======================
# Analyze system values
#======================
sub analyze
{
  #add w/p
  AS4XL::add_sheet($sheet_name);

  #add title and column headings
  AS4XL::add_header("System Values","Name","Current","Recommended","Descrition");

  #add ppc to audit program
  $purpose   = "To ensure that the iSeries system values are set appropriately.  " .
               "See the System Values documentation for additional details.";

  $procedure = "Run the PRTSYSSECA command.  This will create a spool file " .
               "of the security related system values.  Next, print this out. " .
               "and cross reference the settings in the 'Current value' " .
               "column with the IAD recommended settings.  Note any discrepencies.";

  $domain    = "System Values";
  $reference = $sheet_name;
  AS4XL::add_ppc($purpose,$domain,$procedure,$reference);

  for my $name (sort keys %AS4Data::sv)
  {
   if ($AS4Data::sv{$name}->{array})
   {
     #array - get values
     @cs   = @{ $AS4Data::sv{$name}->{current} };
     @rs   = @{ $AS4Data::sv{$name}->{recommended} };
     $desc = $AS4Data::sv{$name}->{description};
     $exception = $AS4Data::sv{$name}->{exception};

     #form an output string
     $cstr = "";
     $rstr = "";
     for my $val (@cs)
     {
       $cstr .= "$val\n";
     }

     for my $val (@rs)
     {
       $rstr .= "$val\n";
     }

     @row = ($name,$cstr,$rstr,$desc);
     AS4XL::write_row(@row);
     if ($exception) { AS4XL::highlight(AS4XL::get_row(),'yellow') }
   }
   else
   {
    #not an array
    $cur  = $AS4Data::sv{$name}->{current};
    $rec  = $AS4Data::sv{$name}->{recommended};
    $desc = $AS4Data::sv{$name}->{description};
    $exception = $AS4Data::sv{$name}->{exception};

    #check for exceptions
    unless ($cur eq $rec) { $exception = 1 }
    @row = ($name,$cur,$rec,$desc);
    AS4XL::write_row(@row);
    if ($exception) { AS4XL::highlight(AS4XL::get_row(),'yellow') }
   } #end array if()
  } #end name for()

  #add legend
  AS4XL::add_legend("yellow|Current != Recommended");

  #link to audit program
  AS4XL::add_ap_link($sheet_name);
}

#=============
# Return value
#=============
return 1;