package AS4XL;
require Exporter;

use strict;
use warnings;
use Win32::OLE qw(in valof with);
use Win32::OLE::Const 'Microsoft Excel';
$Win32::OLE::Warn = 0;

our (@ISA, @EXPORT);
@ISA = qw(Exporter);
@EXPORT= qw($xl $bk $sh $ap_sh init_xl exit_xl add_sheet add_header write_row get_row highlight);

#=================
# Global Variables
#=================
our $xl;      #xl application instance
our $bk;      #xl workbook instance
our $sh;      #xl worksheet instance
our $ap_sh;   #xl audit program sheet

#================
# Local Variables
#================
my $filename;    #name of report file
my $offset;      #column letter of last column for row/header
my @row;         #hold values to write in an excel row
my @xlcol = ("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P",
             "Q","R","S","T","U","V","W","X","Y","Z","AA","AB","AC","AD","AE",
             "AF","AG","AH","AI","AJ","AK","AL","AM","AN","AO","AP","AQ",
             "AR","AS","AT","AU","AV","AW","AX","AY","AZ");
my $rg;          #xl range instance
my $ppc_cnt = 0; #total number of ppcs processed
my $ap_row;      #audit program worksheet's current row
my $linkrg;      #range for hyperlinks
my $display;     #display for hyperlinks
my $popup;       #popup for hyperlinks
my $fit_sh;      #link to sheet for autofitting columns
my $sh_row;      #current row in current sheet

#colors
my $yellow = 6;

#===========================
# Instantiate an XL instance
#===========================
sub init_xl
{
  $xl = Win32::OLE->new('Excel.Application', 'Quit')
      or return(0,"Error in init_xl -->\n***" . Win32::LastError() / "***\n");
  $xl->{DisplayAlerts}=0;
  $xl->{SheetsInNewWorkbook}=1;
  $bk = $xl->Workbooks->Add
      or return(0,"Error in init_xl -->\n***" . Win32::LastError() / "***\n");
  $ap_sh = $bk->Worksheets(1);
  $ap_sh->{Name} = "Audit Program";
  $sh = $ap_sh; #link $sh to audit program sheet to use the add_header function
  add_header("iSeries Audit Program","No.","Control Domain","Purpose","Procedure","Conclusion","Reference");
  $ap_row = 5;  #set starting row on audit program sheet
}

#======================
# Exit xl and save file
#======================
sub exit_xl
{
  my($filename) = @_;

  #save workbook
  $bk->SaveAS($filename);
  $bk->Close;
}

#==============================
# Add a worksheet
#
# called: add_sheet(sheet_name)
#==============================
sub add_sheet
{
  #one arg passed - string for sheet's name
  my($sheetname) = @_;
  $sh = $bk->Worksheets->Add({After=>$bk->Worksheets($bk->Worksheets->{Count})})
      or die Win32::OLE->LastError();
  $sh->{Name} = $sheetname;
}

#===============================================================================================
# Header of work paper - title and column headings
#
# called: add_header(title_of_work_paper,column_heading_1,column_heading_2,...,column_heading_N)
#===============================================================================================
sub add_header
{
  my($title,@cols) = @_;
  $offset = $xlcol[$#cols];

  for my $col (@cols)
  {
    push @row, $col;
  }

  #title
  $sh->Range("A1")->{Value} = $title;
  $sh->Range("A1")->Font->{Bold} = 1;
  $sh->Range("A1")->Font->{Size} = 16;
  $sh->Range("A1:" . $offset . "2")->Merge();
  $sh->Range("A1")->{HorizontalAlignment} = xlCenter;

  #resize divider row
  $sh->Rows("3:3")->{RowHeight} = 5.00;

  #column headings
  $sh->Range("A4:" . $offset . "4")->{Value} = \@row;
  $sh->Range("A4:" . $offset . "4")->Font->{Bold} = 1;
  $sh->Range("A4:" . $offset . "4")->{HorizontalAlignment} = xlCenter;
  $sh->Range("A4:" . $offset . "4")->Interior->{ColorIndex} = 48;
  set_borders($sh->Range("A4:" . $offset . "4"));

  #set initial row
  $sh_row = 4;

  #release memory
  @row = ();
}

#==================================================================
# Add a PPC to the Audit Program
#
# call: add_ppc(purpose,domain,procedure,worksheet name to link to)
#==================================================================
sub add_ppc
{
  my($purpose,$domain,$procedure,$link) = @_;

  $ppc_cnt++;   #increase the No. of ppcs processed

  $ap_sh->Range("A" . $ap_row)->{Value} = $ppc_cnt;
  $ap_sh->Range("B" . $ap_row)->{Value} = smooth($domain);
  $ap_sh->Range("C" . $ap_row)->{Value} = smooth($purpose);
  $ap_sh->Range("D" . $ap_row)->{Value} = smooth($procedure);

  #link to W/P
  $linkrg = $ap_sh->Range("F" . $ap_row);
  $display = $link;
  $popup = "Go to " . $link . " work paper";
  $ap_sh->Hyperlinks->Add({
  Anchor => $linkrg,
  Address => "",
  SubAddress => $link . "!A1",
  TextToDisplay => $display,
  ScreenTip => $popup,
  });
  
  $rg = $ap_sh->Range("A" . $ap_row . ":F" . $ap_row);
  set_borders($rg);
  
  #increment row
  $ap_row++;
}

#=======================================
# Write a row of data to worksheet
#
# call write_row(@row)
# Note - add_header must be called first
#        so that $offset is set
#=======================================
sub write_row
{
  #increment sheet's current row
  $sh_row++;

  my(@row) = @_;

  $sh->Range(sprintf "A%d:" . $offset . "%d",$sh_row,$sh_row)->{Value} = \@row;
  set_borders($sh->Range(sprintf "A%d:" . $offset . "%d",$sh_row,$sh_row));
}

#=================================
# Get current row of current sheet
#=================================
sub get_row
{
  return $sh_row;
}

#==============================
# Highlight a row a given color
#==============================
sub highlight
{
  my($row,$color) = @_;
  my($int) = undef;
  $color = lc($color);

  if ($color eq 'yellow')
  {
    $int = 6;
  }
  elsif ($color eq 'green')
  {
    $int = 4;
  }
  elsif ($color eq 'red')
  {
    $int = 3;
  }
  elsif ($color eq 'blue')
  {
    $int = 8;
  }  

  $sh->Range(sprintf "A%d:" . $offset . "%d",$row,$row)->Interior->{ColorIndex} = $int;
}

#=========================================
# Do any end formatting for excel workbook
#
# call end_formatting
#=============================
sub end_formatting
{
  for my $fit_sh (in $bk->{Worksheets})
  {
    $fit_sh->Columns("A:AZ")->{ColumnWidth} = 100.00;
    $fit_sh->Columns("A:AZ")->AutoFit();
    $fit_sh->Range("A5:AZ65536")->{VerticalAlignment} = xlTop;
    $fit_sh->Range("A5:AZ65536")->{HorizontalAlignment} = xlLeft;
    
    #special case for object authority sheet (OA.All)
    if ($fit_sh->{Name} eq "OA.All")
    {
      with ($fit_sh->PageSetup,
                     PrintTitleRows     => "4:4",
                     Orientation        => xlLandscape,
                     Zoom               => 65,);
    }
    else
    {
      with ($fit_sh->PageSetup,
                     PrintTitleRows     => "4:4",
                     Orientation        => xlLandscape,
                     Zoom               => 75,);
    }                 
  }
}

#===============================
# Link back to the Audit Program
#
# call add_ap_link(sheet_name)
#===============================
sub add_ap_link
{
  my($sheet_name) = @_;
  $sh_row += 2;

  #link to Audit Program
  $linkrg = $sh->Range(sprintf "A%d:A%d",$sh_row,$sh_row);
  $display = "Back to Audit Program";
  $popup = "Go to Audit Program worksheet";
  $sh->Hyperlinks->Add({
  Anchor => $linkrg,
  Address => "",
  SubAddress => "'Audit Program'!A1",
  TextToDisplay => $display,
  ScreenTip => $popup,
  });
  
  #merge link
  $sh->Range(sprintf "A%d:" . $offset . "%d",$sh_row,$sh_row)->Merge();
  $sh->Range(sprintf "A%d:" . $offset . "%d",$sh_row,$sh_row)->{HorizontalAlignment} = xlCenter;
  $sh->Range(sprintf "A%d:" . $offset . "%d",$sh_row,$sh_row)->{VerticalAlignment} = xlTop;
}

#==================================================================
# Create a legend for worksheet
#
# call add_legend("color1|Text1","color2|Text2",...,"colorN|TextN")
#
# Note - keep legend texts short, they will be used in the autofit
#        of columns at the end...so if it's really long it will 
#        look crapsta.
#==================================================================
sub add_legend
{
  my $int;

  $sh_row += 3;
  for my $row (@_)
  {
    my($color,$text) = split /\|/, $row;
    if ($color eq 'yellow')
    {
      $int = 6;
    }
    elsif ($color eq 'green')
    {
      $int = 4;
    }
    elsif ($color eq 'red')
    {
      $int = 3;
    }
    elsif ($color eq 'blue')
    {
      $int = 8;
    }

    #enter data
    $sh->Range(sprintf "A%d:A%d",$sh_row,$sh_row)->Interior->{ColorIndex} = $int;
    $sh->Range(sprintf "B%d:B%d",$sh_row,$sh_row)->{Value} = $text;
    $sh->Range(sprintf "A%d:B%d",$sh_row,$sh_row)->{HorizontalAlignment} = xlLeft;
    set_borders($sh->Range(sprintf "A%d:A%d",$sh_row,$sh_row));

    #increment row
    $sh_row++;

  } #end $row for()
}

#=================
# Borders function
#=================
sub set_borders
{
 #subroutine that accepts a range as an argument and sets the borders
 #around it
 my($range) = @_;
 $range->Borders(xlEdgeBottom)->{LineStyle}  = xlContinuous;
 $range->Borders(xlEdgeBottom)->{Weight}     = xlThin;
 $range->Borders(xlEdgeBottom)->{ColorIndex} = xlContinuous;
 $range->Borders(xlEdgeLeft)->{LineStyle}  = xlContinuous;
 $range->Borders(xlEdgeLeft)->{Weight}     = xlThin;
 $range->Borders(xlEdgeLeft)->{ColorIndex} = xlContinuous;
 $range->Borders(xlEdgeRight)->{LineStyle}  = xlContinuous;
 $range->Borders(xlEdgeRight)->{Weight}     = xlThin;
 $range->Borders(xlEdgeRight)->{ColorIndex} = xlContinuous;
 $range->Borders(xlEdgeTop)->{LineStyle}  = xlContinuous;
 $range->Borders(xlEdgeTop)->{Weight}     = xlThin;
 $range->Borders(xlEdgeTop)->{ColorIndex} = xlContinuous;
 $range->Borders(xlInsideHorizontal)->{LineStyle} = xlContinuous;
 $range->Borders(xlInsideVertical)->{LineStyle} = xlContinuous;
} #end set_borders()

#===============================================================
# Smoothing function to ensure that no
# purpose, procedure, or domain string is longer than 50
# characters in a cell.  This just makes the report look better.
#===============================================================
sub smooth
{
  my($str) = @_;
  my $char_cnt = 0;
  my $final_str;
  #split into letters
	my @letters = split //, $str;

  foreach my $char (@letters)
  {
    if ($char_cnt > 50)
    {
      #create a line - if its the end of a word
      if ($char =~ / / || $char =~ /\n/)
      {
        $final_str .= "\n";
        $char_cnt = 0;
      }
      else
      {
        $final_str .= $char;
      }
    }
    else
    {
      #add to buffer
      $final_str .= $char;
    }

    #increment character count
    $char_cnt++;
  }

  return $final_str;
}

#=============
# Return value
#=============
return 1;