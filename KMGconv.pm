package KMGconv;
%mult =(
  B=>1,
  kB=>1024,
  MB=>1024*1024,
  GB=>1024*1024*1024,
  TB=>1024*1024*1024*1024,
  );

sub  convert{
  my($from, $to, $amount)=@_;
  return $amount*$mult{$from}/$mult{$to};
}

#-------------------------
#example to use
#use KMGconv;
#
#print KMGconv::convert(MB,kB, 12);

