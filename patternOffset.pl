sub PatternOffset {
     my $pattern = shift;
     my $address = shift;
     my $endian = @_ ? shift() : 'V';
     my @results;
     my ($idx, $lst) = (0,0);
     $address = pack($endian, hex($address));
     $idx = index($pattern, $address, $lst);
     while ($idx > 0)
     {
          push @results, $idx;
          $lst = $idx + 1;
          $idx = index($pattern, $address, $lst);
     }
     return @results;
}