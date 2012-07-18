#!perl -w

use strict;
use la2_enc_dec;
use Data::Dumper;


#my $file = q[itemname-ru.dat];
#my $file = q[l2.ini];
#my $file = q[l2.ini-dec-enc];
#my $OUT = la2_decode("TEST/$file");


my $file = q[itemname-ru.dat-dec];
#my $file = q[dec-l2.ini];
my $OUT = la2_encode("TEST/$file");
