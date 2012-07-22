 #
# L2 file decoder (18:33 14.07.2012).
# @author METAJIJI Kadyshev Denis
#

use warnings;
use Time::HiRes qw(gettimeofday);
use strict;
use Encode;		# use Encode qw(from_to);
#use MIME::Base64;	# encode_base64 () и decode_base64 () для кодирования и декодирования соответственно.
use Compress::Zlib qw(compress uncompress);
use Math::BigInt;
use Math::BigInt only => 'GMP';
use Data::Dumper;

my $original = 0;	# временно, в дальнейшем тут надо как-то сделать "прием этого значения"

my $t0 = gettimeofday;	#начали отсчет
print qq[\n========================= -------- Start -------- =========================\n];

# RSA keys:
my $priv_key	= q[0x30B4C2D798D47086145C75063C8E841E719776E400291D7838D3E6C4405B504C6A07F8FCA27F32B86643D2649D1D5F124CDD0BF272F0909DD7352FE10A77B34D831043D9AE541F8263C6FE3D1C14C2F04E43A7253A6DDA9A8C1562CBD493C1B631A1957618AD5DFE5CA28553F746E2FC6F2DB816C7DB223EC91E955081C1DE65];
$priv_key	= Math::BigInt->new($priv_key);
my ($mod, $exp);
if ($original == 1) {	# 1 - File is Original | 0 - File is not Original
	my $s = q[0x97df398472ddf737ef0a0cd17e8d172f0fef1661a38a8ae1d6e829bc1c6e4c3cfc19292dda9ef90175e46e7394a18850b6417d03be6eea274d3ed1dde5b5d7bde72cc0a0b71d03608655633881793a02c9a67d9ef2b45eb7c08d4be329083ce450e68f7867b6749314d40511d09bc5744551baa86a89dc38123dc1668fd72d83];
	$mod = Math::BigInt->new($s);
	$exp = Math::BigInt->new('0x35');
} else {
	my $s= q[0x75b4d6de5c016544068a1acf125869f43d2e09fc55b8b1e289556daf9b8757635593446288b3653da1ce91c87bb1a5c18f16323495c55d7d72c0890a83f69bfd1fd9434eb1c02f3e4679edfa43309319070129c267c85604d87bb65bae205de3707af1d2108881abb567c3b3d069ae67c3a4c6a3aa93d26413d4c66094ae2039];
	$mod = Math::BigInt->new($s);
	$exp = Math::BigInt->new('0x1d');
}

# Вычисление времени выполения скрипта
sub work_time {
	my ($t0) = @_;

	my $t1 = gettimeofday;				# Узнаем время в текущей точке
	my $elapsed = sprintf("%1.7f",$t1 - $t0);	# Округляем до 3 знаков после запятой
	print qq[\n===================== --- Done in: $elapsed sec. --- =====================\n];
}

# Запись в файл
sub save_file {
#&save_file($cfg->{'file_out'}, @a);
	my ($file, $act, $data) = @_;

	if (!$data) {
		print qq[No Data, Error!\n];
		exit 1;
	};

	open(FILE, ">$file-$act");
	binmode FILE;
	print(FILE $data);
	close(FILE);
	print qq[\t\tFile: ${file}-${act}\n\t\t\t successfully writed!\n];
	&work_time($t0);
}

sub la2_decode {
	my ($file) = @_;
	&save_file($file, 'dec', &l2decode_413($file));
}

sub la2_encode {
	my ($file) = @_;
	&save_file($file, 'enc', &l2encode_413($file));
}


sub l2decode_413 {
	my ($filename) = @_;
#	use IO::Uncompress::AnyInflate qw(anyinflate $AnyInflateError);

	open(FILE, "<$filename") || die qq[Error: Can not read '$filename'];
	binmode FILE;

	my $filesize = (stat(FILE))[7];
	return if ($filesize < 28 + 128);

	my $blocks = int(($filesize - 28)/128);
	return if ($blocks < 1);

	my $file;
	read(FILE, $file, $filesize);
	close(FILE);
	return if (!$file);

	my $head = substr($file, 0, 28); #print Dumper($head);
	Encode::from_to($head, 'UTF-16LE', 'UTF-8');
	return if ($head ne 'Lineage2Ver413');

	my $size = $blocks * (128 * 2);
	$file = unpack('H*', substr($file, 28, $size));	# переводим файл в hex, т.к. perl не умеет работать с бинарными данными. в нашем случае substr.

	my $data_gz;
	for (my $i = 0; $i < $blocks; ++$i) {
		my $block = substr($file, $i * (128 * 2), 128 * 2);
		my $res = '0x' . $block;#		my $res = '0x' . unpack('H*', $block);
#print '$enc: ['.$res."]\n";
		my $hex = Math::BigInt->new($res)->bmodpow($exp,$mod)->as_hex();
#print '$dec: ['.$hex."]\n";
#my $enc = Math::BigInt->new($hex)->bmodpow($priv_key,$mod)->as_hex();
#print '$enc: ['.$enc."]\n";

		return if (length($hex) != 252);
		substr($hex, 0, 2) =~ s/^0x//;

		my $s = pack('H*' , $hex);
		$size = ord($s);
		return if ($size > length($s) - 1);

		if ($size ne 124) {	#($size ne 0x7c) | ($size ne oct('0x7c'))
			my $p = length($s) - $size;
			while ($p > 2 && substr($s, $p - 1, 1) ne "\0") { --$p; }
			$s = substr($s, $p, $size);
		} else {
			$s = substr($s, -$size);
		}
		$data_gz .= $s;
	}

	my $a = unpack('L', $data_gz);
	return if (!defined($a));
	$size = int($a);

	$data_gz = substr($data_gz, 4);

	my $result = uncompress($data_gz);
#print $result;
	return if (length($result) != $size);

	return $result;
}

sub l2encode_413 {
	my ($filename) = @_;
print qq[filename: $filename\n];
	open(FILE, "<$filename") || die qq[Error: Can not read '$filename'];
	binmode FILE;

	my $filesize = (stat(FILE))[7];
	return if ($filesize < 128);	# тут мы пока еще в binmode, поэтому 128
print qq[filesize: $filesize\n];

	read(FILE, my $file, $filesize);
	return if (!$file);
	close(FILE);

	my $data_gz = compress($file,6);	# Сжимаем файл
	my $size = pack('L', $filesize);# Конвертируем размер файла в Long вид.
	$data_gz = $size . $data_gz;	# пихаем в начало архива 4 байта с размером архива.

#open(FILE, ">${filename}+head4") || die qq[Error: Can not read '$filename'];
#binmode FILE;
#print FILE $data_gz;
#close(FILE);

	$data_gz = unpack('H*', $data_gz);	# Конвертируем в HEX вид, чтобы perl'у было легче работать с архивом :) ну не любит он бинарные данные...
	$data_gz = substr($data_gz, 0, 12) . pack('H*', unpack('H*', substr($data_gz, 12, 2)) - 1) . substr($data_gz, 14);# исправляем какой-то байт в начале файла...
	$size = length($data_gz);
	my $block_size = 248;
	my $blocks = int(($size)/$block_size);	# Тут 248, т.к. нужно 250 для функции криптования, но 2 байта уйдут на "заголовок строки" в котором будет размер блока - 7c
	return if ($blocks < 1);
	my $last_str = $size % $block_size;	# Проверяем остаток от деления, чтобы узнать сколько у нас осталось неполных байт.
print 'size: ['.($size/2)."]\n";
print qq[blocks: $blocks\n];

	my $data;
	for (my $i = 0; $i < $blocks; ++$i) {
		my $block = substr($data_gz, $i * $block_size, $block_size);
		$block = '0x7c' . $block;
		my $hex = Math::BigInt->from_hex($block)->bmodpow($priv_key,$mod)->as_hex();
		substr($hex, 0, 2) =~ s/^0x//;
		my $zeroNUM = 256 - length($hex);
		if ($zeroNUM != 0) {
			my $zeros;
			for (my $i = 0; $i < $zeroNUM; $i++) { $zeros .= '0'}
			$hex = $zeros . $hex;
		}
		return if (length($hex) != 256);
#print '$enc: [0x'.$hex."]\n"; print '$dec: ['.$block."]\n";
#print 'length($hex): ['.length($hex)."]\n";

		$data .= pack('H*' , $hex);
	}

	my $block = substr($data_gz, -$last_str, -8);
	my $size_str = unpack('H2' , pack('L' , length($block)));
	$block = $block . '000000ffff0300' . substr($data_gz, -8);

#print 'size_str: ['.$size_str."]\n";

	my $zeros = '';
	for (my $i = 18; $i < $block_size - $last_str; $i++) { $zeros .= '0'}
	$block = '0x' . $size_str . $zeros . $block . '0000';

	my $hex = Math::BigInt->new($block)->bmodpow($priv_key,$mod)->as_hex();
	substr($hex, 0, 2) =~ s/^0x//;
	$data .= pack('H*' , $hex);
#print '$enc: [0x'.$hex."]\n"; print '$dec: ['.$block."]\n";
#print 'length($hex): ['.length($hex)."]\n";


	my $result = q[Lineage2Ver413];
	Encode::from_to($result, 'UTF-8', 'UTF-16LE');	# Получаем заголовок файла в UTF-16LE кодировке.
	$result .= $data;
	$result .= pack('H*', '000000000000000000000000');# добавляем 24 ноля, чтобы "выровнять файл"
	$result .= pack('H*', '00000000');	#TODO - узнать что сюда добавляется.
	$result .= pack('H*', '00000000');# добавляем 8 нолей, чтобы "выровнять файл"

#print unpack('L', pack('H*', 'dda08f96'))."\n";
	return $result;

}
return 1;
