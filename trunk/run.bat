@ECHO OFF

::CHCP 65001 >nul
CHCP 866 >nul

:: Perl
SET "Path=%Path%;c:\PATH\TO\bin\perl\bin;"

perl run.pl

PAUSE
