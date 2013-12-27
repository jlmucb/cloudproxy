#############################################################################
# Copyright (c) 2013 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

#############################################################################
# INTEL CONFIDENTIAL
# Copyright 2001-2013 Intel Corporation All Rights Reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its
# suppliers or licensors.  Title to the Material remains with Intel
# Corporation or its suppliers and licensors.  The Material contains trade
# secrets and proprietary and confidential information of Intel or its
# suppliers and licensors.  The Material is protected by worldwide copyright
# and trade secret laws and treaty provisions.  No part of the Material may
# be used, copied, reproduced, modified, published, uploaded, posted,
# transmitted, distributed, or disclosed in any way without Intel's prior
# express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or
# delivery of the Materials, either expressly, by implication, inducement,
# estoppel or otherwise.  Any license under such intellectual property rights
# must be express and approved by Intel in writing.
#############################################################################

@echo off
if EXIST %0 (
  perl -S -x  %0  %1 %2 %3 %4 %5 %6 %7 %8 %9
) ELSE (
  perl -S -x  %0.bat  %1 %2 %3 %4 %5 %6 %7 %8 %9
)
goto end

#!perl

# --- global variables ----
$pattern = "Note: including file:";

# ------- help ----------
sub help
{
  printf STDERR "Usage:
  $0 <target_name>
  
  Log of Microsoft cl with /showIncludes is piped
  to the STDIN and resulting dependencies file is
  printed to the STDOUT\n";
}

# ------ canonize -------
sub canonize
{
  my $file_name = shift;

  #remove leading and traling whitespaces
  $file_name =~ s/^\s*\b(.*)\b\s*$/$1/;

  # replace the leading drive letter with /cygdrive/<letter>/
  $file_name =~ s/^(.):(.*)/\/cygdrive\/$1$2/;
  
  #replace \\ with /
  $file_name =~ s/\\/\//g;
  
  #prepend each whitespace with \\
  $file_name =~ s/(\s)/\\$1/g;
  
  #lowercase
  $file_name = lc($file_name);

  return $file_name;
}

# ----- main ----------

my $num_of_args = $#ARGV + 1;
my %DEPENDECIES_MAP;
my $file_name;
my $target;
my @dependencies;
my $num_of_dependencies;
my $dep_count;

if ($num_of_args != 1)
{
  help();
  exit 1;
}

$target = $ARGV[0];

# read STDIN, find dependencies, lowercase them and put into the DEPENDECIES_MAP
while (<STDIN>) 
{
  chomp; # remove newline
  if (/^\s*${pattern}\s*(.*)$/o)
  {
    # matched
    $file_name = $1;
    
    $file_name = canonize($file_name);
    
    if (! ($file_name =~ /^$/))
    {
      # file_name is not empty
      
      #uniqueness
      $DEPENDECIES_MAP{ $file_name } = 1;
    }
  }
}

# input file finished
$target = canonize($target);

@dependencies = keys(%DEPENDECIES_MAP);
$num_of_dependencies = @dependencies;

if ($num_of_dependencies == 0)
{
  # do not create dependencies 
  exit 0;
} 

printf("$target : \\\n");
$dep_count = 0;
foreach $file_name (@dependencies)
{
  my $continuation;
  
  ++$dep_count;
  
  if ($dep_count != $num_of_dependencies)
  {
    $continuation = "\\";
  }
  
  printf("        $file_name $continuation\n");
}

printf("\n");

exit 0;

__END__

:end
