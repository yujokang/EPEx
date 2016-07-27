#EPEx: Error Path Exploration for Finding Error Handling Bugs

##What is EPEx?

**E**rror **P**ath **Ex**ploration is a Clang checker
that detects missing error handling cases in C code.
The technique is described in detail in the paper,
[Automatically Detecting Error Handling Bugs using Error Specifications](https://yujokang.github.io/papers/epex_2016.pdf),
by [Suman Jana](http://sumanj.info/),
[Yuan Kang](https://yujokang.github.io/),
[Samuel Roth](https://www.linkedin.com/in/samuelroth1) and
[Baishakhi Ray](http://rayb.info/),
presented at the 2016 USENIX Security Symposium.

##Why is EPEx useful?
Writing correct error handling code in C is notoriously hard. Developers often 
forget to check possible error cases or do not propagate error codes upstream 
correctly. EPEx can detect such bugs by symbolically exploring different error 
paths (note that EPEx currently does not detect resource leakage bugs). 

We used EPEx to find bugs in the
GnuTLS, OpenSSL, mbedTLS and WolfSSL libraries,
as well as applications using OpenSSL:
cURL, Apache's HTTP server, Lynx, Mutt, and Wget.
The bugs include not only missing or incorrect checks for failure,
but also cases in which failures are detected,
but improperly reported.

##How does EPEx work?
Besides the program source code, EPEx takes error specifications,
that specify error protocol(s) of the test functions, as input.
EPEx uses under-constrained symbolic execution to explore
execution paths in which each test function can fail and return an error code.
In each of such error paths, EPEx checks if the caller function 
performs at least one of the following steps: exits with an error code, returns an error value,
or logs the function using one of the program's error logging functions.
If not, EPEx considers reports an error handling bug.
EPEx further reduces false positives by comparing results from multiple call-sites of the 
same function and only reports the cases where at least one caller of a test function performs 
one of the three steps described above.

#Installation and Usage

##Prerequisites
###CMake:
If you are using Ubuntu, you might need a newer version of CMake
than what you can get through apt-get.
You can download the source at:
https://cmake.org/download/
It can be built and installed using the standard
`./configure; make; sudo make install`

##LLVM and clang:
You can build the necessary parts of LLVM and clang at:
http://clang.llvm.org/get_started.html
It is not necessary to follow the optional steps 4-6.
To keep clang in your path, add the following line to `~/.bashrc`:
`export PATH=[build directory]bin:$PATH`
The rest of the instructions assume that you have not done this,
and will refer to `[build directory]bin/` as the `binary directory`.
If you did add the binary directory to your path,
you don't have to enter the binary directory in your commands.
To analyze a single file, however, you still have to enter the build directory
that contains the include folder.

##Installing the Clang checker:
1. Go to the directory
`[path to llvm source folder]tools/clang/lib/StaticAnalyzer/Checkers`
2. Add the source:
Enter `ln -s . [path to this release folder]EPEx.cpp`
3. Register the `alpha.unix.Epex` checker:
Open `../../../include/clang/StaticAnalyzer/Checkers/Checkers.td`, look for the block starting with
`let ParentPackage = UnixAlpha in {`,
and inside it, add the text:
```
def EPEx : Checker<"EPEx">,
  HelpText<"Error handling bug finder">,
  DescFile<"EPEx.cpp">;
```
4. Register the source file to be compiled:
Open CMakeLists.txt, look for the block starting with
`add_clang_library(`, and inside it, add the line `EPEx.cpp`.
5. Compile clang with the new checker:
  Inside the build directory, enter `make clang`.

##Creating the Error Specification
A file called `error_spec.txt` needs to be in the directory
in which you run the checker.
It contains error specifications for fallible functions,
as well as logging functions.

###Syntax:
1. Bounds: `[bound operator], [bound value]`, where the bound operator can be:
  a. `GT`: greater than
  b. `GE`: greater than or equal
  c. `LT`: less than
  d. `LE`: less than or equal
  e. `EQ`: equal to
  f. `NE`: not equal to
2. Types:
  a. `I` or `i`: integer
  a. `P` or `p`: pointer; 0 is NULL
  a. `B` or `b`: boolean; 0 is false
3. Bound operators and argument counts can be ignored
by putting `-1` in their place.

###Entries
1. Analyzed functions:
```
[function name], [argument count], [first bound value], [first bound operator], [second bound value], [second bound operator], [return type]
```
2. Global integer specification
(the error value is NULL for pointers and false for booleans):
```
__RETURN_VAL__, [argument count], [first bound operator], [first bound value], , [second bound operator], [second bound value], I
```
3. Logging functions: `1[name of logging function]`

###Sample function lists
The sample error specifications are in sample_specs
####Libraries
The the error specifications for checking the internals of library code
are stored in the following files, which you can use directly:
* GnuTLS: gnutls_error_spec.txt
* OpenSSL: openssl_error_spec.txt
* mbedTLS / PolarSSL: polarssl_error_spec.txt
* wolfSSL: wolfssl_error_spec.txt
####Applications using OpenSSL
The error specifications for external OpenSSL functions are stored in
ssl_error_spec.txt.
It can be combined with the following applications'
global specifications and logging functions:
* httpd: httpd_default_error_spec.txt
* Lynx: lynx_default_error_spec.txt
* Mutt: mutt_default_error_spec.txt
* Rsync: rsync_default_error_spec.txt
* Wget: wget_default_error_spec.txt

###Usage:
####Stages I and II:
1. A single file:
  a. Keep error_spec.txt in the current working directory
  b. Enter:
  ```
  [binary directory]clang -cc1 -w -analyze -analyzer-opt-analyze-headers -analyzer-checker=$2 -I/usr/include -I[build directory]lib/clang/[version]/include/ [source file]
  ```
2. A whole project:
  a. To keep the configuration file available in all directories,
  in this directory, run
  `python setup.py [path to original error_spec.txt] [path to project folder]`
  b. For every step in the build process (eg. ./configure and make),
  prepend the command with:
  ```
  [binary directory]scan-build -enable-checker alpha.unix.EPEx -analyze-headers --use-analyzer [binary directory]clang
  ```

####Stage III:
1. Go to the `stage_III` directory.
2. Run `python output_gatherer.py [arbitrary output log file] [directory where stages I and II were run]`
3. For the unfiltered output from Stage II,
run `python parse_return_logs.py [log file]`
4. For only the bugs reported in Stage III,
run `python parse_return_logs.py [log file] -b`
5. For only the correctly-handled paths,
run `python parse_return_logs.py [log file] -c`
