# Introduction

The following are a set of conventions and items that are relevant to contributors.

# Continuous Integration (Travis CI)

Travis CI is used for continuously testing new commits and pull requests.
We use the sudo-less beta Ubuntu Trusty containers, which do not permit root access.
See the file `.travis.yml` and the scripts in `ci/` for the most up-to-date details.

## Reproducing Locally

Sometimes tests fail in Travis CI and you will want to reproduce them locally for easier troubleshooting.
We can use a container for this, like so:

``` sh
$ docker run -ti --rm travisci/ci-garnet:packer-1490989530 bash -l
```

(Refer to [here](https://docs.travis-ci.com/user/common-build-problems/#Troubleshooting-Locally-in-a-Docker-Image) and [here](https://hub.docker.com/r/travisci/ci-garnet/tags/))

Inside the container, you will need to perform steps like the following:

``` sh
$ git clone https://github.com/riboseinc/rnp.git
$ cd rnp
$ export BOTAN_INSTALL="$HOME/builds/botan-install"
$ export CMOCKA_INSTALL="$HOME/builds/cmocka-install"
$ export JSON_C_INSTALL="$HOME/builds/json-c-install"
$ ci/install.sh
$ env BUILD_MODE=normal CC=clang ci/main.sh
```

(The above uses clang as the compiler -- use `CC=gcc` for GCC)
Refer to the current `.travis.yml` for the most up-to-date information on what environment variables need to be set.

# Code Coverage

CodeCov is used for assessing our test coverage.
The current coverage can always be viewed here: https://codecov.io/github/riboseinc/rnp/

# Security / Bug Hunting

## Static Analysis

### Coverity Scan

Coverity Scan is used for occasional static analysis of the code base.

To initiate analysis, a developer must push to the `coverity_scan` branch.
You may wish to perform a clean clone for this, like so:

``` sh
$ cd /tmp
$ git clone git@github.com:riboseinc/rnp.git
$ git checkout coverity_scan                    # switch to the coverity_scan branch
$ git rebase master coverity_scan               # replay all commits from master onto coverity_scan
$ git push -u origin coverity_scan -f           # forcefully push the coverity_scan branch
```

Note: Some of these steps are overly verbose, and not all are necessary.

The results can be accessed on scan.coverity.com. You will need to create an account and request access to the riboseinc/rnp project.

Since the scan results are not updated live, line numbers may no longer be accurate against master, issues may already be resolved, etc.

### Clang Static Analyzer

Clang includes a useful static analyzer that can also be used to locate potential bugs.

To use it, pass the build command to `scan-build`:

``` sh
$ ./configure
$ scan-build make -j4
[...]
scan-build: 6 bugs found.
scan-build: Run 'scan-view /tmp/scan-build-2017-05-29-223318-9830-1' to examine bug reports.
```

Then use `scan-view`, as indicated above, to start a web server and use your web browser to view the results.

## Dynamic Analysis

### Fuzzer

It is often useful to utilize a fuzzer like [AFL](http://lcamtuf.coredump.cx/afl/) to find ways to improve the robustness of the code base.

Currently, we have a very simple test program in `src/fuzzers/fuzz_keys`, which will attempt to load an armored key file passed on the command line. We can use this with AFL to try to produce crashes, which we can then analyze for issues.

1. Install AFL.
2. Rebuild, using the afl-gcc compiler.
    * It's probably easiest to also do a static build, using the `--disable-shared` option to `configure`.
    * It may be helpful to occasionally enable the address sanitizer, which tends to help produce crashes that may not otherwise be found. Read the documentation for AFL first to understand the challenges with ASan and AFL.
3. Create directories for input files, and for AFL output. 
4. Run `afl-fuzz`.
5. When satisfied, exit with `CTRL-C`.
6. Analyze the crashes/hangs in the output directory.

Here is an example:

``` sh
$ env CC=afl-gcc AFL_HARDEN=1 CFLAGS=-ggdb ./configure --disable-shared
$ make -j$(grep -c '^$' /proc/cpuinfo) clean all
$ mkdir afl_in afl_out
$ cp some_tests/*.asc afl_in/
$ afl-fuzz -i afl_in -o afl_out src/fuzzing/fuzz_keys @@
# ctrl-c to exit
$ valgrind -q src/fuzzing/fuzz_keys < afl_out/[...]
```

#### Further Reading

* AFL's README, parallel_fuzzing.txt, and other bundled documentation.
* https://fuzzing-project.org/tutorial3.html

### Clang Sanitizer

Clang and GCC both support a number of sanitizers that can help locate issues in the code base during runtime.

To use them, you should rebuild with the sanitizers enabled, and then run the tests (or any executable):

``` sh
$ env CC=clang CFLAGS="-fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined" ./configure
$ make -j4
$ src/cmocka/rnp_tests
```

Here we are using the [AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html) and [UndefinedBehaviorSanitizer](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html).
This will produce output showing any memory leaks, heap overflows, or other issues.

# Code Conventions

C is a very flexible and powerful language. Because of this, it is important to establish a set of conventions to avoid common problems and to maintain a consistent code base.

## Code Formatting

`clang-format` (v4+) can be used to format the code base, utilizing the `.clang-format` file included in the repository.

### clang-format git hook

A git pre-commit hook exists to perform this task automatically, and can be enabled like so:

``` sh
$ cd rnp
$ git-hooks/enable.sh
```

If you do not have clang-format v4+ available, you can use a docker container for this purpose by setting `USE_DOCKER="yes"` in `git-hooks/pre-commit.sh`.

This should generally work if you commit from the command line.

Note that if you have unstaged changes on some of the files you are attempting to commit, which have formatting issues detected, you will have to resolve this yourself (the script will inform you of this).

### clang-format (manually)

If you are not able to use the git hook, you can run clang-format manually.

``` sh
$ clang-format -style=file -i src/lib/some_changed_file.c
```

(Or, if you do not have clang-form v4 available, use a container)

### Style Guide

In order to keep the code base consistent, we should define and adhere to a single style.
When in doubt, consult the existing code base.

#### Naming

The following are samples that demonstrate the style for naming different things.

* Functions: `some_function`
* Variables: `some_variable`
* Filenames: `crypto.c`
* Struct: `pgp_key_t`
* Typedefed Enums: `pgp_pubkey_alg_t`
* Enum Values: `PGP_PKA_RSA = 1`
* Constants (macro): `RNP_BUFSIZ`

#### General Guidelines

Do:

* Do use header guards (`#ifndef SOME_HEADER_H [...]`) in headers.
* Do use `sizeof(variable)`, rather than `sizeof(type)`. Or `sizeof(*variable)` as appropriate.
* Do use commit messages that close GitHub issues automatically, when applicable. `Fix XYZ. Closes #78.` See [here.](https://help.github.com/articles/closing-issues-via-commit-messages/).
* Do declare functions `static` when they do not need to be referenced outside the current source file.
* Do omit braces for simple one-line conditionals. (Unless attached to another conditional with multiple lines.)

Do not:
* Do not use static storage-class for variables.
* Do not use `pragma`.

