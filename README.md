
stdin2argv - Shared library to convert stdin to CLI arguments for fuzzing
```
gcc -shared -fPIC -o stdin2argv.so stdin2argv.c -ldl
AFL_PRELOAD=./stdin2argv.so afl-fuzz -i /tmp/sudo_afl/input/ -o /tmp/sudo_afl/output/ -m none -- sudo
```
