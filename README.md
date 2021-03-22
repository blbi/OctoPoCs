## OctoPoCs:Automatic PoC Generator

this tool generates PoC automatically for propagated vulnerability in cloned software

### Module 1. Extracting Crash Primitive
***
#### 0. requirement
Intel PIN 3.13
(https://software.intel.com/content/www/us/en/develop/articles/pin-a-binary-instrumentation-tool-downloads.html)

#### 1. build

```bash
make PIN_ROOT=~/mypin/pin ./obj-intel64/taint_test.so
```

If OctoPoCs's source directory is out of the PIN kit directory, you should specify the path of PIN kit directory.

#### 3. usage

```bash
pin -t ./obj-intel64/taint_test.so -v [ep] -i [poc] -- [cmd]
```

1. ep : vulnerable function name

    you should put the bottommost function of the call stack among shared(cloned) functions

2. poc : poc file name

3. cmd : command that execute the testing binary

    It contains the poc file name

- Warning

    you should execute this command in the directory that contains poc file


### Module 2. Generating Guiding Input
***
#### 0. requirement
angr
(https://docs.angr.io/introductory-errata/install)

#### 1. usage
main source file : generatePoC.py

there are 9 arguments

- cmd : command that execute target binary,
    it should include a name of new poc.

- ep : ep function name (the bottomost function in callstack),
        you can get more information in the paper.

- e_count : a number of times ep is executed

- oldpoc : a name of original poc

- primitive : the primitive file, output of module 1

- prim_fd : a list of bunch division offsets

- stacknum : CFG context sensitivity level

- c_flag : set bunch flag

- newpoc : a name of new poc, this must be included in cmd

