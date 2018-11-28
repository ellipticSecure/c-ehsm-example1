### This example demonstrates how to use the eHSM Hardware Security Module to do elliptic curve cryptography.

For updated documentation, see [the how-to](https://ellipticsecure.com/ehsm/how-to/2018/11/28/ehsm-c-ecc-example.html).
#### Prerequisites: an initialized eHSM with a user password set.

##### Note: edit main.c to ensure that the path to the eHSM pkcs11 shared library is correct for your platform.

#### Test and build instructions

```bash
mkdir build
cd build
cmake ..
make
./c_ehsm_example1 "user password"
```
