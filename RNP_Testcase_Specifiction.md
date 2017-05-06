# Test specification for the RNP
The document aims to describe and capture various use cases for the RNP product in the form of the test cases. These can be used as the acceptance test for the maintenance of the project. 

## Guidelines for testing:

### Testcase naming convention: 

the test case name is composed of the three parts. First being the module under test, second being the feature and third details the motivation of the test. Naming structure looks like 
**<module\>\_<component\>\_<Testmotivation\>.**

For example, when testing generatekey feature of the rnpkeys, the test case name would look like rnpkeys.generatekey.\<Testmotivation\>.

### Testcase specification template:

Following template shall be used for describing a test case.
Testcase Template:


----------
| Testcase | < Insert the testcase number> | Test case objective | < Describe the testcase in brief> |
|:---------|:-----------------------------|:--------------------|:---------------------------------|
| Component| Rnpkeys                      | Test Case Name      | <module\>\_<component\>\_<Testmotivation\>. |
| Feature  | Generate-key                 |                     |                                  |
| Short Description:  |                   |                     |                                  


| Precondition                                                                 |
|:-----------------------------------------------------------------------------|
| Initialize RNP                                                               |
| Set the default value for sshkeydir, res, format, hash via rnp_setvar().     |

| Testing Step                    | Expected behavior                           |
|:--------------------------------|:--------------------------------------------|
| Set the userId via rnp_setvar() | It is expected that the key is generated using the options set via rnp_setvar() |
| Call the API to generate keys(rnp_generate_key)|                                             |


| Verification Step                 | Verification logic                        |
|:----------------------------------|:------------------------------------------|
| Load the newly generated RNP keys |                                           |

| Comments (if any)                 |
|:----------------------------------|
|                                   |

----------


### Testcases:


----------


| Testcase | 1 | Test case objective | VerifySupportedHashAlg |
|:---------|:-----------------------------|:--------------------|:---------------------------------|
| Component| Rnpkeys                      | Test Case Name      | rnpkeys_generatekey_verifySupportedHashAlg |
| Feature  | Generate-key                 |                     |                                  |
| Short Description:  |                   | The test aims to test key generation with all possible hash algorithm. Following hash algorithm are tested for the key generation. "MD5", "SHA-1", "RIPEMD160", "SHA256", "SHA384", "SHA512", "SHA224"                    |                                  


| Precondition                                                                 |
|:-----------------------------------------------------------------------------|
| Initialize RNP                                                               |
| Set the default value for sshkeydir, res, format, hash via rnp_setvar().     |

| Testing Step                    | Expected behavior                           |
|:--------------------------------|:--------------------------------------------|
| Set the hash algorithm via rnp_setvar() | It is expected that the key is generated  using the options set via rnp_setvar() |
| Call the API to generate key (rnp_generate_key)|  |

| Verification Step                 | Verification logic                        |
|:----------------------------------|:------------------------------------------|
| Load the newly generated RNP keys |  This ensures the keys are loaded in the rnp control structure for verification.|
| Find the existence of the key via finding the key with the userId. **Note**: If userid variable is not set, default is always. | Ensures the key exist by finding it. |

| Comments (if any)                 |
|:----------------------------------|
| It is required to delete the old keys if the test case iterates over the hashing algorithm. |


----------


| Testcase | 2 | Test case objective | VerifyUserIdOption |
|:---------|:-----------------------------|:--------------------|:---------------------------------|
| Component| Rnpkeys                      | Test Case Name      | rnpkeys_generatekey_VerifyUserIdOption |
| Feature  | Generate-key                 |                     |                                  |
| Short Description:  |                   | The test aims to test key generation with commandline options UserId. Following different userid are tested. "Rnpkeys_Generatekey_VerifyUserIdOption _MD5", "Rnpkeys_Generatekey_VerifyUserIdOption_SHA-1","Rnpkeys_Generatekey_VerifyUserIdOption _RIPEMD160","Rnpkeys_Generatekey_VerifyUserIdOption _SHA256","Rnpkeys_Generatekey_VerifyUserIdOption _SHA384","Rnpkeys_Generatekey_VerifyUserIdOption _SHA512","Rnpkeys_Generatekey_VerifyUserIdOption _SHA224"    |                                  
 

| Precondition                                                                 |
|:-----------------------------------------------------------------------------|
| Initialize RNP                                                               |
| Set the default value for sshkeydir, res, format, hash via rnp_setvar().     |

| Testing Step                    | Expected behavior                           |
|:--------------------------------|:--------------------------------------------|
| Set the userId via rnp_setvar() | It is expected that the key is generated  using the options set via rnp_setvar() |
| Call the API to generate key (rnp_generate_key)|  |

| Verification Step                 | Verification logic                        |
|:----------------------------------|:------------------------------------------|
| Load the newly generated RNP keys |  This ensures the keys are loaded in the rnp control structure for verification.|
| Find the existence of the key via finding the key with the userId.  |

| Comments (if any)                 |
|:----------------------------------|
|  |


----------


| Testcase | 3 | Test case objective | VerifykeyRingOptions |
|:---------|:-----------------------------|:--------------------|:---------------------------------|
| Component| Rnpkeys                      | Test Case Name      | rnpkeys_generatekey_verifykeyRingOptions |
| Feature  | Generate-key                 |                     |                                  |
| Short Description:  |                   | The test aims to test key generation with the user specified keyring.                  |                                  
 

| Precondition                                                                 |
|:-----------------------------------------------------------------------------|
| Initialize RNP                                                               |
| Set the default value for sshkeydir, res, format, hash via rnp_setvar().     |

| Testing Step                    | Expected behavior                           |
|:--------------------------------|:--------------------------------------------|
| Set the keyring via rnp_setvar() | It is expected that the key is generated  using the options set via rnp_setvar() |
| Call the API to generate key (rnp_generate_key)|  |

| Verification Step                 | Verification logic                        |
|:----------------------------------|:------------------------------------------|
| Delete the default keyring i.e. pubring.gpg and secring.gpg found in the homedir | To ensure that default keyring is NOT available.|
| Load the newly generated RNP keys |  This ensures the keys are loaded in the rnp control structure for verification.|
| Find the existence of the key via finding the key with the userId. **Note**: If userid variable is not set, default is always. | Ensures the key exist by finding it. |

| Comments (if any)                 |
|:----------------------------------|
|  |


----------


| Testcase | 4 | Test case objective | VerifykeyHomeDirOption |
|:---------|:-----------------------------|:--------------------|:---------------------------------|
| Component| Rnpkeys                      | Test Case Name      | rnpkeys_generatekey_VerifykeyHomeDirOption |
| Feature  | Generate-key                 |                     |                                  |
| Short Description:  |                   | The test aims to test key generation with the user specified keyring.                  |                                  
 

| Precondition                                                                 |
|:-----------------------------------------------------------------------------|
| Create new home dir with read/write permissions.                             |
| Delete the keys (if any) in the previous default directory.                  |
| Initialize RNP                                                               |
| Set the default value for sshkeydir, res, format, hash via rnp_setvar().     |

| Testing Step                    | Expected behavior                           |
|:--------------------------------|:--------------------------------------------|
| Call the API to generate key (rnp_generate_key)|  |

| Verification Step                 | Verification logic                        |
|:----------------------------------|:------------------------------------------|
| Load the newly generated RNP keys |  This ensures the keys are loaded in the rnp control structure for verification.|
| Find the existence of the key via finding the key with the userId. **Note**: If userid variable is not set, default is always. | Ensures the key exist by finding it. |

| Comments (if any)                 |
|:----------------------------------|
|  |


----------
































































































































































 
