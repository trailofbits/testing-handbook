---
title: "Wycheproof"
weight: 3
summary: "Wycheproof is a collection of test vectors for existing cryptographic algorithms which developers can use to verify their implementation and check for know attacks and vulnerabilities"
bookCollapseSection: true
math: true
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookComments: false
# bookSearchExclude: false
---

{{< math >}}

# Wycheproof

[Wycheproof](https://github.com/C2SP/wycheproof) is an extensive collection of test vectors designed to verify the correctness and test against known attacks for existing cryptographic algorithms. 
Originally developed by Google, Wycheproof is a community-managed project where contributors can add their own test vectors for specific cryptographic constructions. 
## Overview

Wycheproof provides sets of test vectors aimed at uncovering known vulnerabilities in cryptographic implementations. 
It supports a wide range of cryptographic algorithms, including:
- AES-GCM
- ChaCha20-Poly1305
- ECDH
- RSA

and many more. 
All test vectors are stored in the official [github repository](https://github.com/C2SP/wycheproof).
The vectors are organized in two main folders:
- `testvectors`
- `testvectors_v1`

, with plans to merge them in the future.
While both folders contain similar test vector files, `testvectors_v1` includes more detailed information.
The test vectors, stored in JSON-encoded files, can be used as input in a testing harness to verify the correctness of a cryptographic implementation by comparing the actual output to the expected output specified in the test vector.
To use the test vectors provided by Wycheproof, integrate them into the testing procedures of the cryptographic library you want to test by writing a testing harness. 
This testing harness should parse the JSON file for the specific construction and use the inputs and expected outputs from each test vector to verify the implementation.
Wycheproof provides testing harnesses for Java JCE interface (in the `java` folder) and JavaScript (in the `javascript` folder).

## Repository Structure
The Wycheproof repository is structured as follows:
```
├── README.md       : Project overview
├── doc             : Documentation
├── java            : Java JCE interface testing harness
├── javascript      : JavaScript testing harness
├── kokoro          : Internal Google Jenkins scripts
├── schemas         : Test vector schemas
├── testvectors     : Test vectors
└── testvectors_v1  : Updated test vectors
```

For most developers, the essential folders are `testvectors` and `testvectors_v1` as they contain all the JSON-encoded test vectors. 
The structure of the two folders and how each test file is structured are explained below. 

## Test Vector Structure

Each JSON test file tests a specific cryptographic construction, such as AES-GCM for example. 
Each JSON file consists of multiple *test groups*, and each test group contains multiple test vectors. 
For example, for AES-GCM all test vectors are stored in `aes_gcm_test.json` and comprises 44 test groups and 316 test vectors.

```
testvectors_v1
├── aes_gcm_test.json
│   ├── test group 1
│   │   ├── test vector 1
│   │   ├── test vector ...
│   │   └── test vector 67
│   ├── test group ...
│   │   └── test vector ...
│   └── test group 44
│       ├── test vector 315
│       └── test vector 316
├── ecdh_secp256k1_test.json
│   ├── test group 1
│   │   ├── test vector 1
│   │   ├── ...  
...
```
The visualization above shows an example of how the `testvectors_v1` folder structures different cryptographic algorithms like **AES-GCM** and **ECDH** into different files. 
Each file contains multiple test groups and each test group contains multiple test vectors. 
The following described in greater detail how each test file is structured as well as the commonalities between test files of different constructions. 

## Test files
A test file stores all test vectors used to test a cryptographic algorithm. 
All test files share common attributes:
```json
"algorithm"         : The name of the algorithm tested
"schema"            : The JSON schema which can be found in the `schema` folder at the root of the Wycheproof project
"generatorVersion"  : The version number 
"numberOfTests"     : The total number of test vectors inside this file
"header"            : More detailed description of the intended of the test vectors present in the current file
"notes"             : Provides a more in depth explanation of different flags present in each test vector 
"testGroups"        : An array of one or multiple test groups
```


### Test Groups

Test groups group sets of tests based on shared attributes, such as key sizes, IV sizes, public keys, or curves. 
This classification allows for the extraction of tests that meet specific criteria relevant to the construction being tested.

### Test Vectors
Each test vector includes all necessary inputs and expected outputs for a specific cryptographic algorithm. 
While the structure varies between different algorithms, all test vectors share certain attributes:

#### Shared Attributes
Wycheproof test vectors contain certain attributes which are present in all test vectors.  
The commonalities between all test vectors are four fields:

- `tcId`: A unique identifier for the test vector within a file.
- `comment`: Additional information about the test cases. 
- `flags`: Descriptions of specific test case types and their potential dangers, referenced in the `notes` field.
- `result`: If the test should succeed or not.

The `result` field is important and can take 3 different values:

- **valid**: Test case should succeed.
- **acceptable**: Test case is allowed to succeed but contains some non ideal attributes. Ideally this test case should fail but it is acceptable if it passes.
- **invalid**: Test case should fail.


#### Unique Attributes

Unique attributes are specific to the inputs and outputs of the cryptographic algorithm being tested. 
For instance, AES-GCM tests include `key`, `iv`, `aad`,`msg`, `ct`, and `tag`, while the test for ECDH for secp256k1 include `public`, `private`, and `shared`.


## CI Setup

Wycheproof over time might add new test vectors to existing test files. 
This greatly benefits developers as they only need to write the testing harness once and profit from new test vectors added without the need of any additional work on their side. It is therefore recommended to ensure that the test vectors used inside the testing harness are kept up to date.   
The approach we recommend is to add Wycheproof as a submodule to the github repository.  
In case this is not possible we also provide a simple script which fetches specific test vectors from the Wycheproof repository. 

### Git Submodule

Adding Wycheproof as a git submodule will ensure that if new test vectors are added to the construction under test you will be able to automatically use them. 

```
git sumodule add git@github.com:C2SP/wycheproof.git
```

### Fetching test vectors

If adding Wycheproof as a git submodule is not possible we provide a simple script which fetches the specific constructions and places them inside a `.wycheproof` folder. Given that GitHub does not support the git [archive command](https://github.com/isaacs/github/issues/554) we resort to a simple `curl` query which fetches the specified JSON. In the example below we fetch the AES-GCM and AES-EAX test files. 

```bash
#!/bin/bash

TMP_WYCHEPROOF_FOLDER=".wycheproof/"
TEST_VECTORS=('aes_gcm_test.json' 'aes_eax_test.json')
BASE_URL="https://raw.githubusercontent.com/C2SP/wycheproof/master/testvectors_v1/"

# Create wycheproof folder
mkdir -p $TMP_WYCHEPROOF_FOLDER

# Request all test vector files if they don't exist
for i in "${TEST_VECTORS[@]}"; do
  if [ ! -f "${TMP_WYCHEPROOF_FOLDER}${i}" ]; then
    curl -P "$TMP_WYCHEPROOF_FOLDER" "${BASE_URL}${i}"
    if [ $? -ne 0 ]; then
      echo "Failed to download ${i}"
      exit 1
    fi
  fi
done
```

The script creates a folder called `.wycheproof` in which it will store the JSON files specified inside the `ALGORITHMS` variable by fetching them from the GitHub servers using `curl`.  
Running this script before the testing harness is executed ensures that the Wycheproof test vectors are kept up to date and you benefit from the new test vectors being added. 

## Ideal Use Case

Wycheproof is ideally used to help validate the correctness of existing cryptographic implementations against known edge cases and common mistakes made during development.   
{{< hint warning >}}
Wycheproof is not intended to be used for creating new cryptographic algorithms. Wycheproof is a collection of test vectors of existing and well established algorithms and should be used to test the implementation of these algorithms. 
{{< /hint >}}


## Real world examples

Wycheproof has been instrumental in identifying bugs in prominent cryptographic libraries, such as **OpenJDK's SHA1withDSA** and **Bouncy Castle's ECDHC**. 
Furthermore libraries like [pycryptodome](https://pypi.org/project/pycryptodome/) are using the testvectors of Wycheproof to test their implementation.
By integrating Wycheproof into your testing process, you can enhance the security and reliability of your cryptographic solutions.


### Case study: elliptic npm

[Elliptic](https://www.npmjs.com/package/elliptic) is an elliptic-curve cryptography library written in plain JavaScript.
It is a popular library with millions of weekly downloads and about 3000 dependents. 
The library supports the following algorithms:  
- ECDH
- ECDSA
- EdDSA

on numerous different curves. 
We used the Wycheproof testing vectors to investigate the security of version 6.5.6, which, as of writing this entry, is the most up-to-date version. Using Wycheproof we were able to find vulnerabilities multiple vulnerabilities in both the ECDSA and EDDSA module:

- [CVE-2024-42459](https://nvd.nist.gov/vuln/detail/CVE-2024-42459)  
- [CVE-2024-42460](https://nvd.nist.gov/vuln/detail/CVE-2024-42460)  
- [CVE-2024-42461](https://nvd.nist.gov/vuln/detail/CVE-2024-42461)


In the following we will talk you through how we applied Wycheproof to provide a practical example of how one can make use of it. 
#### Parse file
The first step is to identify all supported curves for EdDSA and check if Wycheproof provides test vectors for the specific curve. 
The EDDSA object's constructor takes the curve's name as input.
Upon examining the source code, we see that the current version of the library only supports EdDSA using the `ed25519` curve. 
```javascript
function EDDSA(curve) {
  assert(curve === 'ed25519', 'only tested with ed25519 so far');
  ...
}
```

Finding the corresponding file inside the [Wycheproof GitHub repo](https://github.com/C2SP/wycheproof) can be done quickly by just searching for the specific curve, resulting in the file `testvectors_v1/ed25519_test.json`.
Parsing the JSON file in JavaScript is straightforward and only requires a few lines of code. 

```javascript
try {
  const fileContent = await fs.readFile(PATH);
  const data = JSON.parse(fileContent.toString());
  data.testGroups.forEach(testGroup => {
    testGroup.tests.forEach(test => {
      test['pk'] = testGroup.publicKey.pk;
      tests.push(test);
    });
  });
} catch (err) {
  console.error('Error reading or parsing file:', err);
  throw err;
}
```
In the code snippet above, the `testvectors_v1/ed25519_test.json` is read, and all test vectors are pushed into a global `tests` variable. 
The public key used to verify the signature is stored as a parameter inside the test group, which we add to each test vector. 
Once all test vectors are read, we can write a testing harness that uses each test vector. 

#### Testing Harness 
The elliptic library uses a Unit testing framework, and we integrated the new Wycheproof test vectors. We created a test factory that generates individual test cases for each test vector.


```javascript
function testFactory(tcId) {
  it(`[${tcId + 1}] `, function () {
    const test = tests[tcId];
    const ed25519 = new eddsa('ed25519');
    const key = ed25519.keyFromPublic(toArray(test.pk, 'hex'));
    let sig;

    if (test.result === 'valid') {
      sig = key.verify(test.msg, test.sig);
      assert.equal(sig, true, `[${test.tcId}] ${test.comment}`);
    } else if (test.result === 'invalid') {
      try {
        sig = key.verify(test.msg, test.sig);
      } catch (err) {
        // Point could not be decoded
        console.log(err);
        sig = false;
      }
      assert.equal(sig, false, `[${test.tcId}] ${test.comment}`);
    }
  });
}

for (var tcId = 0; tcId < expectedTests; tcId++) {
  testFactory(tcId);
}
```

Depending on the test vector's expected result, we assert that verifying the signature either succeeded or failed due to an assertion we catch or because the signature is invalid. 
We repeated the process of writing a testing harness for the remaining cryptographic construction of ECDH and ECDSA.  


#### Results

After running all test vectors the test runner reports that some test failed and after further investigation we can conclude that there exist at least three vulnerabilities. At closer inspection all these tests should have failed but were incorrectly accepted as valid signatures.  
The following test vectors failed: 

{{\< hint warning \>}}

* :x: \[[eddsa](https://github.com/C2SP/wycheproof/blob/master/testvectors\_v1/ed25519\_test.json)\]\[tc37\] removing 0 byte from signature  
* :x: \[[ecdsa](https://github.com/C2SP/wycheproof/blob/master/testvectors\_v1/ecdsa\_secp256k1\_sha256\_test.json)\]\[tc6\] Legacy: ASN encoding of r misses leading 0  
* :x: \[[ecdsa](https://github.com/C2SP/wycheproof/blob/master/testvectors\_v1/ecdsa\_secp521r1\_sha512\_test.json)\]\[tc7\] length of sequence \[r, s\] contains a leading 0

{{\< /hint \>}}

Wycheproof makes it easy to understand the vulnerability that specific test vectors are designed to uncover by checking each test vector's comment field. If the comment field is too ambiguous and more information is needed, one can look at each test vector's flags field and the corresponding explanation of the different flags inside the notes fields at the root of the JSON file.

To understand the failed test vectors, we examined the library's source code to identify the root causes of these vulnerabilities. 

#### EDDSA

The first test vector that failed was inside the EDDSA algorithm for the ed25519 curve. The responsible function is the `EDDSA.prototype.verify`, which checks whether a signature is valid:

```javascript
/**
* @param {Array} message - message bytes
* @param {Array|String|Signature} sig - sig bytesœ
* @param {Array|String|Point|KeyPair} pub - public key
* @returns {Boolean} - true if public key matches sig of message
*/
EDDSA.prototype.verify = function verify(message, sig, pub) {
  message = parseBytes(message);
  sig = this.makeSignature(sig);
  var key = this.keyFromPublic(pub);
  var h = this.hashInt(sig.Rencoded(), key.pubBytes(), message);
  var SG = this.g.mul(sig.S());
  var RplusAh = sig.R().add(key.pub().mul(h));
  return RplusAh.eq(SG);
};
```

The issue stems from EDDSA signature's length never being checked, allowing for appending or removing zeros from the end of the signature. 

```
Valid signature:   ...6a5c51eb6f946b30d
Invalid signature: ...6a5c51eb6f946b30d0000
```

Adding a simple length check fixes this vulnerability and prevents an attacker from creating invalid signatures by appending or removing zeros from the end of the signature.

```javascript
  if(sig.length !== 128) {
    return false;
  }
```

This vulnerability can lead to consensus problems as some libraries will correctly reject these invalid signatures while elliptic would accept this fraudulent signature allowing to create multiple valid signatures for a given message. Once the signatures are parsed however the trailing zeros are removed and the internal signatures representation is corrected. This vulnerability resulted in the creation of [CVE-2024-42459](https://nvd.nist.gov/vuln/detail/CVE-2024-42459). 

#### ECDSA

The two failed test vectors accepted invalid signature encoding, leading to the same problem with the EDDSA issue, where one message can have multiple valid signatures. Both problems had to do with the specification of DER-encoded signatures. 

The first issue stems from an invalid bit placement. The first bit for both r and s should be zero, indicating that they are positive integers. However, during the import of the DER encoded signatures, this property is never checked and is implicitly assumed to be zero.   
The implicit assumptions allow for multiple encodings, which is not permitted in the case of the DER.  

One must add checks for the specific locations to the import DER function to remedy this issue. 

```javascript
Signature.prototype._importDER = function _importDER(data, enc) {
  ...
  if ((data[p.place] & 128) !== 0) {
    return false;
  }
  ...

  if ((data[p.place] & 128) !== 0) {
    return false;
  }
  ...
}
```

Running the new code identifies the signature the test vector provided as invalid and correctly rejects it. [CVE-2024-42460](https://nvd.nist.gov/vuln/detail/CVE-2024-42460)

The second issue is similar to the first issue. The DER encoding follows the Tag-Length-Value format. The following is an example of an encoding: 

```
<Tag><Lenght><Value>
  02    20    813ef79ccefa9a56f7ba805f0e478584fe5f0dd5f567bc09b5123ccbc9832365
```

The length field, encoded in hex, specifies how many bytes the value field takes up. The length field cannot contain a leading zero bit for the length, but this is never explicitly checked. The getLength function, which parses the length of the DER data, does not perform the check and subsequently allows for multiple DER encodings.  

```javascript
function getLength(buf, p) {
  ...
  if(buf[p.place] === 0x00) {
    return false;
  }
  ...
}
```

After adding a check that ensures that the length parameter is zero, the invalid signatures fail, and the test vector is satisfied. [CVE-2024-42461](https://nvd.nist.gov/vuln/detail/CVE-2024-42461)

#### Takeaway 
Finding such mistakes can be challenging, but using Wycheproof test vectors helps identify corner cases like these. 
Investing time in creating a reusable testing harness with slight modifications for different constructions can go a long way in ensure these vulnerabilities do not go undetected.
