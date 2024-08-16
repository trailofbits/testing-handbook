---
title: "Testing harness example"
weight: 30
# bookFlatSection: false
# bookToc: true
# bookHidden: false
# bookCollapseSection: false
# bookComments: false
# bookSearchExclude: false
---

# Wycheproof testing harness example in python

In the following section, we will showcase how to write a simple testing harness to test a python library implementing AES in GCM mode. 
We will use the [cryptography](https://pypi.org/project/cryptography/) package as an example of an AES GCM implementation.
For testing we will use the [pytest](https://pypi.org/project/pytest/) packages as it is one of the most popular testing frameworks in python. 

## Prerequisites

The first step is to add the Wycheproof repository as a submodule to your existing repository.

```
git submodule add https://github.com/C2SP/wycheproof.git
```

The first step of using Wycheproof is to parse the JSON file containing all the test vectors to make it usable for testing and then write a simple testing function. 

## 1. Parse the JSON File

First, check if Wycheproof offers test vectors for the specific cryptographic algorithm being tested by searching inside the `testvectors` or `testvectors_v1` folders. 
For the AES-GCM example, we will use the following file:
- `testvectors_v1/aes_gcm_test.json`

All test files share a common structure that can be used to write a testing harness that allows to generalize between different constructions, which we discussed in the previous section. There are a total of 45 test groups in the `aes_gcm_test.json` file. The test groups differentiate themselves by different key, IV, and tag sizes. If the underlying AES implementation only supports certain parameter sizes, they can be filtered out during the parsing stage.  

Here is an example of how to load and parse the test vectors:

```python
def load_wycheproof_test_vectors(path: str):
    testVectors = []
    try:
        with open(path, 'r') as f:
            wycheproof_json = json.loads(f.read())    
    except FileNotFoundError:
        print(f"No Wycheproof file found at: {path}")
        return testVectors

    convert_attr = {'key', 'aad', 'iv', 'msg', 'ct', 'tag'}
    for testGroup in wycheproof_json['testGroups']:
        if testGroup['ivSize'] < 64 or testGroup['ivSize'] > 1024:
            continue
        for tv in testGroup['tests']:
            for attr in convert_attr:
                if attr in tv:
                    tv[attr] = bytes.fromhex(tv[attr])
            testVectors.append(tv)
    return testVectors
```

This function reads the JSON file and converts the relevant attributes from hex strings to bytes.
Since the specific AES-GCM implementation allows only for IV to be in a specific range we filter the test groups based on the accepted IV size. 
Wycheproof provides us with a total of 283 test vectors for the specified parameters. 

## 2. Write the Testing Harness

After parsing the testing vectors, writing a testing harness is the next step. 
One can integrate the Wycheproof test vectors into the existing framework if a testing framework already exists. 
Notably, the testing framework should be flexible to expect that certain test vectors should fail, as some test vectors are specifically designed such that a correct implementation should raise an error and refuse to validate. We will demonstrate a simple example of how to write a testing harness to check encryption and decryption of the AES GCM implementation.

### Testing Harness for Encryption

The `parametrize` decorator of pytest allows us to create multiple tests that only differ in their parameterization. 
Here is an example testing harness for encryption:

```python
@pytest.mark.parametrize("tv", tvs, ids=[str(tv['tcId']) for tv in tvs])
def test_encryption(tv):
    try:
        aesgcm = AESGCM(tv['key'])
        ct = aesgcm.encrypt(tv['iv'], tv['msg'], tv['aad'])
    except ValueError as e:
        assert tv['result'] != 'valid', tv['comment']
        return
    if tv['result'] == 'valid':
        assert ct[:-16] == tv['ct'], f"Ciphertext mismatch: {tv['comment']}"
        assert ct[-16:] == tv['tag'], f"Tag mismatch: {tv['comment']}"
    elif tv['result'] == 'invalid' or tv['result'] == 'acceptable':
        assert ct[:-16] != tv['ct'] or ct[-16:] != tv['tag']
    else:
        assert False
```

This function tests the encryption process by encrypting the provided input. 
If a `ValueError` occurs during encryption, the function ensures that the test vector is expected to fail. 
If no exceptions are raised, the function verifies that the encryption results match the expected outcomes.
Specifically:
1. For test vectors expected to succeed, it checks that both the calculated tag and ciphertext are correct.
2. For test vectors expected to fail, it confirms that either the tag or the ciphertext is incorrect.

You can run the tests using pytest with the following command:

```bash
pytest /file/path/test.py
```

All 283 tests should pass.


### Testing Harness for Decryption

Similarly, to test the decryption process, we can use pytest's parameterization feature to test all combinations of test vectors. 
The decryption test function handles exceptions specific to the AES implementation and verifies the expected outcomes based on the flags provided in the Wycheproof test vectors.
If the AES implementation returns certain errors the flag provided for each Wycheproof test vectors can be used to verify the specific exceptions. 

```python
@pytest.mark.parametrize("tv", tvs, ids=[str(tv['tcId']) for tv in tvs])
def test_decryption(test_vector):
    try:
        aes_gcm = AESGCM(test_vector['key'])
        decrypted_msg = aes_gcm.decrypt(test_vector['iv'], test_vector['ct'] + test_vector['tag'], test_vector['aad'])
    except ValueError:
        assert test_vector['result'] != 'valid', test_vector['comment']
        return
    except InvalidTag:
        assert test_vector['result'] != 'valid', test_vector['comment']
        assert 'ModifiedTag' in test_vector['flags'], f"Expected 'ModifiedTag' flag: {test_vector['comment']}"
        return
    assert test_vector['result'] == 'valid', f"No invalid test case should pass: {test_vector['comment']}"
    assert decrypted_msg == test_vector['msg'], f"Decryption mismatch: {test_vector['comment']}"
```
If the cryptography library can not validate the tag an `InvalidTag` exception is raised. 
This function tests the decryption process by attempting to decrypt the provided ciphertext. 
The function covers several scenarios:
1. `ValueError`: If a `ValueError` occurs, the function checks if the test vector is supposed to fail.  
2. `InvalidTag`: If an `InvalidTag` exception is raised, the function verifies that the test vector is expected to fail and checks for the presence of the `ModifiedTag` flag.  
3. Successful Decryption: If no exceptions occur, the function confirms that the test vector is expected to succeed and that the decrypted message matches the expected plaintext.

## Summary

In this article, we demonstrated how to write a testing harness for AES-GCM using the Wycheproof test vectors and the pytest framework. 
We covered:
- Parsing the JSON test vectors.
- Writing testing functions for both encryption and decryption.
- Handling edge cases and errors within the testing framework.

By following these steps, you can ensure that your cryptographic implementation is robust and conforms to the expected standards.
