[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/xZdH_0p-)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=17719216)

# COMP0061 -- Privacy Enhancing Technologies -- Lab on encryption, elliptic curves, and signatures

This lab will introduce the basics of Pycryptodome, encryption, signatures, and an end-to-end encryption system.

### Structure of Labs

The structure of most of the labs will be similar: two Python files will be provided.

- The first is named `lab_X.py` and contains the structure of the code you need to complete.
- The second is named `lab_X_test.py` and contains unit tests (written for the Pytest library) that you may execute to
  partially check your answers.

Note that the tests passing is a necessary but not sufficient condition to fulfill each task. There are programs that
would make the tests pass that would still be invalid (or blatantly insecure) implementations.

The only dependency your Python code should have, besides Pytest and the standard library, is the Pycryptodome library.

The Pycryptodome documentation is [available on-line here](https://www.pycryptodome.org/src/introduction).

### Checking out code

Check out the code by using your preferred git client (e.g., git command line client, GitHub Desktop, Sourcetree).

**_Alternatively_**, you can use the GitHub Codespaces feature to check out and work on the code in the cloud.

### Setup

The intended environment for this lab is the Linux operating system with Python 3 installed.

#### Local virtual environment

To create a local virtual environment, activate the virtual environment, and install the dependencies needed for the
lab, run the following commands in the lab folder:

```shell
python3 -m venv .venv/
source .venv/bin/activate
pip3 install -r requirements.txt
```

On subsequent runs, you will only need to activate the virtualenv.

```shell
source .venv/bin/activate
```

To exit the virtual environment, run:

```shell
deactivate
```

The virtual environment is needed to run the unit tests locally.

#### Development containers

As an alternative to a local virtual environment, we provide the setup files for
[development containers](https://code.visualstudio.com/docs/remote/containers) which use
[Docker](https://docs.docker.com/get-docker/) to create a separate development environment for each repository and
install the required libraries. You don't need to know how to use Docker to use development containers. These are
supported by popular IDEs such as [Visual Studio Code](https://code.visualstudio.com/) and
[PyCharm](https://www.jetbrains.com/pycharm/).

#### GitHub Codespaces

Another alternative for running your code is to use GitHub Codespaces which use cloud-based development containers. On
GitHub, the "<> Code" button at the top right of the repository page will have a Codespaces tab. This allows you to
create a cloud-based environment to work on the assignment. You still need to use `git` to commit and push your work
when working in a codespace.

#### GitHub Classroom tests

The tests are the same as the ones that run as part of the GitHub Classroom automated marking system, so you can also
run the tests by simply committing and pushing your changes to GitHub, without the need for a local setup or even having
Python 3 installed.

### Working with unit tests

Unit tests are run from the command line by executing the command:

```shell
$ pytest -v
```

Note the `-v` flag toggles a more verbose output. If you wish to inspect the output of the full tests run you may pipe
this command to the `less` utility (execute `man less` for a full manual of the less utility):

```shell
$ pytest -v | less
```

You can also run a selection of tests associated with each task by adding the Pytest marker for each task to the Pytest
command:

```shell
$ pytest -v -m task1
```

The markers are defined in the test file and listed in `pytest.ini`.

You may also select tests to run based on their name using the `-k` flag. Have a look at the test file to find out the
function names of each test. For example the following command executes the very first test of Lab 1:

```shell
$ pytest -v -k test_libs_present
```

The full documentation of pytest is [available here](http://pytest.org/latest/).

### What you will have to submit

The deadline for all labs is at the end of term but labs will be progressively released throughout the term, as new
concepts are introduced. We encourage you to attempt labs as soon as they are made available and to use the dedicated
lab time to bring up any queries with the TAs.

Labs will be checked using GitHub Classroom, and the tests will be run each time you push any changes to the `main`
branch of your GitHub repository. The latest score from automarking should be shown in the Readme file. To see the test
runs, look at the Actions tab in your GitHub repository.

Make sure the submitted `lab_ec.py` file at least satisfies the tests, without the need for any external dependency
except the Python standard libraries and the Pycryptodome library. Only submissions prior to the GitHub Classroom
deadline will be marked, so make sure you push your code in time.

To re-iterate, the tests passing is a necessary but not sufficient condition to fulfill each task. All submissions will
be checked by TAs for correctness and your final marks are based on their assessment of your work.  
For full marks, make sure you have fully filled in any sections marked with `TODO` comments, including answering any
questions in the comments of the `lab_ec.py`.

## TASK 1 -- Basic installation \[1 point\]

> Ensure libraries are installed on the system. Ensure the lab code can be imported.

### Hints

- Execute the following command to ensure the tests run:

  ```shell
  $ pytest -v -m task1
  ```

- If everything is installed correctly the two selected tests should both pass without a problem, and without any
  modification to the code file. This first task is meant to ensure everything is installed properly. If it fails, let
  us know by tagging the TAs in a comment on your feedback pull request on GitHub.

## TASK 2 -- Symmetric encryption using AES-GCM \[1 point\]

> Implement encryption and decryption functions that simply performs AES GCM symmetric encryption and decryption using
> the functions in `Cryptodome.Cipher`.

### Hints

- This first task lets you explore how to use AES-GCM from `Cryptodome.Cipher`. You may run the tests for this task
  using:

  ```shell
  $ pytest -v -m task2
  ```

- Consider these imports:

  ```python
  from os import urandom
  from Cryptodome.Cipher import AES
  ```

- Note that `urandom` produces cryptographically strong bytes, which is handy for keys and initialisation vectors.

- The `Cryptodome.Cipher` package provides the AES class, so you only need to instantiate it correctly for GCM.

- The documentation for `Cryptodome.Cipher` is [available here](https://www.pycryptodome.org/src/cipher/modern).

## TASK 3 -- Understand Elliptic Curve Arithmetic \[1 point\]

> - Test if a point is on a curve.
> - Implement Point addition.
> - Implement Point doubling.
> - Implement Scalar multiplication (double & add).
> - Implement Scalar multiplication (Montgomery ladder).
>
> _Must not use any of the `from Cryptodome.PublicKey.ECC.ECCpoint`_. Only the `Integer` implementation from
> `Cryptodome.Math.Numbers`!

### Hints

- The five (5) tests for this task run through:

  ```shell
  $ pytest -v -m task3
  ```

- `Cryptodome.Math.Numbers.Integer` provides facilities to do fast computations on `big numbers`.

  ```python
  from Cryptodome.Math.Numbers import Integer
  ```

- The Integer type works as you would expect but has some additional functionality, including and `invert(p)` method.

- The documentation strings for each function provide guidance as to the algorithms you need to implement.

- The tests provide you some guidance as to the inputs and outputs expected by each function.

- The lecture slides include the formulas for performing EC addition and doubling. Make use of them.

- Note that the neutral element `(infinity)` is encoded in `(x, y)` coordinates as `(None, None)`. Make sure you handle
  this input correctly. Do you also output it correctly?

## TASK 4 -- Standard ECDSA signatures \[1 point\]

> - Implement a key / param generation
> - Implement ECDSA signature using `Cryptodome.Signature.DSS`
> - Implement ECDSA signature verification using `Cryptodome.Signature.DSS`

### Hints

- The tests for this task run through:

  ```shell
  $ pytest -v -m task4
  ```

- This task lets you practice generating and verifying digital signatures. This is a vital skill, and you do not have to
  know how digital signature work to make use of them.

- Note, that `Cryptodome.Signature.DSS` provides both facilities to generate and verify signatures. The documentation is
  [available here](https://www.pycryptodome.org/src/signature/dsa). Do use it.

- It is necessary to use a secure hash function to hash an input before signing or verifying it (self study: why is
  that?). Luckily, `Cryptodome.Hash` contains a number of functions, including `SHA256`.

## TASK 5 -- Diffie-Hellman Key Exchange and Derivation \[2 point: 1 point for DHKE and 1 point for test coverage\]

> - use Bob's public key to derive a shared key.
> - Use Bob's public key to encrypt a message.
> - Use Bob's private key to decrypt the message.

### Hints

- The tests for this task run through:

  ```shell
  $ pytest -v -m task5
  ```

- This time you may use `ECCPoint` to implement an EC Diffie-Hellman exchange.

- Also: have a look at the provided key generation function to guide the remaining of the implementation.

- This task requires you to implement a simple hybrid encryption scheme, guided by the scheme presented in the slides.
  In a nutshell you may assume that Alice and Bob are aware of each other's public keys, and use those to eventually
  derive a shared key. This shared key is then passed through a key derivation function (what should you use for key
  derivation?) to obtain a key for an AES-GCM cipher to protect the integrity and confidentiality of a message.
- You may find the `_point_to_bytes` function useful for the input to the key derivation function.

- You may assume that the public key passed to `dh_encrypt` is the public encryption key of the recipient, and the
  `alice_sig` parameter is the signature key of Alice the sender. Conversely, the `priv` parameter of `dh_encrypt` is
  the recipient's (Bob) secret decryption key and `alice_ver` a public verification key for a signature scheme.

- You have already implemented much of what's needed for this task in tasks 2 and 4. Call the functions rather than
  reimplement the encryption and signing.

- As part of this task you MUST implement a number of tests to ensure that your code is correct. Stubs for tests are
  provided, namely `test_encrypt`, `test_decrypt` (which are self-explanatory), and `test_fails_*` which are meant to
  check for conditions under which the decryption or signature verification must fail. At least these should be
  implemented in the code file, but feel free to implement more.

- Your tests should run when you execute the following command, which produces a report on your test coverage. Ensure
  all lines of code are fully covered by the test regime!

  ```shell
  $ pytest --cov-report html --cov lab_ec
  ```

## TASK 6 -- Time EC scalar multiplication \[0 points\]

> _Open Task - Optional_
>
> Time your implementations of scalar multiplication (use time.perf_counter_ns() for measurements) for different scalar
> sizes

### Hints

- If you are set on answering this question, you must time your execution of scalar multiplication to investigate timing
  side channels.

- Once you have observed timing channels that may leak secrets, go back and fix the scalar multiplication code to run in
  constant time.
