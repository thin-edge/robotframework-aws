# robotframework-aws

Robot Framework Library for AWS IoT in the context of thin-edge.io

# Using it

1. Install via pip

    ```sh
    pip install git+https://github.com/reubenmiller/robotframework-aws.git@0.0.1
    ```

    Or add it to your `requirements.txt` file

    ```sh
    robotframework-aws @ git+https://github.com/reubenmiller/robotframework-aws.git@0.0.1
    ```

    Then install it via

    ```sh
    pip install -r requirements.txt
    ```

2. Create a `.env` file with the following environment variables

    ```sh
    AWS_ACCESS_KEY_ID=ABCDEFGHI
    AWS_SECRET_ACCESS_KEY=<secret>
    AWS_REGION=us-east-1
    ```

3. Create a Robot test `tests/Example.robot`

    ```robot
    *** Settings ***
    Library    AWS

    *** Test Cases ***
    Example
        Create Policy   myiotdevice
        ${aws_url}=     Get IoT URL
        DeviceLibrary.Setup
        DeviceLibrary.Execute Command     tedge config set aws.url ${aws_url}
        DeviceLibrary.Execute Command     tedge connect aws
    ```

4. Run the test

    ```sh
    robot tests/Example.robot
    ```

## Library docs

You can generate the docs yourself using:

```sh
libdoc AWS/AWS.py show > AWS/AWS.rst
```

Or the more interactive html documentation using:

```sh
libdoc AWS/AWS.py AWS/AWS.html
```

## Development

Before submitting a PR, make sure you run the formatting and linting against your code to ensure you don't have an formatting or linting errors.

You can run the formatting and linting by first installing the development dependencies, using the following [just](https://github.com/casey/just) tasks:

```sh
just venv
just install_dev
```

After the dependencies have been installed, run the linting/formatting task and check the output.

```sh
just lint
```

The pylint output should rate your code as 10.00/10. Below is an example of the console output:

```
Your code has been rated at 10.00/10 (previous run: 10.00/10, +0.00)
```
