*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Create certificate key pair
    ${certs}=    AWS.Create Certificate Key Pair
    Should Not Be Empty    ${certs}
    [Teardown]    Delete Certificate    ${certs["certificateId"]}

Create CSR using AWS CA
    ${policy_name}    AWS.Get Random Name
    AWS.Create Policy    ${policy_name}    auto_delete=${True}

    ${common_name}    AWS.Get Random Name
    ${key_path}=    AWS.Create Certificate Private Key
    ${csr}=    AWS.Create CSR    ${key_path}    ${common_name}
    Should Not Be Empty    ${csr}

    ${cert}=    AWS.Create Certificate From CSR    ${csr}    policy_name=${policy_name}    auto_delete=${True}
    Should Not Be Empty    ${cert["certificatePem"]}

Upload self-signed certificate
    ${policy_name}    AWS.Get Random Name
    AWS.Create Policy    ${policy_name}    auto_delete=${True}

    ${common_name}    AWS.Get Random Name
    ${key_path}=    AWS.Create Certificate Private Key
    ${certicicate}=    Create Self-Signed Certificate    ${key_path}    common_name=${common_name}
    ${response}=    Register Self-Signed Certificate    ${certicicate}    policy_name=${policy_name}
    Should Not Be Empty    ${response}
