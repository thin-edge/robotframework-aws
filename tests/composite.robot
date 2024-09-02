*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Create Certificate and Thing
    ${response}=     AWS.Create Thing With Self-Signed Certificate
    Should Not Be Empty    ${response.name}
    Should Not Be Empty    ${response.policy_name}
    Should Not Be Empty    ${response.private_key}
    Should Not Be Empty    ${response.public_key}

    AWS.Thing Should Exist    ${response.name}
