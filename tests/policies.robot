*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Create a new Policy
    ${name}=    AWS.Get Random Name
    ${policy}=    AWS.Create Policy    ${name}
    Should Not Be Empty    ${policy}
    ${policy2}=    AWS.Get Policy    ${name}
    Should Be Equal    ${policy["policyArn"]}    ${policy2["policyArn"]}

Deleting a non-existent Policy should not throw an error
    AWS.Delete Policy    does_not_exist

Deleting a non-existent Policy should throw an error
    Run Keyword And Expect Error    ResourceNotFoundException*    AWS.Delete Policy    does_not_exist    missing_ok=${False}

Assert that a policy exists
    ${name}=    AWS.Get Random Name
    AWS.Create Policy    ${name}
    AWS.Policy Should Exist    ${name}

Fails if policy does not exist
    Run Keyword And Expect Error    ResourceNotFoundException*    AWS.Policy Should Exist     dummypolicy
