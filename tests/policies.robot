*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Create a new Policy
    [Setup]    AWS.Delete Policy    hello_world    missing_ok=${True}
    ${policy}=    AWS.Create Policy    hello_world
    Should Not Be Empty    ${policy}
    ${policy2}=    AWS.Get Policy    hello_world
    Should Be Equal    ${policy["policyArn"]}    ${policy2["policyArn"]}

Deleting a non-existent Policy should not throw an error
    AWS.Delete Policy    does_not_exist

Deleting a non-existent Policy should throw an error
    Run Keyword And Expect Error    ResourceNotFoundException*    AWS.Delete Policy    does_not_exist    missing_ok=${False}

Assert that a policy exists
    AWS.Create Policy    testpolicy001
    AWS.Policy Should Exist    testpolicy001

Fails if policy does not exist
    Run Keyword And Expect Error    ResourceNotFoundException*    AWS.Policy Should Exist     dummypolicy
