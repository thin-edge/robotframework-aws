*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Create Thing with auto cleanup
    ${name}    AWS.Get Random Name
    ${thing}=    AWS.Create Thing    ${name}    auto_delete=${True}
    Should Not Be Empty    ${thing}
    
    ${response}=    AWS.Thing Should Exist    ${name}
    Should Not Be Empty    ${response}

Create Thing with Principal
    ${thing_name}=    AWS.Get Random Name

    ${policy_name}=    AWS.Get Random Name
    AWS.Create Policy    ${policy_name}

    ${cert_key_path}=    AWS.Create Certificate Private Key
    ${cert_pub}=    AWS.Create Self-Signed Certificate    ${cert_key_path}    ${thing_name}
    ${cert_response}=    Register Self-Signed Certificate    ${cert_pub}    policy_name=${policy_name}

    AWS.Create Thing    ${thing_name}    certificate_arn=${cert_response["certificateArn"]}
    AWS.Thing Should Exist    ${thing_name}

Delete Thing
    ${name}    AWS.Get Random Name
    ${thing}=    AWS.Create Thing    ${name}    auto_delete=${False}
    Should Not Be Empty    ${thing}
    
    ${response}=    AWS.Thing Should Exist    ${name}
    Should Not Be Empty    ${response}

    AWS.Delete Thing    ${name}

Delete non-existent thing
    # Deleting a non-existent thing should not 
    AWS.Delete Thing    does_not_exist

Check if thing exists
    AWS.Thing Should Not Exist    does_not_exist

Throws an error if thing exists
    ${name}    AWS.Get Random Name
    AWS.Create Thing    ${name}
    Run Keyword And Expect Error    ResourceExistsException*    AWS.Thing Should Not Exist    ${name}
