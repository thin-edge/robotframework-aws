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
