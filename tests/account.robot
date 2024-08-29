*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Get IoT Url
    ${url}=    AWS.Get IoT URL
    Should Not Be Empty    ${url}

Get Account ID
    ${value}=    AWS.Get Account ID
    Should Not Be Empty    ${value}
