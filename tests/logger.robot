*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Start/stop MQTT logger
    ${name}    AWS.Start MQTT Logger    hello
    AWS.Stop MQTT Logger

Assert message count
    ${name}    AWS.Start MQTT Logger    hello
    Publish MQTT Message    hello    world
    ${messages}=    Should Have MQTT Messages    min_count=1
    Should Not Be Empty    ${messages}

Assert MQTT message
    ${name}    AWS.Start MQTT Logger    hello
    Publish MQTT Message    hello    world
    ${messages}=    Should Have MQTT Messages    topic=hello
    Should Not Be Empty    ${messages}
