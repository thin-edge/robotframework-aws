*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Start/stop MQTT logger
    ${name}    AWS.Start MQTT Logger    hello
    AWS.Stop MQTT Logger

Assert message count
    ${topic}=    AWS.Get Random Name
    ${name}    AWS.Start MQTT Logger    ${topic}
    Publish MQTT Message    ${topic}    world
    ${messages}=    Should Have MQTT Messages    topic=${topic}        min_count=1
    Should Not Be Empty    ${messages}

Assert MQTT message
    ${topic}=    AWS.Get Random Name
    ${name}    AWS.Start MQTT Logger    ${topic}
    Publish MQTT Message    ${topic}    world
    ${messages}=    Should Have MQTT Messages    topic=${topic}
    Should Not Be Empty    ${messages}
