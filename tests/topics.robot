*** Settings ***

Resource            ./resources/common.resource
Library             AWS

*** Test Cases ***

Get Local Command Topic
    ${name}    AWS.Start MQTT Logger
    ${topic}    AWS.Get Local Command Topic    example
    Should Be Equal    ${topic}     aws/cmd/example

Get Cloud Command Topic
    ${name}    AWS.Start MQTT Logger
    ${topic}    AWS.Get Cloud Command Topic    common_name=device001    topic_suffix=foo/bar
    Should Be Equal    ${topic}     thinedge/device001/cmd/foo/bar

Get Telemetry Topic
    ${cloud_topic}    AWS.Get Cloud Telemetry Topic    common_name=device001    te_topic=te/device/main///m/environment
    Should Be Equal    ${cloud_topic}     thinedge/device001/td/device:main/m/environment

Get Registration Topic
    ${cloud_topic}    AWS.Get Cloud Telemetry Topic    common_name=device001    te_topic=te/device/main//
    Should Be Equal    ${cloud_topic}     thinedge/device001/td/device:main

Get cloud topic for the AWS shadow
    ${topic}=    AWS.Get Cloud Shadow Topic    common_name=device001    topic_suffix=foo/bar
    Should Be Equal    ${topic}     $aws/things/device001/shadow/foo/bar

Get local topic for the AWS shadow
    ${topic}=    AWS.Get Local Shadow Topic    topic_suffix=foo/bar
    Should Be Equal    ${topic}     aws/shadow/foo/bar
