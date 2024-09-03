"""AWS MQTT Logger
"""

import logging
import re
import json
from dataclasses import dataclass
from typing import Any, List, Dict, Optional
from threading import Event

import certifi
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
from AWSIoTPythonSDK.core.protocol.paho.client import MQTTMessage
from paho.mqtt.matcher import MQTTMatcher

from .date import to_date, RelativeTime


# Configure logging
logger = logging.getLogger("AWSIoTPythonSDK.core")
logger.setLevel(logging.DEBUG)
streamHandler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
streamHandler.setFormatter(formatter)
logger.addHandler(streamHandler)


class Message:
    """MQTT Message"""

    def __init__(self, message: MQTTMessage) -> None:
        self.message = message

    @property
    def timestamp(self) -> float:
        """Timestamp in seconds"""
        return self.message.timestamp

    @property
    def topic(self) -> str:
        """Topic"""
        return self.message.topic

    @property
    def payload(self) -> bytes:
        """Payload"""
        return self.message.payload

    @property
    def payload_text(self) -> str:
        """Payload as text"""
        if callable(getattr(self.message.payload, "decode", None)):
            return self.message.payload.decode("utf-8")

        return self.message.payload

    def __repr__(self) -> str:
        return json.dumps(self.to_dict())

    def to_dict(self):
        """Convert the message to a dictionary"""
        return {
            "timestamp": self.timestamp,
            "topic": self.topic,
            "payload": self.payload_text,
        }


@dataclass
class MQTTLoggerOptions:
    """MQTT Logger Options"""

    # Your AWS IoT custom endpoint
    host: str = ""

    # Port number override
    port: int = 0

    # Use MQTT over WebSocket
    use_websocket: bool = True

    # Root CA file path
    root_ca: str = ""

    # Targeted client id
    client_id: str = "MQTTLogger"

    # Private key file path
    private_key: str = ""

    # Certificate file path
    public_key: str = ""

    def __post_init__(self):
        # Port defaults
        if self.use_websocket and not self.port:
            self.port = 443

        if not self.use_websocket and not self.port:
            self.port = 8883

        if not self.use_websocket and (not self.public_key or not self.private_key):
            raise ValueError("Missing credentials for authentication.")

        if not self.root_ca:
            self.root_ca = certifi.where()


class MQTTLogger:
    """MQTT Logger

    The MQTT Logger subscribes to an MQTT topic and saves all of the received messages so
    that assertions can be made against the recorded messages
    """

    def __init__(self, options: MQTTLoggerOptions) -> None:
        self.options = options
        self._client = None
        self._messages = []

    @property
    def messages(self) -> List[Message]:
        """Get list of received MQTT messages"""
        return self._messages

    def create(self):
        """Create an AWS MQTT client"""
        options = self.options

        # init client
        aws_client = None
        if self.options.use_websocket:
            aws_client = AWSIoTMQTTClient(options.client_id, useWebsocket=True)
            aws_client.configureEndpoint(options.host, options.port)
            aws_client.configureCredentials(options.root_ca)
        else:
            aws_client = AWSIoTMQTTClient(options.client_id)
            aws_client.configureEndpoint(options.host, options.port)
            aws_client.configureCredentials(
                options.root_ca, options.private_key, options.public_key
            )

        aws_client.configureAutoReconnectBackoffTime(1, 32, 20)
        aws_client.configureOfflinePublishQueueing(
            -1
        )  # Infinite offline Publish queueing
        aws_client.configureDrainingFrequency(2)
        aws_client.configureConnectDisconnectTimeout(10)
        aws_client.configureMQTTOperationTimeout(5)
        aws_client.onMessage = self.__on_message
        aws_client.disableMetricsCollection()
        return aws_client

    def __on_message(self, message: MQTTMessage):
        logger.info("Received new message")
        self._messages.append(Message(message))

    def publish(self, topic: str, payload: Any, qos: int = 1):
        """Publish an MQTT message"""
        self._client.publish(
            topic,
            payload,
            QoS=qos,
        )

    def start(self, topic: str, qos: int = 1):
        """Start the MQTT Logger if it has not already been started"""
        if self._client:
            return

        self._client = self.create()

        # Connect and subscribe to AWS IoT
        assert self._client.connect(), "Could not connect AWS MQTT Client"

        event = Event()

        def acked(*_args, **_kwargs):
            logger.info("Subscription acknowledged")
            event.set()

        self._client.subscribeAsync(topic, qos, ackCallback=acked)
        event.wait(5)

    def stop(self) -> List[Any]:
        """Stop the MQTT logger"""
        self._client.disconnectAsync()
        return [*self._messages]

    def match_mqtt_messages(
        self,
        topic: Optional[str] = None,
        message_pattern: Optional[str] = None,
        date_from: Optional[RelativeTime] = None,
        date_to: Optional[RelativeTime] = None,
        **kwargs,
    ) -> List[Dict[str, Any]]:
        """Match mqtt messages using different types of filters

        Args:
            topic (str): Filter by topic
        """

        if date_from:
            date_from = to_date(date_from).timestamp()

        if date_to:
            date_to = to_date(date_to).timestamp()

        message_pattern_re = None
        if message_pattern:
            message_pattern_re = re.compile(message_pattern, re.IGNORECASE)

        mqtt_matcher = MQTTMatcher()
        if topic:
            mqtt_matcher[topic] = True

        matches = []
        for message in self.messages:
            if date_to is not None and message.timestamp < date_from:
                continue

            if date_from is not None and message.timestamp > date_to:
                continue

            if message_pattern_re is not None and message_pattern_re.match(
                message.payload
            ):
                continue

            if topic is not None and not _mqtt_topic_match(mqtt_matcher, message.topic):
                continue

            matches.append(message)

        return matches


def _mqtt_topic_match(matcher, topic) -> bool:
    """Match an MQTT topic"""
    try:
        next(matcher.iter_match(topic))
        return True
    except StopIteration:
        return False
