"""AWS Robot Framework library
"""

import json
import logging
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from robot.api.deco import keyword, library
from robot.libraries.BuiltIn import BuiltIn
from .policy import Policy

IoTPolicy = Dict[str, Any]

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s %(module)s -%(levelname)s- %(message)s"
)
logger = logging.getLogger(__name__)

try:
    from . import _version

    __version__ = _version.version
except Exception:
    __version__ = "0.0.0"

__author__ = "thin-edge.io"


@library(scope="GLOBAL", auto_keywords=False)
class AWS:
    """AWS Robot Framework Library

    Keywords used to interact and make assertions with AWS IoT focusing
    on the areas related to thin-edge.io

    Example.robot::
        *** Settings ***
        Library    AWS
        Library    DeviceLibrary

        *** Test Cases ***
        Example
            Create Policy   myiotdevice
            ${aws_url}=     Get IoT URL
            DeviceLibrary.Setup
            DeviceLibrary.Execute Command     tedge config set aws.url ${aws_url}
            DeviceLibrary.Execute Command     tedge connect aws
    """

    ROBOT_LISTENER_API_VERSION = 3

    # Constructor
    def __init__(
        self,
    ):
        self._on_cleanup = []
        self._iot_client = None
        self.session: boto3.Session = None
        self._account_id = ""

        load_dotenv()

        # Load settings from global variable
        self.config = BuiltIn().get_variable_value(r"&{AWS_CONFIG}", {}) or {}

        self._create_session(self.access_key_id, self.access_key, self.region)

        # pylint: disable=invalid-name
        self.ROBOT_LIBRARY_LISTENER = self

    @property
    def access_key_id(self):
        return self.config.get("access_key_id")

    @property
    def access_key(self):
        return self.config.get("access_key")

    @property
    def region(self):
        return self.config.get("region")

    @property
    def account_id(self):
        if not self._account_id:
            account_id = self.session.client("sts").get_caller_identity()["Account"]
            self._account_id = account_id
        return self._account_id

    #
    # Hooks
    #
    def end_suite(self, _data: Any, result: Any):
        """End suite hook which is called by Robot Framework
        when the test suite has finished

        Args:
            _data (Any): Test data
            result (Any): Test details
        """
        for func in self._on_cleanup:
            if callable(func):
                try:
                    func()
                except Exception as ex:
                    logger.warning("Cleanup function failed. error=%s", ex)

        self._on_cleanup.clear()

    def _create_session(
        self, aws_access_key_id: str, aws_secret_access_key: str, region_name: str = ""
    ):
        """
        Creates an AWS session using the provided access key, secret key, and optional region.
        Returns a success message if the session creation is successful.
        """
        try:
            self.session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region_name,
            )
            # Try to create an IoT client to verify the session
            # Perform a simple operation like listing IoT policies to verify the connection
            self.get_iot_url()
            return self.session
        except ClientError as e:
            raise RuntimeError(f"Failed to create AWS session: {e}")

    @property
    def iot_client(self):
        if not self._iot_client:
            self._iot_client = self.session.client("iot")
        return self._iot_client

    #
    # Account information
    #
    @keyword("Get IoT URL")
    def get_iot_url(self):
        """
        Retrieves the IoT endpoint for the AWS account
        """
        response = self.iot_client.describe_endpoint(endpointType="iot:Data-ATS")
        return response["endpointAddress"]

    @keyword("Get Account ID")
    def get_account_id(self) -> str:
        """Get the AWS account ID related to your credentials"""
        return self.account_id

    #
    # IoT Policy Management
    #
    @keyword("Policy Should Exist")
    def policy_should_exist(self, name: str) -> IoTPolicy:
        """
        Checks if the specified IoT policy exists
        """
        policy = self.iot_client.get_policy(policyName=name)
        assert policy
        return policy

    @keyword("Get Policy")
    def get_policy(self, name: str) -> IoTPolicy:
        return self.iot_client.get_policy(policyName=name)

    @keyword("Delete Policy")
    def delete_policy(self, name: str, missing_ok: bool = True):
        logger.info("Deleting policy. name=%s", name)
        try:
            self.iot_client.delete_policy(policyName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                if missing_ok:
                    logger.info(
                        "Nothing to delete as policy does not exist. name=%s", name
                    )
                    return
                raise
            raise

    @keyword("Create Policy")
    def create_policy(
        self, name, policy=None, exists_ok: bool = True, auto_delete: bool = True
    ) -> IoTPolicy:
        """
        Creates a new IoT policy with the provided name and reads the policy document from a file
        """
        try:
            if not policy:
                policy_document = Policy().create(self.region, self.account_id)
            elif isinstance(policy, str):
                policy_document = json.loads(policy)
            else:
                policy_document = policy

            response = self.iot_client.create_policy(
                policyName=name, policyDocument=json.dumps(policy_document)
            )

            if auto_delete:
                self._on_cleanup.append(lambda name=name: self.delete_policy(name))

            return response
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
                if exists_ok:
                    return self.get_policy(name)
                raise
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Error decoding JSON. %s", e)


if __name__ == "__main__":
    pass
