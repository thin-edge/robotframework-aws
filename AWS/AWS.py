"""AWS Robot Framework library
"""

import datetime
import json
import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError
from dotenv import load_dotenv
from robot.api.deco import keyword, library
from robot.libraries.BuiltIn import BuiltIn, RobotNotRunningError

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .policy import Policy
from .random import random_name

IoTPolicy = Dict[str, Any]

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s %(module)s -%(levelname)s- %(message)s"
)
logger = logging.getLogger(__name__)

try:
    from . import _version

    __version__ = _version.version
# pylint: disable=broad-exception-caught
except Exception:
    __version__ = "0.0.0"

__author__ = "thin-edge.io"


@dataclass
class ThingData:
    """Thing Data"""

    name: str
    policy_name: str
    private_key: str
    public_key: str
    url: str


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

    # pylint: disable=invalid-name
    # pylint: disable=too-many-public-methods

    ROBOT_LISTENER_API_VERSION = 3

    # Constructor
    def __init__(
        self,
    ):
        self._on_cleanup = []
        self._iot_client = None
        self._session: boto3.Session = None
        self._account_id = ""
        self.config = {}

        load_dotenv()

        # Load settings from global variable
        try:
            self.config = BuiltIn().get_variable_value(r"&{AWS_CONFIG}", {}) or {}
        except RobotNotRunningError:
            pass

        # pylint: disable=invalid-name
        self.ROBOT_LIBRARY_LISTENER = self

    @property
    def access_key_id(self) -> str:
        """AWS Access Key ID"""
        return self.config.get("access_key_id")

    @property
    def access_key(self) -> str:
        """AWS Access Key"""
        return self.config.get("access_key")

    @property
    def region(self) -> str:
        """AWS Region"""
        return self.config.get("region")

    @property
    def account_id(self) -> str:
        """AWS Account ID"""
        if not self._account_id:
            account_id = self.session.client("sts").get_caller_identity()["Account"]
            self._account_id = account_id
        return self._account_id

    @property
    def session(self):
        """AWS Session"""
        # lazy initialization of session
        if self._session is None:
            self._session = self._create_session(
                self.access_key_id, self.access_key, self.region
            )
        return self._session

    #
    # Hooks
    #
    def append_cleanup(self, func, *args, **kwargs):
        """Append a cleanup task"""

        def _cleanup():
            func(*args, **kwargs)

        self._on_cleanup.append(_cleanup)

    def prepend_cleanup(self, func, *args, **kwargs):
        """Prepend a cleanup task"""

        def _cleanup():
            func(*args, **kwargs)

        self._on_cleanup.insert(0, _cleanup)

    def end_suite(self, _data: Any, _result: Any):
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
                # pylint: disable=broad-exception-caught
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
            # Load settings from global variable
            self.config = BuiltIn().get_variable_value(r"&{AWS_CONFIG}", {}) or {}

            self._session = boto3.Session(
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                region_name=region_name,
            )
            # Try to create an IoT client to verify the session
            # Perform a simple operation like listing IoT policies to verify the connection
            self.get_iot_url()
            return self._session
        except ClientError as e:
            raise RuntimeError("Failed to create AWS session") from e

    @property
    def iot_client(self):
        """Get AWS IoT Client"""
        if not self._iot_client:
            self._iot_client = self.session.client("iot")
        return self._iot_client

    #
    # Utils
    #
    @keyword("Get Random Name")
    def get_random_name(self) -> str:
        """Generate a random name"""
        return random_name()

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
        """Get a Policy by name

        Arguments:
            name (str): Policy name
        """
        return self.iot_client.get_policy(policyName=name)

    @keyword("Delete Policy")
    def delete_policy(self, name: str, missing_ok: bool = True):
        """Delete a policy

        Arguments:
            name (str): Policy name
            missing_ok (bool, optional): Don't throw an error if the policy does not exist.
                Defaults to True
        """
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
        self,
        name: str,
        policy: Optional[IoTPolicy] = None,
        exists_ok: bool = True,
        auto_delete: bool = True,
    ) -> IoTPolicy:
        """
        Creates a new IoT policy with the provided name and reads the policy document from a file

        Arguments:
            name: Policy name
            policy (IoTPolicy, optional): Policy definition. If not provided then the default
                thin-edge.io policy definition will be used.
            exists_ok (bool, optional): Don't thrown an error if the policy name already exists.
                Defaults to True
            auto_delete (bool, optional): Automatically delete policy on suite teardown.
                Defaults to True
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
                self.append_cleanup(self.delete_policy, name)

            return response
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceAlreadyExistsException":
                if exists_ok:
                    return self.get_policy(name)
                raise
        except json.JSONDecodeError as e:
            raise RuntimeError("Error decoding JSON") from e

        raise RuntimeError("Unexpected error. The code should not reach here")

    #
    # Certificates
    #
    @keyword("Create Self-Signed Certificate")
    def create_self_signed_certificate(
        self,
        key_path: str,
        common_name: str,
        validity_days: int = 10,
        country: str = "DE",
        state: str = "NRW",
        locality_name: str = "Duesseldorf",
        organization: str = "thin-edge.io",
    ) -> str:
        """Create a Self-Signed Certificate

        Arguments:
            key_path (str): Path to the private key (this must exist)
            common_name (str): Certificate common name
            validity_days (int, optional): Number of days the certificate should be valid for.
                Defaults to 10
            country (str, optional): Country Code. Defaults to DE
            state (str, optional): State or Province. Defaults to NRW
            locality_name (str, optional): Locality name. Defaults to Duesseldorf
            organization (str, optional): Organization. Defaults to thin-edge.io

        Returns:
            str: Public certificate in PEM format
        """
        # pylint: disable=too-many-arguments
        key = load_pem_private_key(Path(key_path).read_bytes(), password=None)
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                # Our certificate will be valid for 10 days
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=validity_days)
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName(f"{common_name}.local"),
                    ]
                ),
                critical=False,
                # Sign our certificate with our private key
            )
            .sign(key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    @keyword("Register Self-Signed Certificate")
    def register_certificate(
        self,
        certificate_pem: str,
        status="ACTIVE",
        policy_name: str = "",
        auto_delete: bool = True,
    ) -> Dict[str, Any]:
        """Register a self signed certificate which does not have a CA

        Arguments:
            certificate_pem: Public certificate contents in PEM format
            status (str, optional): Certificate status. Defaults to ACTIVE
            policy_name (str, optional). Policy to attach to the certificate.
                Defaults to None
            auto_delete (bool, optional): Automatically delete the certificate
                on suite teardown. Defaults to True

        Returns:
            Dict[str, Any]: AWS response with the registered certificate
        """
        response = self.iot_client.register_certificate_without_ca(
            certificatePem=certificate_pem,
            status=status,
        )
        if auto_delete:
            self.prepend_cleanup(self.delete_certificate, response["certificateId"])

        if policy_name:
            self.iot_client.attach_policy(
                policyName=policy_name,
                target=response["certificateArn"],
            )

        return response

    @keyword("Create Certificate Key Pair")
    def create_certificate_key(
        self,
        private_key: Optional[str] = None,
        public_key: Optional[str] = None,
        active=True,
    ) -> Dict[str, Any]:
        """Create a certificate key pair (private and public keys) by using the
        AWS service.

        Arguments:
            public_key (str, optional): File path where the public cert contents should
                be written to. Defaults to None
            private_key (str, optional): File path where the public cert contents should
                be written to. Defaults to None
            activate (bool, optional): Certificate activation status. Defaults to True

        Returns:
            Dict[str, Any]: AWS response containing both the private and public keys
                as well as other meta information about the request
        """
        response = self.iot_client.create_keys_and_certificate(setAsActive=active)
        if public_key is not None:
            with open(public_key, "w", encoding="utf-8") as file:
                file.write(response["certificatePem"])

        if private_key is not None:
            with open(private_key, "w", encoding="utf-8") as file:
                file.write(response["keyPair"]["PrivateKey"])

        return response

    @keyword("Create Certificate Private Key")
    def create_cert_private_key(
        self, key_path: Optional[str] = None, auto_delete=True
    ) -> str:
        """Create a private key. If the key path is not provided then a temporary file
        location will be used

        Arguments:
            key_path (str, optional): Where to store the private key.
                Defaults to a temporary file
            auto_delete (bool, optional): Automatically delete the key at suite teardown.
                Defaults to True

        Returns:
            str: Path to the private key
        """
        if key_path is None:
            # pylint: disable=consider-using-with
            key_path = tempfile.NamedTemporaryFile(delete=False).name

        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Write our key to disk for safe keeping
        with open(key_path, "wb") as f:
            f.write(
                key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        if auto_delete:
            self.append_cleanup(Path(key_path).unlink, missing_ok=True)

        return key_path

    @keyword("Create CSR")
    def create_csr(
        self,
        key_path: str,
        common_name: str,
        country: str = "DE",
        state: str = "NRW",
        locality_name: str = "Duesseldorf",
        organization: str = "thin-edge.io",
    ) -> str:
        """Create a Certificate Signing Request given a private key

        Arguments:
            key_path (str): Path to the private key
            common_name (str): Certificate Common Name
            country (str, optional): Country Code. Defaults to DE
            state (str, optional): State or Province. Defaults to NRW
            locality_name (str, optional): Locality name. Defaults to Duesseldorf
            organization (str, optional): Organization. Defaults to thin-edge.io

        Returns:
            str: Public certificate in PEM format
        """
        # pylint: disable=too-many-arguments
        key = load_pem_private_key(Path(key_path).read_bytes(), password=None)

        # Generate a CSR
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(
                x509.Name(
                    [
                        # Provide various details about who we are.
                        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, locality_name),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
                        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                    ]
                )
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        # Describe what sites we want this certificate for.
                        x509.DNSName(f"{common_name}.local"),
                    ]
                ),
                critical=False,
                # Sign the CSR with our private key.
            )
            .sign(key, hashes.SHA256())
        )

        return csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    @keyword("Create Certificate From CSR")
    def create_certificate_from_csr(
        self,
        csr: str,
        cert_path: Optional[str] = None,
        policy_name: Optional[str] = None,
        auto_delete=True,
    ) -> Dict[str, Any]:
        """Create public certificate from an existing Certificate Signing Request

        Arguments:
            csr (str): Certificate signing request in PEM format
            cert_path (str, optional): Path to write the certificate to (if defined).
                Defaults to None
            policy_name (str, optional): AWS Policy to attach to the certificate.
                Defaults to None
            auto_delete (bool, optional): Automatically delete the certificate on suite teardown.
                Defaults to True

        Returns:
            Dict[str, Any]: AWS response which includes the public certificate
                under "certificatePem"
        """
        response = self.iot_client.create_certificate_from_csr(
            certificateSigningRequest=csr, setAsActive=True | False
        )
        if cert_path:
            with open(cert_path, "w", encoding="utf-8") as file:
                file.write(response["certificatePem"])

        if auto_delete:
            # Run early in cleanup as it has a dependency on the given policy
            self.prepend_cleanup(
                self.delete_certificate,
                response["certificateId"],
                policy_name=policy_name,
            )

        if policy_name is not None:
            self.iot_client.attach_policy(
                policyName=policy_name,
                target=response["certificateArn"],
            )

        return response

    @keyword("Delete Certificate")
    def delete_certificate(self, certificate_id: str, policy_name: str = ""):
        """Delete a certificate

        Arguments:
            certificate_id (str): Certificate id
            policy_name (str, optional): Policy name attached to the certificate
        """
        # Detach policy
        if policy_name:
            # Detaching policy requires looking up the cert's ARN
            cert_response = self.iot_client.describe_certificate(
                certificateId=certificate_id,
            )

            self.iot_client.detach_policy(
                policyName=policy_name,
                target=cert_response["certificateDescription"]["certificateArn"],
            )

        # Deactivate certificate
        self.iot_client.update_certificate(
            certificateId=certificate_id,
            newStatus="INACTIVE",
        )

        # Delete cert
        self.iot_client.delete_certificate(
            certificateId=certificate_id, forceDelete=True
        )

    #
    # Thing
    #
    @keyword("Create Thing")
    def create_thing(
        self,
        name: str,
        thing_type: str = "",
        attributes: Optional[Dict[str, Any]] = None,
        certificate_arn: Optional[str] = None,
        auto_delete: bool = True,
    ) -> Dict[str, Any]:
        """Create Thing

        Arguments:
            name (str): Thing name
            thing_type (str, optional): Thing type. Defaults to None
            attributes (Dict[str, Any], optional): Thing attributes payload. Defaults to None
            certificate_arn (str, optional): Certificate ARN to be attached as the thing principal
            auto_delete (bool, optional): Automatically delete thing on suite teardown.
                Defaults to True
        """
        # pylint: disable=too-many-arguments
        options = {
            "thingName": name,
        }
        if thing_type:
            options["thingTypeName"] = thing_type

        if attributes:
            options["attributePayload"] = attributes

        response = self.iot_client.create_thing(**options)
        if auto_delete:
            self.append_cleanup(self.delete_thing, name)

        if certificate_arn:
            self.iot_client.attach_thing_principal(
                thingName=name,
                principal=certificate_arn,
            )
            if auto_delete:
                self.prepend_cleanup(
                    self.iot_client.detach_thing_principal,
                    thingName=name,
                    principal=certificate_arn,
                )

        return response

    @keyword("Thing Should Exist")
    def assert_thing_exists(self, name: str):
        """Assert the existence of a thing

        Arguments:
            name (str): Thing name
        """
        response = self.iot_client.describe_thing(
            thingName=name,
        )
        assert response
        return response

    @keyword("Thing Should Not Exist")
    def assert_thing_does_not_exist(self, name: str):
        """Assert that a Thing does not exist

        Arguments:
            name (str): Thing name
        """
        exists = True
        try:
            self.assert_thing_exists(name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                exists = False
            else:
                raise
        assert not exists, "ResourceExistsException"

    @keyword("Delete Thing")
    def delete_thing(self, name: str, expected_version: Optional[int] = None):
        """Delete a Thing

        Arguments:
            name (str): Thing name
            expected_version (int, optional): The expected version of the thing record
                in the registry. If the version of the record in the registry does not
                match the expected version specified in the request, the DeleteThing
                request is rejected with a VersionConflictException. Defaults to None
        """
        options = {
            "thingName": name,
        }
        if expected_version is not None:
            options["expectedVersion"] = expected_version

        self.iot_client.delete_thing(**options)

    #
    # Composite
    #
    @keyword("Create Thing With Self-Signed Certificate")
    def create_thing_with_self_signed_certificates(
        self,
        name: str = "",
        policy_name: str = "",
        thing_type: str = "",
        auto_delete: bool = True,
    ) -> ThingData:
        """Create thing with newly generated self-signed certificate (private and public key)

        Random values are used for the name and policy name if they are not provided.

        Arguments:
            name (str, optional): Thing name. A randomly generated value is used if one
                is not provided
            policy_name (str, optional): Policy name to be attached to the thing.
                If a name is not provided then a new policy will be created with a randomly
                generated name.
            thing_type (str, optional): Thing type. Defaults to None
            auto_delete (bool, optional): Automatically delete thing on suite teardown.
                Defaults to True
        """
        if not name:
            name = self.get_random_name()

        if not policy_name:
            policy_name = self.get_random_name()
            self.create_policy(name=policy_name, auto_delete=auto_delete)

        cert_key_path = self.create_cert_private_key(auto_delete=auto_delete)
        public_key = self.create_self_signed_certificate(
            cert_key_path, common_name=name
        )
        cert_response = self.register_certificate(
            public_key, policy_name=policy_name, auto_delete=auto_delete
        )
        self.create_thing(
            name,
            thing_type=thing_type,
            certificate_arn=cert_response["certificateArn"],
            auto_delete=auto_delete,
        )

        return ThingData(
            name=name,
            policy_name=policy_name,
            private_key=Path(cert_key_path).read_text(encoding="utf-8"),
            public_key=public_key,
            url=self.get_iot_url(),
        )
