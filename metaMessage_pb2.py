"""
MetaMessage protocol buffer placeholder.
This would typically be generated from .proto files using protoc.
"""

from .c2c_pb2 import NFCData


class Anticol:
    """Placeholder for Anticol message."""
    
    def __init__(self):
        self.uid = b''


class Status:
    """Placeholder for Status message."""
    
    def __init__(self):
        self.code = 0
        self.message = ''


class Data:
    """Placeholder for Data message."""
    
    def __init__(self):
        self.payload = b''


class Session:
    """Placeholder for Session message."""
    
    def __init__(self):
        self.session_id = ''
        self.status = ''


class Wrapper:
    """Placeholder for Wrapper protobuf message."""
    
    def __init__(self):
        self.NFCData = NFCData()
        self.Anticol = Anticol()
        self.Status = Status()
        self.Data = Data()
        self.Session = Session()
        self._which_field = None
    
    def ParseFromString(self, data: bytes) -> None:
        """Parse Wrapper from bytes."""
        if len(data) > 0:
            self.NFCData.ParseFromString(data)
            self._which_field = 'NFCData'
    
    def SerializeToString(self) -> bytes:
        """Serialize Wrapper to bytes."""
        if self._which_field == 'NFCData':
            return self.NFCData.SerializeToString()
        return b''
    
    def HasField(self, field_name: str) -> bool:
        """Check if field is set."""
        return self._which_field == field_name
    
    def WhichOneof(self, oneof_name: str) -> str:
        """Get which field in oneof is set."""
        return self._which_field or ''
    
    def CopyFrom(self, other: 'Wrapper') -> None:
        """Copy data from another Wrapper instance."""
        self._which_field = other._which_field
        if self._which_field == 'NFCData':
            self.NFCData.CopyFrom(other.NFCData)