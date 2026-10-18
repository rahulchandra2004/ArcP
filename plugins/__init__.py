"""ArcP Polymorphic Plugins Registry."""
from .base_plugin import PipeResult, RadialAction, SliceConfig, SubSliceConfig
from .image_ops import ImageOpsPlugin
from .data_ops import DataOpsPlugin
from .code_log_ops import CodeLogOpsPlugin
from .ml_ops import MlOpsPlugin
from .infra_ops import InfraOpsPlugin
from .binary_ops import BinaryOpsPlugin
from .git_ops import GitOpsPlugin

__all__ = [
    "PipeResult",
    "RadialAction",
    "SliceConfig",
    "SubSliceConfig",
    "ImageOpsPlugin",
    "DataOpsPlugin",
    "CodeLogOpsPlugin",
    "MlOpsPlugin",
    "InfraOpsPlugin",
    "BinaryOpsPlugin",
    "GitOpsPlugin",
]
