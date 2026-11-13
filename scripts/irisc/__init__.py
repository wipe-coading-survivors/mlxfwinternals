from .irisc_dis import dis as disasm

__all__ = ["assemble", "encode_form", "disasm", "AsmError",
           "clcrc_unwrap", "clcrc_wrap"]


def __getattr__(name):
    if name in ("assemble", "encode_form", "AsmError"):
        from . import irisc_asm
        return getattr(irisc_asm, name)
    if name in ("clcrc_unwrap", "clcrc_wrap"):
        import mlxfwutil
        return getattr(mlxfwutil, name)
    raise AttributeError(name)
