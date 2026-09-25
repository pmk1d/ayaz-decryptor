"""Необязательное ускорение; без компилятора остаётся Python-реализация."""

import os
from setuptools import Extension, setup


extensions = []
if os.environ.get("AYAZ_NO_NATIVE") != "1":
    extensions.append(Extension(
        "ayaz_decryptor._native",
        ["ayaz_decryptor/_native.c"],
        extra_compile_args=["/O2"] if os.name == "nt" else ["-O3"],
        optional=True,
    ))

setup(ext_modules=extensions)
