from setuptools import setup, Extension

truenas_pyscram_ext = Extension(
    'truenas_pyscram',
    sources=[
        'src/pyscram/truenas_pyscram.c',
        'src/pyscram/error.c',
        'src/pyscram/crypto_datum.c',
        'src/pyscram/scram_auth_data.c',
        'src/pyscram/py_client_first.c',
        'src/pyscram/py_server_first.c',
        'src/pyscram/py_client_final.c',
        'src/pyscram/py_server_final.c',
        'src/pyscram/py_scram_verify.c',
        'src/scram/scram_client_first.c',
        'src/scram/scram_utils.c',
        'src/scram/scram_server_final.c',
        'src/scram/scram_server_first.c',
        'src/scram/scram_client_final.c'
    ],
    include_dirs=['src/scram', 'src/pyscram'],
    libraries=['ssl', 'crypto', 'bsd']
)

setup(
    ext_modules=[truenas_pyscram_ext]
)

