from distutils.core import setup, Extension

# ltc_scrypt_module
# ltc_scrypt
medcoin_hybrid_module = Extension('medcoin_hybrid',
                               sources = ['hybridmodule.c',
                                          'hybrid.cpp'],
                               include_dirs=['.'])

setup (name = 'medcoin_hybrid',
       version = '1.0',
       description = 'Bindings for HybridScryptHash256 proof of work used by MediterraneanCoin',
       ext_modules = [medcoin_hybrid_module])
