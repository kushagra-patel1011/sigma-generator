"""Draft Sigma rule + STIX 2.1 bundle generator driven by MITRE ATT&CK.

The package is deliberately import-light: :mod:`src.attack_fetcher` owns the
ATT&CK data, :mod:`src.mappings` owns the ATT&CK -> Sigma translation table,
:mod:`src.sigma_generator` turns the two into a rule and :mod:`src.stix_builder`
wraps the result in a STIX 2.1 bundle.
"""

__version__ = "1.2.0"
__all__ = ["__version__"]
