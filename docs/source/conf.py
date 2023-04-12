# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'pylurk'
copyright = '2023, Daniel Migault'
author = 'Daniel Migault'
release = '0.0.3'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration
import os
import sys
## Read The Doc and running SPhinx locally does not use the same path.
#sys.path.insert( 0, os.path.abspath( '/home/mglt/gitlab/pylurk.git/src' ))

## for local construction
## 1. expressed as full path
# sys.path.insert( 0, os.path.abspath( '/home/mglt/gitlab/pylurk.git/src' ))
# sys.path.insert( 0, os.path.abspath( '/home/mglt/gitlab/pytls13/src' ))
## 2. expressed with relative path (relative from one leve below source)
#sys.path.insert( 0, os.path.abspath( '../../../src' ))
#sys.path.insert( 0, os.path.abspath( './' ))

## for RTD
#sys.path.insert( 0, os.path.abspath( '../../src' ))
#sys.path.insert( 0, os.path.abspath( '../../../src/pylurk' ))
#sys.path.insert( 0, os.path.abspath( '../../../src/pylurk/tls13' ))
#sys.path.insert( 0, os.path.abspath( 'source' ))
#sys.path.insert( 0, os.path.abspath( 'source/pytls13' ))


extensions = [ 'sphinx.ext.autodoc', 'sphinx.ext.napoleon' ]

## we includ ethe Napoleon settings. Current values 
## are the default except for including the __init__ as we 
## used toi describe th efunction in the init as opposed to
## the class or function itslef.
# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'alabaster'
html_static_path = ['_static']
