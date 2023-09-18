"""
blocklist.py

This file just contains the blocklist of JWT tokens. It will be imported by 
app and the logout resorce so that tokens can be added to the blocklist when the 
use logs out.
"""

BLOCKLIST = set()