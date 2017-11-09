#!/bin/bash
TOTP=430694
docker run --rm isam_freeradius radtest sweeden@au1.ibm.com "$TOTP" 169.44.117.85:22 0 SECRET
