#!/bin/bash
# This runs during Vercel's build step.
# We install the playwright Python library but deliberately skip downloading
# the heavy Chromium binary (~300MB) since we connect remotely via Browserless.io CDP.
pip install playwright
