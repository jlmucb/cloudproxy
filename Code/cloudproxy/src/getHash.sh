#!/bin/bash
sha256sum | cut -d' ' -f1 | xxd -r -ps | base64
