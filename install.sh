#!/bin/bash

# script para instalar as dependencias necessarias
echo "instalando dependencias..."
pip install cryptography pyotp qrcode[pil]
echo "instalacao concluida."