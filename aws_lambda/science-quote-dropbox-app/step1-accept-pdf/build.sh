#!/bin/bash

# Generic script to create a Lambda layer with dependencies for any step
# Reads dependencies from requirements.layer.txt in the current directory

set -e

unset CONDA_SHLVL

export CONDA_ENV_PATH="../../../conda_env_osx-64"

LAYER_DIR="lambda-layer"
rm -rf $LAYER_DIR
mkdir -p $LAYER_DIR/python

if [ ! -f requirements.layer.txt ]; then
  echo "❌ requirements.layer.txt not found in $(pwd)"
  exit 1
fi

echo "📦 Installing dependencies for Lambda Linux environment from requirements.layer.txt..."

conda run -p $CONDA_ENV_PATH pip install \
    --platform manylinux2014_x86_64 \
    --target=$LAYER_DIR/python \
    --implementation cp \
    --python-version 3.13 \
    --only-binary=:all: \
    --upgrade \
    -r requirements.layer.txt

echo "📦 Dependencies installed in $LAYER_DIR/python"

echo "📝  Creating layer zip file..."
cd $LAYER_DIR
zip -r ../lambda-layer.zip .
cd ..

echo "✅ Lambda layer created: lambda-layer.zip" 
